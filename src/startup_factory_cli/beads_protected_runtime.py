"""Protected broker-side authority for the optional Beads backend.

This module deliberately does not implement the Beads adapter.  It is the
protected, standard-library-only side of the task-#2/task-#3 protocol: signed
leases, one-use capabilities, append-only evidence, generation-CAS current
records, exact preparation argv admission and deterministic recovery.

All public request/result objects are immutable JSON wire records.  Callers
provide the protected root and HMAC key *locations*, never key bytes.  The
broker is expected to invoke these functions outside the agent environment.
"""

from __future__ import annotations

import ctypes
import dataclasses
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import time
from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final


SCHEMA_VERSION: Final = 1
BEADS_BASELINE_COMMIT: Final = "20e493e569c922d1253bdeff068c5e56c94957fb"
MAX_GENERATION: Final = 99_999_999_999_999_999_999
MAX_CANONICAL_BYTES: Final = 1_048_576
MAX_EXECUTABLE_BYTES: Final = 67_108_864
REPOSITORY_NAMESPACE: Final = "beads-authority-v1"
RE_ATTEST_COMMAND: Final = ("--db", "{selector}", "--json", "--sandbox", "config", "list")
_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_HEX_DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_BROKER_CONTEXT: ContextVar[tuple[str, str] | None] = ContextVar("beads-protected-runtime", default=None)
_FAULT_PHASE: ContextVar[str | None] = ContextVar("beads-protected-runtime-fault", default=None)


class BeadsProtectedRuntimeError(RuntimeError):
    """Fail-closed protected-runtime protocol error."""


class BeadsStaleAuthorityError(BeadsProtectedRuntimeError):
    """A compare-and-swap predecessor or lease is no longer current."""


class BeadsCapabilityConsumedError(BeadsProtectedRuntimeError):
    """A one-use protected capability was already consumed."""


@contextmanager
def use_beads_protected_runtime_v1(protected_root: str, hmac_key_path: str):
    """Bind an explicit broker-only locator context for repository-only verifiers.

    This is intentionally lexical and does not read ambient environment
    variables.  Broker request handlers establish it around an operation.
    """

    token = _BROKER_CONTEXT.set((protected_root, hmac_key_path))
    try:
        yield
    finally:
        _BROKER_CONTEXT.reset(token)


def _store_for_repository(repository_locator_sha256: str) -> "_Store":
    context = _BROKER_CONTEXT.get()
    if context is None:
        raise BeadsProtectedRuntimeError("repository-only verifier requires explicit broker locator context")
    return _Store(
        {
            "protectedRoot": context[0],
            "hmacKeyPath": context[1],
            "repositoryLocatorSha256": repository_locator_sha256,
        }
    )


@contextmanager
def _inject_fault(phase: str):
    """Test-only deterministic process-boundary fault hook."""

    token = _FAULT_PHASE.set(phase)
    try:
        yield
    finally:
        _FAULT_PHASE.reset(token)


def _fault(phase: str) -> None:
    if _FAULT_PHASE.get() == phase:
        raise SystemExit(f"intentional protected-runtime fault after {phase}")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if dataclasses.is_dataclass(value):
        return _plain(dataclasses.asdict(value))
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _validate_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 32:
        raise BeadsProtectedRuntimeError("protected record nesting exceeds 32")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_GENERATION:
            raise BeadsProtectedRuntimeError("protected record integer is out of bounds")
        return value
    if isinstance(value, float):
        raise BeadsProtectedRuntimeError("floating-point protected fields are forbidden")
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 256:
                raise BeadsProtectedRuntimeError("protected record keys must be bounded non-empty strings")
            if key in result:
                raise BeadsProtectedRuntimeError("duplicate protected record key")
            result[key] = _validate_json(item, depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > 4096:
            raise BeadsProtectedRuntimeError("protected record sequence is too large")
        return [_validate_json(item, depth=depth + 1) for item in value]
    raise BeadsProtectedRuntimeError(f"unsupported protected record value: {type(value).__name__}")


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def canonical_bytes(value: Any) -> bytes:
    validated = _validate_json(_plain(value))
    encoded = json.dumps(validated, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise BeadsProtectedRuntimeError("protected canonical record exceeds 1048576 bytes")
    return encoded


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclasses.dataclass(frozen=True, slots=True)
class _WireRecord:
    payload: Mapping[str, Any]
    auth: str | None = None
    record_sha256: str | None = None
    full_bytes_sha256: str | None = None

    def __post_init__(self) -> None:
        validated = _validate_json(_plain(self.payload))
        schema = globals().get("_TYPE_SCHEMAS", {}).get(type(self).__name__)
        if schema is not None:
            unknown = sorted(set(validated) - schema["fields"])
            if unknown:
                raise BeadsProtectedRuntimeError(
                    f"{type(self).__name__} has unknown protected field(s): " + ", ".join(unknown)
                )
            forbidden_null = sorted(
                field for field, value in validated.items()
                if value is None and field not in schema["nullable"]
            )
            if forbidden_null:
                raise BeadsProtectedRuntimeError(
                    f"{type(self).__name__} has non-nullable protected field(s): "
                    + ", ".join(forbidden_null)
                )
        object.__setattr__(self, "payload", _freeze(validated))
        for label, digest in (("record", self.record_sha256), ("full-bytes", self.full_bytes_sha256)):
            if digest is not None and not _DIGEST.fullmatch(digest):
                raise BeadsProtectedRuntimeError(f"invalid {label} digest")
        if self.auth is not None and not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", self.auth):
            raise BeadsProtectedRuntimeError("invalid protected record authentication")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"payload": _plain(self.payload)}
        if self.auth is not None:
            result["auth"] = self.auth
        if self.record_sha256 is not None:
            result["recordSha256"] = self.record_sha256
        if self.full_bytes_sha256 is not None:
            result["fullBytesSha256"] = self.full_bytes_sha256
        return result


def _wire_type(name: str) -> type[_WireRecord]:
    return dataclasses.dataclass(frozen=True, slots=True)(type(name, (_WireRecord,), {"__module__": __name__}))


_TYPE_NAMES = (
    # Claim and mutation.
    "PrepareAtomicClaimRequestV1", "AdvanceAtomicClaimRequestV1",
    "RecordAtomicClaimReceiptRequestV1", "AuthorizeClaimLaunchRequestV1",
    "AtomicClaimLeaseV1", "AtomicClaimReceiptV1", "LaunchAuthorizationV1",
    "BeginBeadsMutationRequestV1", "FinishBeadsMutationRequestV1",
    "BeadsMutationIntentV1", "BeadsMutationResultV1",
    # Installed selector and preparation sequence.
    "BeadsInstalledDatabaseSelectorBindingV1", "BeadsInstalledSelectorObservationV1",
    "BeadsSelectedStoreObservationV1", "VerifiedBeadsInstalledDatabaseSelectorV1",
    "BeadsPreparationRemediationEvidenceV1", "BeadsPreparationSequenceV1",
    # Preparation.
    "AuthorizeBeadsPreparationRequestV1", "BeadsPreparationAuthorizationV1",
    "BeginBeadsPreparationRequestV1", "BeadsPreparationLeaseV1",
    "BeadsPreparationCommandIntentV1", "ObserveBeadsStoreRequestV1",
    "BeadsStoreStateProjectionV1", "BeadsStoreObservationV1",
    "AdvanceBeadsPreparationRequestV1", "BeadsPreparationStepV1",
    "BeadsStatusProfileDynamicBindingsV1", "VerifiedBeadsStatusProfileDynamicBindingsV1",
    "FinishBeadsPreparationRequestV1", "FinishBeadsPreparationResultV1",
    "BeadsStatusProfileV1", "BeadsPreparationCurrentV1",
    "BeadsPreparationActivationReceiptV1", "VerifiedCurrentBeadsPreparationV1",
    "VerifiedHistoricalBeadsPreparationV1",
    # Immutable change-plan cores.
    "BeadsBootstrapRuntimeCoreInputsV1", "BeadsBootstrapRuntimeCoreV1",
    "BeadsAdapterReleaseCoreInputsV1", "BeadsAdapterReleaseCoreV1",
    "BeadsChangePlanCoreReferenceV1", "RecordBeadsChangePlanCoreRequestV1",
    "BeadsChangePlanCoreRecordV1", "BeadsChangePlanCoreTransactionIntentV1",
    "BeadsChangePlanCoreTransactionReceiptV1", "VerifiedBeadsChangePlanCoreRecordV1",
    # Authority state and transitions.
    "BeadsRepositoryAuthorityLockV1", "BeadsAuthorityPredecessorV1",
    "BeadsAuthorityLocatorV1", "ActiveBeadsAuthorityTupleV1", "BeadsAuthorityCandidateV1",
    "RevokeBeadsAuthorityCommandV1", "StageBeadsAuthorityCommandV1",
    "ActivateBeadsAuthorityCommandV1", "AuthorizeBeadsAuthorityTransitionRequestV1",
    "BeadsAuthorityTransitionAuthorizationV1", "RevokeBeadsAuthorityEpochRequestV1",
    "StageBeadsAuthorityEpochRequestV1", "ActivateBeadsAuthorityEpochRequestV1",
    "BeadsAuthorityEpochStateV1", "BeadsAuthorityTransitionIntentV1",
    "BeadsAuthorityTransitionAuthorizationConsumedV1", "BeadsAuthorityTransitionStepV1",
    "BeadsAuthorityTransitionReceiptV1", "VerifyBeadsAuthorityTransitionReceiptRequestV1",
    "VerifiedBeadsAuthorityTransitionReceiptV1", "VerifiedRevokedBeadsAuthorityV1",
    "VerifiedPendingBeadsAuthorityV1", "VerifiedActiveBeadsAuthorityV1",
    # Runtime API manifest.
    "AuthorizeBeadsRuntimeApiManifestRecordRequestV1",
    "BeadsRuntimeApiManifestRecordCapabilityV1",
    "RecordBeadsProtectedRuntimeApiManifestRequestV1", "BeadsProtectedRuntimeApiManifestV1",
    "VerifyBeadsProtectedRuntimeApiManifestRequestV1",
    "VerifiedBeadsProtectedRuntimeApiManifestV1",
    "VerifiedHistoricalBeadsProtectedRuntimeApiManifestV1",
    "BeadsRuntimeTransactionAuthorityBindingV1", "BeadsRuntimeApiManifestIntentV1",
    "BeadsRuntimeApiManifestCapabilityConsumedV1",
    "BeadsRuntimeApiManifestTransactionStepV1", "BeadsRuntimeApiManifestReceiptV1",
    # Adapter release manifest.
    "AuthorizeBeadsAdapterReleaseManifestRecordRequestV1",
    "BeadsAdapterReleaseManifestRecordCapabilityV1",
    "RecordBeadsAdapterReleaseManifestRequestV1", "BeadsAdapterReleaseManifestV1",
    "VerifyBeadsAdapterReleaseManifestRequestV1", "VerifiedBeadsAdapterReleaseManifestV1",
    "BeadsAdapterReleaseManifestIntentV1", "BeadsAdapterReleaseManifestCapabilityConsumedV1",
    "BeadsAdapterReleaseManifestTransactionStepV1", "BeadsAdapterReleaseManifestReceiptV1",
    "BeadsRuntimeManifestObservationV1",
)

globals().update({name: _wire_type(name) for name in _TYPE_NAMES})


_STORE_FIELDS = {"protectedRoot", "hmacKeyPath", "repositoryLocatorSha256"}
_SEQUENCE_FIELDS = {
    "bootstrapChangeKind", "preparationMode", "preparationSequenceKind",
    "preparationSequenceSha256", "remediationEvidenceSha256", "databasePathKind",
    "createStageDatabasePathLocatorSha256", "installedDatabaseSelectorBindingSha256",
    "selectorObservationASha256", "selectedStoreObservationASha256",
}
_REQUEST_FIELDS: dict[str, set[str]] = {
    "BeadsBootstrapRuntimeCoreInputsV1": {
        "bootstrapChangeKind", "adapterChangeKind", "remediationEvidenceSha256", "baselineCommit",
    },
    "BeadsAdapterReleaseCoreInputsV1": {
        "bootstrapChangeKind", "adapterChangeKind", "remediationEvidenceSha256", "baselineCommit",
    },
    "PrepareAtomicClaimRequestV1": _STORE_FIELDS | {"taskId", "expectedRevision", "claimNonce", "expiresAtUnix"},
    "AdvanceAtomicClaimRequestV1": _STORE_FIELDS | {"leaseRecordSha256", "observedRevision", "observedStatus", "claimSucceeded"},
    "RecordAtomicClaimReceiptRequestV1": _STORE_FIELDS | {"leaseRecordSha256", "readBackRevision", "readBackStatus", "claimIdentitySha256"},
    "AuthorizeClaimLaunchRequestV1": _STORE_FIELDS | {"claimReceiptRecordSha256", "launchNonce", "expiresAtUnix"},
    "BeginBeadsMutationRequestV1": _STORE_FIELDS | {
        "mutationClass", "mutationNonce", "commandArgv", "expiresAtUnix",
        "launchAuthorizationRecordSha256", "preparationLeaseRecordSha256",
        "preparationCommandIntentRecordSha256",
    },
    "FinishBeadsMutationRequestV1": _STORE_FIELDS | {
        "mutationClass", "mutationIntentRecordSha256", "exitCode", "stdoutSha256",
        "stderrSha256", "readBackSha256",
    },
    "AuthorizeBeadsPreparationRequestV1": _STORE_FIELDS | _SEQUENCE_FIELDS | {
        "planSha256", "executableSha256", "operatorIdentitySha256", "authorizationNonce",
        "expiresAtUnix", "runtimeApiManifestRecordSha256", "adapterReleaseManifestRecordSha256",
        "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "createStageDatabasePath",
        "installedSelectorPath", "selectedStorePath", "doltRootPath", "executablePath",
        "repositoryPath", "databaseName", "installPath", "cleanupPath", "statusConfigValue",
        "sourceAuthorityTransitionReceiptRecordSha256", "sourcePreparationPointerRecordSha256",
    },
    "BeginBeadsPreparationRequestV1": _STORE_FIELDS | {"authorizationRecordSha256", "leaseNonce", "expiresAtUnix"},
    "AdvanceBeadsPreparationRequestV1": _STORE_FIELDS | {
        "leaseRecordSha256", "commandOrdinal", "commandKind", "argv",
    },
    "ObserveBeadsStoreRequestV1": _STORE_FIELDS | {
        "leaseRecordSha256", "observationPhase", "acceptedConfigEnvelopeSha256",
        "predecessorObservationRecordSha256", "configReadbackStepRecordSha256",
    },
    "FinishBeadsPreparationRequestV1": _STORE_FIELDS | {
        "leaseRecordSha256", "preObservationRecordSha256", "postObservationRecordSha256",
        "dynamicBindingsCanonicalJson", "statusProfilePayloadCanonicalJson",
        "preparedStorePayloadCanonicalJson", "expectedCurrentPointerFullBytesSha256",
    },
    "RecordBeadsChangePlanCoreRequestV1": _STORE_FIELDS | {
        "bootstrapRuntimeCoreCanonicalJson", "adapterReleaseCoreCanonicalJson",
    },
    "AuthorizeBeadsAuthorityTransitionRequestV1": _STORE_FIELDS | _SEQUENCE_FIELDS | {
        "command", "authorizationNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256", "candidate",
    },
    "RevokeBeadsAuthorityEpochRequestV1": _STORE_FIELDS | {"authorizationRecordSha256"},
    "StageBeadsAuthorityEpochRequestV1": _STORE_FIELDS | {"authorizationRecordSha256"},
    "ActivateBeadsAuthorityEpochRequestV1": _STORE_FIELDS | {"authorizationRecordSha256"},
    "VerifyBeadsAuthorityTransitionReceiptRequestV1": _STORE_FIELDS | {"receiptRecordSha256"},
    "AuthorizeBeadsRuntimeApiManifestRecordRequestV1": _STORE_FIELDS | {
        "mode", "capabilityNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256",
        "bootstrapRuntimeCoreSha256", "runtimeTransactionAuthorityBinding",
    },
    "RecordBeadsProtectedRuntimeApiManifestRequestV1": _STORE_FIELDS | {
        "moduleSha256", "schemaFixtureSha256", "exports", "bootstrapRuntimeCoreSha256",
    },
    "VerifyBeadsProtectedRuntimeApiManifestRequestV1": _STORE_FIELDS | {
        "expectedManifestRecordSha256", "expectedModuleSha256", "expectedSchemaFixtureSha256",
    },
    "AuthorizeBeadsAdapterReleaseManifestRecordRequestV1": _STORE_FIELDS | {
        "capabilityNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256",
        "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256",
    },
    "RecordBeadsAdapterReleaseManifestRequestV1": _STORE_FIELDS | {
        "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256",
        "runtimeManifestObservations", "adapterPayloadSha256", "releaseIdentitySha256",
        "remediationEvidenceSha256",
    },
    "VerifyBeadsAdapterReleaseManifestRequestV1": _STORE_FIELDS | {
        "expectedManifestRecordSha256", "expectedRuntimeApiManifestRecordSha256",
        "expectedReleaseIdentitySha256",
    },
}


_NULLABLE_FIELDS = {
    "acceptedConfigEnvelopeSha256", "adapterReleaseManifestRecordSha256", "candidate", "cleanupIntentRecordSha256",
    "cleanupObservedRecordSha256", "configReadbackStepRecordSha256",
    "createStageDatabasePath", "createStageDatabasePathLocatorSha256",
    "currentPointerFullBytesSha256", "doltRootPath", "exitCode",
    "expectedCurrentFullBytesSha256", "expectedCurrentPointerFullBytesSha256",
    "installIntentRecordSha256",
    "installedDatabaseSelectorBindingSha256", "installedSelectorPath",
    "installObservedRecordSha256", "launchAuthorizationRecordSha256",
    "predecessorCurrentFullBytesSha256", "predecessorJournalEntryFullBytesSha256",
    "predecessorJournalEntryRecordSha256", "predecessorLeaseRecordSha256",
    "predecessorObservationRecordSha256", "predecessorTransactionIntentSha256",
    "preparationCommandIntentRecordSha256", "preparationLeaseRecordSha256",
    "preparationPointerRecordSha256", "readBackSha256", "remediationEvidenceSha256",
    "runtimeApiManifestRecordSha256",
    "selectedStoreObservationASha256", "selectedStorePath",
    "selectorObservationASha256", "sourceAuthorityTransitionReceiptRecordSha256",
    "sourcePreparationPointerRecordSha256", "stderrSha256", "stdoutSha256",
    "successorLeaseRecordSha256",
}

_SIGNED = {"kind", "schemaVersion"}
_SEQUENCED = _SIGNED | _SEQUENCE_FIELDS
_CLAIM_LEASE = _SIGNED | {
    "repositoryLocatorSha256", "taskId", "expectedRevision", "claimNonce", "expiresAtUnix",
    "claimState", "activeAuthorityRecordSha256", "transactionIntentSha256",
    "predecessorLeaseRecordSha256", "observedRevision", "observedStatus",
}
_PREPARATION_AUTHORIZATION = _SEQUENCED | {
    "repositoryLocatorSha256", "planSha256", "executableSha256", "operatorIdentitySha256", "authorizationNonce",
    "expiresAtUnix", "runtimeApiManifestRecordSha256", "adapterReleaseManifestRecordSha256",
    "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "createStageDatabasePath",
    "repositoryPath", "databaseName", "installPath", "cleanupPath", "statusConfigValue",
    "installedSelectorPath", "selectedStorePath", "doltRootPath",
    "executablePath", "executableObservation", "pinnedExecutablePath",
    "pinnedExecutableObservation", "createStageObservationA", "installObservationA",
    "cleanupObservationA", "cleanupTreeObservationA", "revokedAuthorityRecordSha256",
}
_PREPARATION_LEASE = _PREPARATION_AUTHORIZATION | {
    "authorizationRecordSha256", "leaseNonce", "transactionIntentSha256", "nextCommandOrdinal",
    "preparationState", "lastCommandIntentRecordSha256", "predecessorLeaseRecordSha256",
    "createStageObservationCurrent",
}
_PREPARATION_STEP = _SEQUENCED | {
    "repositoryLocatorSha256", "leaseRecordSha256", "commandIntentRecordSha256", "commandKind",
    "commandOrdinal", "argv", "argvSha256", "outcome", "exitCode", "stdoutSha256",
    "stderrSha256", "mutationIntentRecordSha256", "mutationResultRecordSha256",
    "successorLeaseRecordSha256", "transactionIntentSha256", "postObservationRecordSha256",
    "stagePathSha256", "installPathSha256", "cleanupPathSha256", "expectedStageTreeSha256",
    "installIntentRecordSha256", "installedTree", "installedTreeSha256",
    "installObservedRecordSha256", "cleanupTreeObservationA", "cleanupIntentRecordSha256",
    "cleanupAbsentObservation",
}
_PREPARATION_TERMINAL = _SEQUENCED | {
    "repositoryLocatorSha256", "leaseRecordSha256", "preObservationRecordSha256",
    "postObservationRecordSha256", "statusProfileRecordSha256", "preparedPayloadCanonicalSha256",
    "preparedPayloadCanonicalJson", "transactionIntentSha256", "installIntentRecordSha256",
    "installObservedRecordSha256", "cleanupIntentRecordSha256", "cleanupObservedRecordSha256",
}
_AUTHORITY_STATE = _SEQUENCED | {
    "repositoryLocatorSha256", "generation", "authorityState", "candidate",
    "predecessorCurrentFullBytesSha256", "transitionAuthorizationRecordSha256",
    "transitionIntentSha256", "preparationPointerRecordSha256",
    "adapterReleaseManifestRecordSha256", "runtimeApiManifestRecordSha256",
}
_AUTHORITY_TRANSITION = _SEQUENCED | {
    "repositoryLocatorSha256", "command", "transactionIntentSha256", "authorizationRecordSha256",
    "authorityStateRecordSha256", "authorityStateFullBytesSha256",
    "predecessorCurrentFullBytesSha256", "candidate", "transitionStepRecordSha256",
}
_RUNTIME_MANIFEST = _SIGNED | {
    "repositoryLocatorSha256", "generation", "predecessorCurrentFullBytesSha256",
    "capabilityRecordSha256", "mode", "moduleSha256", "schemaFixtureSha256", "exports",
    "bootstrapRuntimeCoreSha256", "runtimeTransactionAuthorityBinding",
    "runtimeTransactionAuthorityBindingSha256", "changePlanCoreRecordSha256",
    "transactionIntentSha256", "historicalOnly",
}
_ADAPTER_MANIFEST = _SIGNED | {
    "repositoryLocatorSha256", "generation", "predecessorCurrentFullBytesSha256",
    "capabilityRecordSha256", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256",
    "runtimeApiManifestRecordSha256", "changePlanCoreRecordSha256", "runtimeManifestObservations",
    "adapterPayloadSha256", "releaseIdentitySha256", "remediationEvidenceSha256",
    "transactionIntentSha256",
}

# Exact top-level shapes for every registered non-request wire type.  Variants
# of a state machine share only the explicit union of fields that their own
# type can carry; fields from another protocol type are never accepted.
_RESULT_FIELDS: dict[str, set[str]] = {
    "AtomicClaimLeaseV1": _CLAIM_LEASE,
    "AtomicClaimReceiptV1": _SIGNED | {"repositoryLocatorSha256", "leaseRecordSha256", "taskId", "revision", "status", "claimIdentitySha256", "activeAuthorityRecordSha256"},
    "LaunchAuthorizationV1": _SIGNED | {"repositoryLocatorSha256", "claimReceiptRecordSha256", "activeAuthorityRecordSha256", "launchNonce", "expiresAtUnix", "transactionIntentSha256"},
    "BeadsMutationIntentV1": _SEQUENCED | {"repositoryLocatorSha256", "mutationClass", "mutationNonce", "argv", "argvSha256", "expiresAtUnix", "transactionIntentSha256", "activeAuthorityRecordSha256", "launchAuthorizationRecordSha256", "preparationLeaseRecordSha256", "preparationCommandIntentRecordSha256", "revokedAuthorityRecordSha256"},
    "BeadsMutationResultV1": _SEQUENCED | {"repositoryLocatorSha256", "mutationClass", "mutationNonce", "argv", "argvSha256", "expiresAtUnix", "transactionIntentSha256", "activeAuthorityRecordSha256", "launchAuthorizationRecordSha256", "preparationLeaseRecordSha256", "preparationCommandIntentRecordSha256", "revokedAuthorityRecordSha256", "mutationIntentRecordSha256", "exitCode", "stdoutSha256", "stderrSha256", "readBackSha256", "observedByBroker"},
    "BeadsInstalledDatabaseSelectorBindingV1": {"repositoryLocatorSha256", "sourcePreparationPointerRecordSha256", "selectorPath", "selectedStorePath", "doltRootPath", "databaseName", "selectorObservation", "selectedStoreObservation", "doltRootObservation"},
    "BeadsInstalledSelectorObservationV1": {"pathSha256", "device", "inode", "owner", "linkCount", "fileType", "ancestrySha256"},
    "BeadsSelectedStoreObservationV1": {"pathSha256", "device", "inode", "owner", "linkCount", "fileType", "ancestrySha256"},
    "VerifiedBeadsInstalledDatabaseSelectorV1": {"repositoryLocatorSha256", "sourcePreparationPointerRecordSha256", "selectorPath", "selectedStorePath", "doltRootPath", "databaseName", "selectorObservation", "selectedStoreObservation", "doltRootObservation"},
    "BeadsPreparationRemediationEvidenceV1": {"remediationEvidenceSha256"},
    "BeadsPreparationSequenceV1": set(_SEQUENCE_FIELDS),
    "BeadsPreparationAuthorizationV1": _PREPARATION_AUTHORIZATION,
    "BeadsPreparationLeaseV1": _PREPARATION_LEASE,
    "BeadsPreparationCommandIntentV1": _SEQUENCED | {"repositoryLocatorSha256", "leaseRecordSha256", "commandOrdinal", "commandKind", "argv", "argvSha256", "transactionIntentSha256"},
    "BeadsStoreStateProjectionV1": {"primaryStore", "executableObservation", "installObservation", "cleanupObservation", "selectedStoreObservation", "doltRootObservation"},
    "BeadsStoreObservationV1": _SEQUENCED | {"repositoryLocatorSha256", "leaseRecordSha256", "observationPhase", "stateProjection", "storeStateSha256", "acceptedConfigEnvelopeSha256", "predecessorObservationRecordSha256", "configReadbackStepRecordSha256", "transactionIntentSha256"},
    "BeadsPreparationStepV1": _PREPARATION_STEP,
    "BeadsStatusProfileDynamicBindingsV1": {"schemaVersion", "repositoryLocatorSha256", "preparationLeaseRecordSha256", "preObservationRecordSha256", "postObservationRecordSha256", "storeStateSha256", "acceptedConfigEnvelopeCanonicalSha256"} | _SEQUENCE_FIELDS,
    "VerifiedBeadsStatusProfileDynamicBindingsV1": {"schemaVersion", "repositoryLocatorSha256", "preparationLeaseRecordSha256", "preObservationRecordSha256", "postObservationRecordSha256", "storeStateSha256", "acceptedConfigEnvelopeCanonicalSha256"} | _SEQUENCE_FIELDS,
    "FinishBeadsPreparationResultV1": _PREPARATION_TERMINAL | {"resultStoredJournalHeadSha256", "pointerRecordSha256", "currentPointerFullBytesSha256", "activationReceiptRecordSha256"},
    "BeadsStatusProfileV1": _SEQUENCED | {"repositoryLocatorSha256", "leaseRecordSha256", "payloadCanonicalSha256", "payloadCanonicalJson", "dynamicBindingsCanonicalSha256", "transactionIntentSha256"},
    "BeadsPreparationCurrentV1": _SEQUENCED | {"repositoryLocatorSha256", "generation", "predecessorCurrentFullBytesSha256", "leaseRecordSha256", "resultRecordSha256", "resultStoredJournalHeadSha256", "statusProfileRecordSha256", "transactionIntentSha256", "installIntentRecordSha256", "installObservedRecordSha256", "cleanupIntentRecordSha256", "cleanupObservedRecordSha256"},
    "BeadsPreparationActivationReceiptV1": _SEQUENCED | {"repositoryLocatorSha256", "pointerRecordSha256", "pointerFullBytesSha256", "resultRecordSha256", "resultStoredJournalHeadSha256", "statusProfileRecordSha256", "installIntentRecordSha256", "installObservedRecordSha256", "cleanupIntentRecordSha256", "cleanupObservedRecordSha256"},
    "VerifiedCurrentBeadsPreparationV1": _SEQUENCED | {"repositoryLocatorSha256", "pointerRecordSha256", "pointerFullBytesSha256", "resultRecordSha256", "activationReceiptRecordSha256", "historicalOnly"},
    "VerifiedHistoricalBeadsPreparationV1": _SEQUENCED | {"repositoryLocatorSha256", "pointerRecordSha256", "pointerFullBytesSha256", "resultRecordSha256", "activationReceiptRecordSha256", "historicalOnly"},
    "BeadsBootstrapRuntimeCoreV1": _SIGNED | {"bootstrapChangeKind", "adapterChangeKind", "remediationEvidenceSha256", "baselineCommit"},
    "BeadsAdapterReleaseCoreV1": _SIGNED | {"bootstrapChangeKind", "adapterChangeKind", "remediationEvidenceSha256", "baselineCommit"},
    "BeadsChangePlanCoreReferenceV1": {"changePlanCoreRecordSha256", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256"},
    "BeadsChangePlanCoreRecordV1": _SIGNED | {"repositoryLocatorSha256", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "bootstrapRuntimeCoreCanonicalJson", "adapterReleaseCoreCanonicalJson", "bootstrapChangeKind", "adapterChangeKind", "remediationEvidenceSha256", "transactionIntentSha256"},
    "BeadsChangePlanCoreTransactionIntentV1": {"repositoryLocatorSha256", "operation", "transactionIntentSha256"},
    "BeadsChangePlanCoreTransactionReceiptV1": {"repositoryLocatorSha256", "operation", "transactionIntentSha256", "resultRecordSha256", "resultFullBytesSha256"},
    "VerifiedBeadsChangePlanCoreRecordV1": _SIGNED | {"repositoryLocatorSha256", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "bootstrapRuntimeCoreCanonicalJson", "adapterReleaseCoreCanonicalJson", "bootstrapChangeKind", "adapterChangeKind", "remediationEvidenceSha256", "transactionIntentSha256"},
    "BeadsRepositoryAuthorityLockV1": {"repositoryLocatorSha256", "owner"},
    "BeadsAuthorityPredecessorV1": {"authorityStateRecordSha256", "authorityStateFullBytesSha256", "predecessorCurrentFullBytesSha256"},
    "BeadsAuthorityLocatorV1": {"repositoryLocatorSha256", "authorityStateRecordSha256", "authorityStateFullBytesSha256", "predecessorCurrentFullBytesSha256", "verifiedReceiptRecordSha256", "repositoryPath", "databaseName"},
    "ActiveBeadsAuthorityTupleV1": set(_AUTHORITY_CANDIDATE_FIELDS) if "_AUTHORITY_CANDIDATE_FIELDS" in globals() else {"preparationPointerRecordSha256", "preparationActivationReceiptRecordSha256", "adapterReleaseManifestRecordSha256", "runtimeApiManifestRecordSha256", "repositoryPath", "databaseName"},
    "BeadsAuthorityCandidateV1": {"preparationPointerRecordSha256", "preparationActivationReceiptRecordSha256", "adapterReleaseManifestRecordSha256", "runtimeApiManifestRecordSha256", "repositoryPath", "databaseName"},
    "RevokeBeadsAuthorityCommandV1": {"command"}, "StageBeadsAuthorityCommandV1": {"command"}, "ActivateBeadsAuthorityCommandV1": {"command"},
    "BeadsAuthorityTransitionAuthorizationV1": _SEQUENCED | {"repositoryLocatorSha256", "command", "authorizationNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256", "candidate"},
    "BeadsAuthorityEpochStateV1": _AUTHORITY_STATE,
    "BeadsAuthorityTransitionIntentV1": _AUTHORITY_TRANSITION,
    "BeadsAuthorityTransitionAuthorizationConsumedV1": _AUTHORITY_TRANSITION,
    "BeadsAuthorityTransitionStepV1": _AUTHORITY_TRANSITION,
    "BeadsAuthorityTransitionReceiptV1": _AUTHORITY_TRANSITION,
    "VerifiedBeadsAuthorityTransitionReceiptV1": _AUTHORITY_TRANSITION,
    "VerifiedRevokedBeadsAuthorityV1": _AUTHORITY_STATE | {"transitionReceiptRecordSha256"},
    "VerifiedPendingBeadsAuthorityV1": _AUTHORITY_STATE | {"transitionReceiptRecordSha256"},
    "VerifiedActiveBeadsAuthorityV1": _AUTHORITY_STATE | {"transitionReceiptRecordSha256"},
    "BeadsRuntimeApiManifestRecordCapabilityV1": _SIGNED | {"repositoryLocatorSha256", "mode", "capabilityNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256", "bootstrapRuntimeCoreSha256", "runtimeTransactionAuthorityBinding", "runtimeTransactionAuthorityBindingSha256", "changePlanCoreRecordSha256", "revokedAuthorityRecordSha256"},
    "BeadsProtectedRuntimeApiManifestV1": _RUNTIME_MANIFEST,
    "VerifiedBeadsProtectedRuntimeApiManifestV1": _RUNTIME_MANIFEST,
    "VerifiedHistoricalBeadsProtectedRuntimeApiManifestV1": _RUNTIME_MANIFEST,
    "BeadsRuntimeTransactionAuthorityBindingV1": {"kind", "identitySha256"},
    "BeadsRuntimeApiManifestIntentV1": {"repositoryLocatorSha256", "operation", "transactionIntentSha256"},
    "BeadsRuntimeApiManifestCapabilityConsumedV1": {"capabilityRecordSha256", "transactionIntentSha256"},
    "BeadsRuntimeApiManifestTransactionStepV1": _RUNTIME_MANIFEST,
    "BeadsRuntimeApiManifestReceiptV1": {"resultRecordSha256", "resultFullBytesSha256", "transactionIntentSha256"},
    "BeadsAdapterReleaseManifestRecordCapabilityV1": _SIGNED | {"repositoryLocatorSha256", "capabilityNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256", "changePlanCoreRecordSha256", "revokedAuthorityRecordSha256"},
    "BeadsAdapterReleaseManifestV1": _ADAPTER_MANIFEST,
    "VerifiedBeadsAdapterReleaseManifestV1": _ADAPTER_MANIFEST,
    "BeadsAdapterReleaseManifestIntentV1": {"repositoryLocatorSha256", "operation", "transactionIntentSha256"},
    "BeadsAdapterReleaseManifestCapabilityConsumedV1": {"capabilityRecordSha256", "transactionIntentSha256"},
    "BeadsAdapterReleaseManifestTransactionStepV1": _ADAPTER_MANIFEST,
    "BeadsAdapterReleaseManifestReceiptV1": {"resultRecordSha256", "resultFullBytesSha256", "transactionIntentSha256"},
    "BeadsRuntimeManifestObservationV1": {"phase", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256", "adapterPayloadSha256", "remediationEvidenceSha256"},
}
_TYPE_SCHEMAS: dict[str, dict[str, set[str]]] = {}
for _type_name in _TYPE_NAMES:
    fields = set(_REQUEST_FIELDS.get(_type_name, _RESULT_FIELDS.get(_type_name, set())))
    _TYPE_SCHEMAS[_type_name] = {
        "fields": fields,
        "nullable": fields & _NULLABLE_FIELDS,
        "required": set(),
    }
for _core_name in ("BeadsBootstrapRuntimeCoreInputsV1", "BeadsAdapterReleaseCoreInputsV1"):
    _TYPE_SCHEMAS[_core_name]["required"] = set(_REQUEST_FIELDS[_core_name])


def _request(value: _WireRecord, expected_name: str) -> dict[str, Any]:
    if type(value).__name__ != expected_name:
        raise BeadsProtectedRuntimeError(f"expected {expected_name}, received {type(value).__name__}")
    if value.auth is not None or value.record_sha256 is not None or value.full_bytes_sha256 is not None:
        raise BeadsProtectedRuntimeError("request objects cannot carry broker authentication fields")
    payload = _plain(value.payload)
    allowed = _REQUEST_FIELDS.get(expected_name)
    if allowed is not None:
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise BeadsProtectedRuntimeError(
                f"{expected_name} has unknown protected field(s): " + ", ".join(unknown)
            )
    return payload


def _required(payload: Mapping[str, Any], *fields: str) -> None:
    missing = [field for field in fields if field not in payload]
    if missing:
        raise BeadsProtectedRuntimeError("missing required protected field(s): " + ", ".join(missing))


def _digest(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise BeadsProtectedRuntimeError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise BeadsProtectedRuntimeError(f"{label} is not a bounded identifier")
    return value


def _generation(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_GENERATION:
        raise BeadsProtectedRuntimeError("generation must be an integer in 1..99999999999999999999")
    return value


def _private_regular(path: Path, label: str, *, executable: bool = False) -> bytes:
    parent, leaf = _open_absolute_parent(path, label)
    try:
        descriptor = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        try:
            data = _read_regular_descriptor(descriptor, label, executable=executable)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)
    return data


def _directory_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "owner": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "linkCount": metadata.st_nlink,
    }


def _ancestry_identity(metadata: os.stat_result) -> dict[str, int]:
    """Stable path-substitution identity for an opened ancestor.

    Ancestor link counts can legitimately change when unrelated sibling
    directories are created.  Device/inode still pins the opened object;
    owner and mode retain the security-relevant metadata without turning
    concurrent activity elsewhere in a shared temporary parent into a false
    substitution signal.
    """

    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "owner": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def _validate_directory_metadata(metadata: os.stat_result, label: str, *, private: bool) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise BeadsProtectedRuntimeError(f"{label} must be a non-symlink directory")
    if private and (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise BeadsProtectedRuntimeError(f"{label} must be broker-owned and mode 0700 or stricter")


def _open_absolute_directory(path: Path, label: str, *, private: bool = False) -> tuple[int, list[dict[str, int]]]:
    """Open every absolute path component without following links.

    The returned descriptor pins the final directory.  Intermediate identities
    are retained as evidence and every mutation reopens through the same
    descriptor-relative primitive instead of trusting a prior string check.
    """

    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise BeadsProtectedRuntimeError(f"{label} must be a normalized absolute path")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.anchor, flags)
    identities: list[dict[str, int]] = []
    try:
        root_metadata = os.fstat(descriptor)
        _validate_directory_metadata(root_metadata, f"{label} ancestor", private=False)
        identities.append(_ancestry_identity(root_metadata))
        for index, part in enumerate(path.parts[1:]):
            if part in {"", ".", ".."}:
                raise BeadsProtectedRuntimeError(f"{label} contains an unsafe path component")
            child = os.open(part, flags, dir_fd=descriptor)
            metadata = os.fstat(child)
            _validate_directory_metadata(
                metadata,
                label if index == len(path.parts[1:]) - 1 else f"{label} ancestor",
                private=private and index == len(path.parts[1:]) - 1,
            )
            identities.append(_ancestry_identity(metadata))
            os.close(descriptor)
            descriptor = child
        return descriptor, identities
    except (OSError, BeadsProtectedRuntimeError) as exc:
        os.close(descriptor)
        if isinstance(exc, BeadsProtectedRuntimeError):
            raise
        raise BeadsProtectedRuntimeError(f"cannot open {label} without following links: {exc}") from exc


def _open_absolute_parent(path: Path, label: str) -> tuple[int, str]:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise BeadsProtectedRuntimeError(f"{label} must be a normalized absolute leaf path")
    descriptor, _ = _open_absolute_directory(path.parent, f"{label} parent")
    return descriptor, path.name


def _read_regular_descriptor(
    descriptor: int,
    label: str,
    *,
    executable: bool = False,
    max_bytes: int = MAX_CANONICAL_BYTES,
) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise BeadsProtectedRuntimeError(f"{label} must be a non-symlink single-link regular file")
    if before.st_uid not in ({0, os.getuid()} if executable else {os.getuid()}):
        raise BeadsProtectedRuntimeError(f"{label} has an unauthorized owner")
    forbidden = 0o022 if executable else 0o077
    if stat.S_IMODE(before.st_mode) & forbidden:
        raise BeadsProtectedRuntimeError(f"{label} permissions are not protected")
    if executable and stat.S_IMODE(before.st_mode) & 0o111 == 0:
        raise BeadsProtectedRuntimeError(f"{label} is not executable")
    data = bytearray()
    while len(data) <= max_bytes:
        chunk = os.read(descriptor, min(65536, max_bytes + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    after = os.fstat(descriptor)
    if len(data) > max_bytes or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        after.st_uid,
        after.st_nlink,
    ):
        raise BeadsProtectedRuntimeError(f"{label} is oversized or changed while read")
    return bytes(data)


def _ensure_private_directory(path: Path, label: str, *, create: bool = False) -> None:
    if create:
        parent, leaf = _open_absolute_parent(path, label)
        try:
            try:
                os.mkdir(leaf, mode=0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        finally:
            os.close(parent)
    descriptor, _ = _open_absolute_directory(path, label, private=True)
    os.close(descriptor)


def _safe_join(root: Path, *parts: str) -> Path:
    current = root
    for part in parts:
        if not _SAFE_ID.fullmatch(part):
            raise BeadsProtectedRuntimeError("protected path component is invalid")
        current = current / part
    return current


class _Store:
    def __init__(self, payload: Mapping[str, Any]) -> None:
        _required(payload, "protectedRoot", "hmacKeyPath", "repositoryLocatorSha256")
        repository_digest = _digest(payload["repositoryLocatorSha256"], "repositoryLocatorSha256")
        assert repository_digest is not None
        self.repository_digest = repository_digest
        self.root = Path(str(payload["protectedRoot"]))
        self.key_path = Path(str(payload["hmacKeyPath"]))
        self._root_fd, self.root_ancestry = _open_absolute_directory(self.root, "protected root", private=True)
        if self.key_path.parent != self.root or not self.key_path.is_absolute():
            raise BeadsProtectedRuntimeError("HMAC key must be a direct protected-root child")
        try:
            key_descriptor = os.open(
                self.key_path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._root_fd,
            )
        except OSError as exc:
            raise BeadsProtectedRuntimeError(
                f"Beads protected-runtime HMAC key must be a non-symlink single-link regular file: {exc}"
            ) from exc
        try:
            self.key = _read_regular_descriptor(key_descriptor, "Beads protected-runtime HMAC key")
        finally:
            os.close(key_descriptor)
        if len(self.key) < 32 or len(self.key) > 4096:
            raise BeadsProtectedRuntimeError("Beads HMAC key must contain 32..4096 bytes")
        namespace = self.root / REPOSITORY_NAMESPACE
        try:
            os.mkdir(REPOSITORY_NAMESPACE, mode=0o700, dir_fd=self._root_fd)
            os.fsync(self._root_fd)
        except FileExistsError:
            pass
        namespace_fd = os.open(
            REPOSITORY_NAMESPACE,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=self._root_fd,
        )
        _validate_directory_metadata(os.fstat(namespace_fd), "Beads authority namespace", private=True)
        self.repository = namespace / repository_digest.removeprefix("sha256:")
        repository_name = repository_digest.removeprefix("sha256:")
        try:
            os.mkdir(repository_name, mode=0o700, dir_fd=namespace_fd)
            os.fsync(namespace_fd)
        except FileExistsError:
            pass
        self._repository_fd = os.open(
            repository_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=namespace_fd,
        )
        os.close(namespace_fd)
        _validate_directory_metadata(
            os.fstat(self._repository_fd),
            "Beads repository authority namespace",
            private=True,
        )
        self.lock_path = self.repository / "repository.lock"

    def __del__(self) -> None:
        for name in ("_repository_fd", "_root_fd"):
            descriptor = getattr(self, name, None)
            if isinstance(descriptor, int) and descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, -1)

    def _relative_parts(self, path: Path) -> tuple[str, ...]:
        try:
            relative = path.relative_to(self.repository)
        except ValueError as exc:
            raise BeadsProtectedRuntimeError("protected record path escaped its repository namespace") from exc
        parts = relative.parts
        if not parts or any(not _SAFE_ID.fullmatch(part) for part in parts):
            raise BeadsProtectedRuntimeError("protected record path contains an unsafe component")
        return parts

    def _open_directory(self, parts: Sequence[str], *, create: bool) -> int:
        descriptor = os.dup(self._repository_fd)
        try:
            for part in parts:
                if not _SAFE_ID.fullmatch(part):
                    raise BeadsProtectedRuntimeError("protected path component is invalid")
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                        os.fsync(descriptor)
                    except FileExistsError:
                        pass
                child = os.open(
                    part,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                _validate_directory_metadata(os.fstat(child), "protected record directory", private=True)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except (OSError, BeadsProtectedRuntimeError) as exc:
            os.close(descriptor)
            if isinstance(exc, BeadsProtectedRuntimeError):
                raise
            raise BeadsProtectedRuntimeError(f"protected record ancestry is unsafe or changed: {exc}") from exc

    def _open_parent(self, path: Path, *, create: bool = False) -> tuple[int, str]:
        parts = self._relative_parts(path)
        return self._open_directory(parts[:-1], create=create), parts[-1]

    def _read_bytes(
        self,
        path: Path,
        label: str,
        *,
        max_bytes: int = MAX_CANONICAL_BYTES,
    ) -> bytes:
        parent, leaf = self._open_parent(path)
        try:
            descriptor = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
            try:
                return _read_regular_descriptor(descriptor, label, max_bytes=max_bytes)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise BeadsProtectedRuntimeError(f"cannot read {label} without following links: {exc}") from exc
        finally:
            os.close(parent)

    def exists(self, path: Path) -> bool:
        parent, leaf = self._open_parent(path)
        try:
            try:
                metadata = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if stat.S_ISLNK(metadata.st_mode):
                raise BeadsProtectedRuntimeError("protected path is a substituted symlink")
            return True
        finally:
            os.close(parent)

    def locked(self):
        return _RepositoryLock(self)

    def sign(self, kind: str, payload: Mapping[str, Any]) -> tuple[dict[str, Any], str, str, str]:
        body = {"kind": kind, "schemaVersion": SCHEMA_VERSION, **_plain(payload)}
        body_bytes = canonical_bytes(body)
        record_digest = sha256(body_bytes)
        domain = f"startup-factory/{kind}/v1\0".encode("ascii")
        auth = "hmac-sha256:" + hmac.new(self.key, domain + body_bytes, hashlib.sha256).hexdigest()
        envelope = {"payload": body, "auth": auth}
        envelope_bytes = canonical_bytes(envelope)
        return envelope, auth, record_digest, sha256(envelope_bytes)

    def verify(self, envelope: Mapping[str, Any], kind: str) -> tuple[dict[str, Any], str, str, str]:
        if set(envelope) != {"payload", "auth"} or not isinstance(envelope["payload"], Mapping):
            raise BeadsProtectedRuntimeError("protected envelope has an unknown or missing field")
        body = _plain(envelope["payload"])
        if body.get("kind") != kind or body.get("schemaVersion") != SCHEMA_VERSION:
            raise BeadsProtectedRuntimeError("protected envelope kind/schema mismatch")
        candidate, auth, record_digest, full_digest = self.sign(kind, {k: v for k, v in body.items() if k not in {"kind", "schemaVersion"}})
        if not hmac.compare_digest(str(envelope["auth"]), auth) or canonical_bytes(candidate) != canonical_bytes(envelope):
            raise BeadsProtectedRuntimeError("protected envelope authentication failed")
        return body, auth, record_digest, full_digest

    def directory(self, *parts: str) -> Path:
        current = self.repository
        descriptor = self._open_directory(parts, create=True)
        os.close(descriptor)
        for part in parts:
            current = _safe_join(current, part)
        return current

    def read_json(self, path: Path, label: str) -> dict[str, Any]:
        raw = self._read_bytes(path, label)
        try:
            value = json.loads(raw, parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise BeadsProtectedRuntimeError(f"{label} contains malformed JSON") from exc
        if not isinstance(value, dict) or canonical_bytes(value) != raw:
            raise BeadsProtectedRuntimeError(f"{label} is not exact canonical JSON")
        return value

    def write_immutable(self, path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
        encoded = canonical_bytes(value)
        parent, leaf = self._open_parent(path, create=True)
        try:
            try:
                descriptor = os.open(
                    leaf,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    mode,
                    dir_fd=parent,
                )
            except FileExistsError:
                if self._read_bytes(path, "existing protected record") != encoded:
                    raise BeadsProtectedRuntimeError("immutable protected record collision")
                return
            try:
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(parent)
        finally:
            os.close(parent)

    def write_immutable_bytes(
        self,
        path: Path,
        encoded: bytes,
        mode: int,
        *,
        max_bytes: int = MAX_CANONICAL_BYTES,
    ) -> None:
        if not encoded or len(encoded) > max_bytes:
            raise BeadsProtectedRuntimeError("immutable protected bytes are empty or oversized")
        parent, leaf = self._open_parent(path, create=True)
        try:
            try:
                descriptor = os.open(
                    leaf,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    mode,
                    dir_fd=parent,
                )
            except FileExistsError:
                if self._read_bytes(
                    path,
                    "existing immutable protected bytes",
                    max_bytes=max_bytes,
                ) != encoded:
                    raise BeadsProtectedRuntimeError("immutable protected byte collision")
                metadata = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                if stat.S_IMODE(metadata.st_mode) != mode:
                    raise BeadsProtectedRuntimeError("immutable protected byte mode changed")
                return
            try:
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fchmod(descriptor, mode)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(parent)
        finally:
            os.close(parent)

    def unlink_exact(self, path: Path, expected: bytes, label: str) -> None:
        parent, leaf = self._open_parent(path)
        try:
            if self._read_bytes(path, label) != expected:
                raise BeadsProtectedRuntimeError("immutable protected record collision")
            os.unlink(leaf, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)

    def replace_current(self, path: Path, value: Mapping[str, Any], expected_full_digest: str | None) -> str:
        encoded = canonical_bytes(value)
        current_digest: str | None = None
        if self.exists(path):
            current_digest = sha256(self._read_bytes(path, "current protected record"))
        if current_digest != expected_full_digest:
            raise BeadsStaleAuthorityError("current protected authority predecessor changed")
        parent, leaf = self._open_parent(path, create=True)
        temporary = f"current-temp-{secrets.token_hex(16)}"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent,
            )
            os.write(descriptor, encoded)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)
        return sha256(encoded)


class _RepositoryLock:
    def __init__(self, store: _Store) -> None:
        self.store = store
        self.descriptor: int | None = None

    def __enter__(self) -> _Store:
        self.descriptor = os.open(
            "repository.lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=self.store._repository_fd,
        )
        metadata = os.fstat(self.descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise BeadsProtectedRuntimeError("repository authority lock is unsafe")
        fcntl.flock(self.descriptor, fcntl.LOCK_EX)
        return self.store

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        assert self.descriptor is not None
        fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        os.close(self.descriptor)


def _record_result(type_name: str, body: Mapping[str, Any], auth: str, record_digest: str, full_digest: str) -> _WireRecord:
    return globals()[type_name](payload=body, auth=auth, record_sha256=record_digest, full_bytes_sha256=full_digest)


_JOURNAL_BODY_FIELDS = {
    "kind", "schemaVersion", "generation", "recordKind", "recordSha256",
    "recordFullBytesSha256", "repositoryLocatorSha256",
    "predecessorJournalEntryRecordSha256", "predecessorJournalEntryFullBytesSha256",
}


def _directory_json_names(store: _Store, parts: tuple[str, ...]) -> set[str]:
    descriptor = store._open_directory(parts, create=True)
    try:
        names = {entry.name for entry in os.scandir(descriptor)}
    finally:
        os.close(descriptor)
    if any(not re.fullmatch(r"[0-9a-f]{64}\.json", name) for name in names):
        raise BeadsProtectedRuntimeError("protected HMAC journal contains an unexpected filename")
    return names


def _journal_chain(store: _Store) -> tuple[dict[str, tuple[str, str, dict[str, Any]]], str | None, str | None, int]:
    """Verify one complete, monotonic and uniquely linked journal chain."""

    current_path = store.directory("journals") / "current.json"
    history_names = _directory_json_names(store, ("journals", "history"))
    index_names = _directory_json_names(store, ("journals", "by-record"))
    if not store.exists(current_path):
        if history_names or index_names:
            raise BeadsProtectedRuntimeError("protected HMAC journal has evidence without a current head")
        return {}, None, None, 0
    current = store.read_json(current_path, "current protected HMAC journal entry")
    _, _, current_record, current_full = store.verify(current, "beads-protected-journal-entry")
    seen_entries: set[str] = set()
    by_protected_record: dict[str, tuple[str, str, dict[str, Any]]] = {}
    envelope = current
    expected_generation: int | None = None
    while True:
        body, _, journal_record, journal_full = store.verify(envelope, "beads-protected-journal-entry")
        if set(body) != _JOURNAL_BODY_FIELDS:
            raise BeadsProtectedRuntimeError("protected HMAC journal entry has an unknown or missing field")
        generation = _generation(body.get("generation"))
        if expected_generation is None:
            expected_generation = generation
        elif generation != expected_generation:
            raise BeadsProtectedRuntimeError("protected HMAC journal generations are not contiguous")
        if journal_record in seen_entries:
            raise BeadsProtectedRuntimeError("protected HMAC journal contains a predecessor cycle")
        if body.get("repositoryLocatorSha256") != store.repository_digest:
            raise BeadsProtectedRuntimeError("protected HMAC journal repository binding mismatch")
        protected_record = _digest(body.get("recordSha256"), "journal recordSha256")
        protected_full = _digest(body.get("recordFullBytesSha256"), "journal recordFullBytesSha256")
        assert protected_record is not None and protected_full is not None
        if protected_record in by_protected_record:
            raise BeadsProtectedRuntimeError("protected record has multiple journal successors")
        history_path = store.directory("journals", "history") / f"{journal_record.removeprefix('sha256:')}.json"
        if not store.exists(history_path) or canonical_bytes(store.read_json(history_path, "journal chain history")) != canonical_bytes(envelope):
            raise BeadsProtectedRuntimeError("protected HMAC journal head/predecessor lacks exact immutable history")
        seen_entries.add(journal_record)
        by_protected_record[protected_record] = (journal_record, journal_full, body)
        predecessor = _digest(
            body.get("predecessorJournalEntryRecordSha256"),
            "predecessorJournalEntryRecordSha256",
            nullable=True,
        )
        predecessor_full = _digest(
            body.get("predecessorJournalEntryFullBytesSha256"),
            "predecessorJournalEntryFullBytesSha256",
            nullable=True,
        )
        if predecessor is None:
            if predecessor_full is not None or generation != 1:
                raise BeadsProtectedRuntimeError("protected HMAC journal genesis is malformed")
            break
        if predecessor_full is None or generation == 1:
            raise BeadsProtectedRuntimeError("protected HMAC journal predecessor/full-bytes pair is malformed")
        predecessor_path = store.directory("journals", "history") / f"{predecessor.removeprefix('sha256:')}.json"
        envelope = store.read_json(predecessor_path, "predecessor protected HMAC journal entry")
        _, _, observed_predecessor, observed_predecessor_full = store.verify(
            envelope, "beads-protected-journal-entry"
        )
        if observed_predecessor != predecessor or observed_predecessor_full != predecessor_full:
            raise BeadsProtectedRuntimeError("protected HMAC journal predecessor identity mismatch")
        expected_generation = generation - 1
    expected_history_names = {value[0].removeprefix("sha256:") + ".json" for value in by_protected_record.values()}
    if history_names != expected_history_names:
        raise BeadsProtectedRuntimeError("protected HMAC journal contains an orphan, fork or missing history entry")
    expected_index_names = {record.removeprefix("sha256:") + ".json" for record in by_protected_record}
    if index_names != expected_index_names:
        raise BeadsProtectedRuntimeError("protected HMAC journal record index is incomplete or forked")
    for protected_record, (journal_record, journal_full, _) in by_protected_record.items():
        index = store.read_json(
            store.directory("journals", "by-record") / (protected_record.removeprefix("sha256:") + ".json"),
            "protected HMAC journal record index",
        )
        _, _, indexed_record, indexed_full = store.verify(index, "beads-protected-journal-entry")
        if indexed_record != journal_record or indexed_full != journal_full:
            raise BeadsProtectedRuntimeError("protected HMAC journal record index selects another successor")
    return by_protected_record, current_record, current_full, _generation(current["payload"]["generation"])


def _journal_record(store: _Store, kind: str, record_digest: str, full_digest: str) -> None:
    chain, predecessor, expected_current, generation = _journal_chain(store)
    existing = chain.get(record_digest)
    if existing is not None:
        _, existing_full, body = existing
        if (
            body.get("recordKind") != kind
            or body.get("recordFullBytesSha256") != full_digest
            or existing_full is None
        ):
            raise BeadsProtectedRuntimeError("protected HMAC journal record index collision")
        return
    next_generation = generation + 1
    _generation(next_generation)
    payload = {
        "generation": next_generation,
        "recordKind": kind,
        "recordSha256": record_digest,
        "recordFullBytesSha256": full_digest,
        "repositoryLocatorSha256": store.repository_digest,
        "predecessorJournalEntryRecordSha256": predecessor,
        "predecessorJournalEntryFullBytesSha256": expected_current,
    }
    envelope, _, journal_digest, journal_full = store.sign("beads-protected-journal-entry", payload)
    history = store.directory("journals", "history") / f"{journal_digest.removeprefix('sha256:')}.json"
    lookup = store.directory("journals", "by-record") / f"{record_digest.removeprefix('sha256:')}.json"
    store.write_immutable(history, envelope)
    store.write_immutable(lookup, envelope)
    observed = store.replace_current(store.directory("journals") / "current.json", envelope, expected_current)
    if observed != journal_full:
        raise BeadsProtectedRuntimeError("protected HMAC journal head exact-byte mismatch")
    _journal_chain(store)


def _verify_journal(store: _Store, kind: str, record_digest: str, full_digest: str) -> None:
    chain, _, _, _ = _journal_chain(store)
    indexed = chain.get(record_digest)
    if indexed is None:
        raise BeadsProtectedRuntimeError("protected record has no exact HMAC journal entry in the current chain")
    _, _, body = indexed
    if body.get("recordKind") != kind or body.get("recordFullBytesSha256") != full_digest:
        raise BeadsProtectedRuntimeError("protected HMAC journal entry mismatch")


def _journal_binding_for_record(
    store: _Store,
    record_digest: str,
    full_digest: str,
    *,
    require_current: bool = False,
) -> tuple[str, str]:
    chain, current_record, current_full, _ = _journal_chain(store)
    binding = chain.get(record_digest)
    if binding is None or binding[2].get("recordFullBytesSha256") != full_digest:
        raise BeadsProtectedRuntimeError("protected result has no exact result-stored journal head")
    if require_current and (binding[0] != current_record or binding[1] != current_full):
        raise BeadsProtectedRuntimeError("protected result is not the actual current result-stored journal head")
    return binding[0], binding[1]


def _signed_record(store: _Store, type_name: str, kind: str, payload: Mapping[str, Any], category: str) -> _WireRecord:
    envelope, auth, record_digest, full_digest = store.sign(kind, payload)
    directory = store.directory(category, "history")
    store.write_immutable(directory / f"{record_digest.removeprefix('sha256:')}.json", envelope)
    _journal_record(store, kind, record_digest, full_digest)
    return _record_result(type_name, envelope["payload"], auth, record_digest, full_digest)


def _load_record(store: _Store, type_name: str, kind: str, category: str, record_digest: str) -> _WireRecord:
    digest = _digest(record_digest, "recordSha256")
    assert digest is not None
    path = store.directory(category, "history") / f"{digest.removeprefix('sha256:')}.json"
    envelope = store.read_json(path, f"{kind} history record")
    body, auth, observed_record, full_digest = store.verify(envelope, kind)
    if observed_record != digest:
        raise BeadsProtectedRuntimeError("protected history filename/digest mismatch")
    _verify_journal(store, kind, observed_record, full_digest)
    return _record_result(type_name, body, auth, observed_record, full_digest)


def _load_current(store: _Store, type_name: str, kind: str, category: str) -> _WireRecord:
    path = store.directory(category) / "current.json"
    if not store.exists(path):
        raise BeadsProtectedRuntimeError(f"no current {kind} exists")
    envelope = store.read_json(path, f"current {kind}")
    body, auth, record_digest, full_digest = store.verify(envelope, kind)
    history = store.directory(category, "history") / f"{record_digest.removeprefix('sha256:')}.json"
    if not store.exists(history) or canonical_bytes(store.read_json(history, f"{kind} history")) != canonical_bytes(envelope):
        raise BeadsProtectedRuntimeError(f"current {kind} has no exact immutable history")
    _verify_journal(store, kind, record_digest, full_digest)
    return _record_result(type_name, body, auth, record_digest, full_digest)


def _write_current(
    store: _Store,
    type_name: str,
    kind: str,
    category: str,
    payload: Mapping[str, Any],
    expected_full_digest: str | None,
) -> _WireRecord:
    envelope, auth, record_digest, full_digest = store.sign(kind, payload)
    history = store.directory(category, "history") / f"{record_digest.removeprefix('sha256:')}.json"
    store.write_immutable(history, envelope)
    _journal_record(store, kind, record_digest, full_digest)
    observed = store.replace_current(store.directory(category) / "current.json", envelope, expected_full_digest)
    if observed != full_digest:
        raise BeadsProtectedRuntimeError("protected current exact-byte digest mismatch")
    return _record_result(type_name, envelope["payload"], auth, record_digest, full_digest)


def _load_capability(store: _Store, category: str, kind: str, record_digest: str) -> _WireRecord:
    return _load_record(store, "_WireRecord", kind, category, record_digest)


def _consume_capability(store: _Store, category: str, capability: _WireRecord, intent_digest: str) -> None:
    if capability.record_sha256 is None:
        raise BeadsProtectedRuntimeError("capability has no protected record digest")
    consumed = store.directory(category, "consumed") / f"{capability.record_sha256.removeprefix('sha256:')}.json"
    payload = {
        "capabilityRecordSha256": capability.record_sha256,
        "capabilityFullBytesSha256": capability.full_bytes_sha256,
        "transactionIntentSha256": intent_digest,
        "repositoryLocatorSha256": store.repository_digest,
    }
    kind = f"beads-{category.removesuffix('s')}-consumed"
    value, _, record_digest, full_digest = store.sign(kind, payload)
    if store.exists(consumed):
        existing = store.read_json(consumed, "capability consumption record")
        body, _, observed_record, observed_full = store.verify(existing, kind)
        if (
            observed_record != record_digest
            or observed_full != full_digest
            or canonical_bytes(existing) != canonical_bytes(value)
            or any(body.get(key) != item for key, item in payload.items())
        ):
            raise BeadsCapabilityConsumedError("capability was consumed by another transaction")
        return
    store.write_immutable(consumed, value)
    _journal_record(store, kind, record_digest, full_digest)


def _capability_consumed_by(
    store: _Store,
    category: str,
    capability: _WireRecord,
    intent_digest: str,
) -> bool:
    if capability.record_sha256 is None:
        raise BeadsProtectedRuntimeError("capability has no protected record digest")
    path = store.directory(category, "consumed") / f"{capability.record_sha256.removeprefix('sha256:')}.json"
    if not store.exists(path):
        return False
    kind = f"beads-{category.removesuffix('s')}-consumed"
    envelope = store.read_json(path, "capability consumption recovery record")
    body, _, record_digest, full_digest = store.verify(envelope, kind)
    _verify_journal(store, kind, record_digest, full_digest)
    if body.get("transactionIntentSha256") != intent_digest:
        raise BeadsCapabilityConsumedError("capability was consumed by another transaction")
    return True


def _expiry(payload: Mapping[str, Any]) -> None:
    value = payload.get("expiresAtUnix")
    if not isinstance(value, int) or isinstance(value, bool) or value <= int(time.time()) or value > int(time.time()) + 31_536_000:
        raise BeadsProtectedRuntimeError("protected capability expiry is absent, expired or beyond one year")


def _same_repository(store: _Store, payload: Mapping[str, Any]) -> None:
    if payload.get("repositoryLocatorSha256") != store.repository_digest:
        raise BeadsProtectedRuntimeError("protected record repository identity mismatch")


def _transaction_intent(store: _Store, operation: str, payload: Mapping[str, Any]) -> tuple[str, Path]:
    _identifier(operation, "transaction operation")
    operation_id = sha256(canonical_bytes({"operation": operation, "request": payload})).removeprefix("sha256:")
    directory = store.directory("transactions", operation_id)
    intent_payload = {
        "operation": operation,
        "requestSha256": sha256(canonical_bytes(payload)),
        "operationId": operation_id,
        "repositoryLocatorSha256": store.repository_digest,
        "predecessorTransactionIntentSha256": None,
    }
    kind = f"beads-{operation}-transaction-intent"
    intent, _, intent_digest, intent_full = store.sign(kind, intent_payload)
    path = directory / "intent.json"
    store.write_immutable(path, intent)
    observed = store.read_json(path, "transaction intent")
    body, _, observed_digest, observed_full = store.verify(observed, kind)
    if (
        canonical_bytes(observed) != canonical_bytes(intent)
        or observed_digest != intent_digest
        or observed_full != intent_full
        or any(body.get(key) != item for key, item in intent_payload.items())
    ):
        raise BeadsProtectedRuntimeError("transaction intent recovery mismatch")
    _journal_record(store, kind, intent_digest, intent_full)
    return intent_digest, directory


def _transaction_receipt(store: _Store, directory: Path, operation: str, result: _WireRecord) -> None:
    intent = store.read_json(directory / "intent.json", "transaction intent predecessor")
    intent_kind = f"beads-{operation}-transaction-intent"
    _, _, intent_digest, _ = store.verify(intent, intent_kind)
    receipt_payload = {
        "operation": operation,
        "transactionIntentSha256": intent_digest,
        "resultRecordSha256": result.record_sha256,
        "resultFullBytesSha256": result.full_bytes_sha256,
        "repositoryLocatorSha256": store.repository_digest,
    }
    kind = f"beads-{operation}-transaction-receipt"
    receipt, _, receipt_digest, receipt_full = store.sign(kind, receipt_payload)
    store.write_immutable(directory / "receipt.json", receipt)
    _journal_record(store, kind, receipt_digest, receipt_full)


def _resume_transaction_result(
    store: _Store,
    directory: Path,
    operation: str,
    type_name: str,
    kind: str,
    category: str,
) -> _WireRecord | None:
    receipt_path = directory / "receipt.json"
    if not store.exists(receipt_path):
        return None
    envelope = store.read_json(receipt_path, "transaction receipt")
    kind_name = f"beads-{operation}-transaction-receipt"
    receipt, _, receipt_digest, receipt_full = store.verify(envelope, kind_name)
    _verify_journal(store, kind_name, receipt_digest, receipt_full)
    if receipt.get("operation") != operation or receipt.get("repositoryLocatorSha256") != store.repository_digest:
        raise BeadsProtectedRuntimeError("transaction receipt operation mismatch")
    result = _load_record(store, type_name, kind, category, receipt.get("resultRecordSha256"))
    if result.full_bytes_sha256 != receipt.get("resultFullBytesSha256"):
        raise BeadsProtectedRuntimeError("transaction receipt exact result digest mismatch")
    return result


def _recover_current_transaction_result(
    store: _Store,
    directory: Path,
    operation: str,
    type_name: str,
    kind: str,
    category: str,
    intent_digest: str,
) -> _WireRecord | None:
    current_path = store.directory(category) / "current.json"
    if not store.exists(current_path):
        return None
    envelope = store.read_json(current_path, f"current {kind} recovery")
    body, auth, record_digest, full_digest = store.verify(envelope, kind)
    if body.get("transactionIntentSha256") != intent_digest:
        return None
    result = _record_result(type_name, body, auth, record_digest, full_digest)
    history = store.directory(category, "history") / f"{record_digest.removeprefix('sha256:')}.json"
    if not store.exists(history) or canonical_bytes(store.read_json(history, f"{kind} recovery history")) != canonical_bytes(envelope):
        raise BeadsProtectedRuntimeError("current transaction result lacks exact immutable history")
    _verify_journal(store, kind, record_digest, full_digest)
    _transaction_receipt(store, directory, operation, result)
    return result


def prepare_atomic_claim_v1(request: PrepareAtomicClaimRequestV1) -> AtomicClaimLeaseV1:
    payload = _request(request, "PrepareAtomicClaimRequestV1")
    _required(payload, "taskId", "expectedRevision", "claimNonce", "expiresAtUnix")
    _identifier(payload["taskId"], "taskId")
    _identifier(payload["claimNonce"], "claimNonce")
    _expiry(payload)
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "prepare-atomic-claim", payload)
        resumed = _resume_transaction_result(
            store, directory, "prepare-atomic-claim", "AtomicClaimLeaseV1",
            "atomic-claim-lease", "claims",
        )
        if resumed is not None:
            return resumed
        authority = _current_authority(store, require_active=True)
        reservation_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "taskId": payload["taskId"],
            "transactionIntentSha256": intent_digest,
        }
        reservation, _, reservation_digest, reservation_full = store.sign(
            "beads-atomic-claim-task-reservation", reservation_payload
        )
        reservation_path = store.directory("claim-task-reservations") / (
            sha256(str(payload["taskId"]).encode("utf-8")).removeprefix("sha256:") + ".json"
        )
        if store.exists(reservation_path):
            existing = store.read_json(reservation_path, "atomic claim task reservation")
            if canonical_bytes(existing) != canonical_bytes(reservation):
                raise BeadsCapabilityConsumedError("task already has another protected atomic-claim reservation")
        else:
            store.write_immutable(reservation_path, reservation)
            _journal_record(store, "beads-atomic-claim-task-reservation", reservation_digest, reservation_full)
        lease_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "taskId": payload["taskId"],
            "expectedRevision": payload["expectedRevision"],
            "claimNonce": payload["claimNonce"],
            "expiresAtUnix": payload["expiresAtUnix"],
            "claimState": "prepared",
            "activeAuthorityRecordSha256": authority.record_sha256,
            "transactionIntentSha256": intent_digest,
        }
        result = _signed_record(store, "AtomicClaimLeaseV1", "atomic-claim-lease", lease_payload, "claims")
        _transaction_receipt(store, directory, "prepare-atomic-claim", result)
        return result


def advance_atomic_claim_v1(request: AdvanceAtomicClaimRequestV1) -> AtomicClaimLeaseV1:
    payload = _request(request, "AdvanceAtomicClaimRequestV1")
    _required(payload, "leaseRecordSha256", "observedRevision", "observedStatus", "claimSucceeded")
    store = _Store(payload)
    if not isinstance(payload["claimSucceeded"], bool):
        raise BeadsProtectedRuntimeError("claimSucceeded must be boolean")
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "advance-atomic-claim", payload)
        resumed = _resume_transaction_result(
            store, directory, "advance-atomic-claim", "AtomicClaimLeaseV1",
            "atomic-claim-lease", "claims",
        )
        if resumed is not None:
            return resumed
        prior = _load_record(store, "AtomicClaimLeaseV1", "atomic-claim-lease", "claims", payload["leaseRecordSha256"])
        _expiry(prior.payload)
        _same_repository(store, prior.payload)
        _require_current_authority_record(
            store, prior.payload.get("activeAuthorityRecordSha256"), "active"
        )
        if prior.payload.get("claimState") != "prepared":
            raise BeadsStaleAuthorityError("atomic claim lease is not in prepared state")
        _consume_capability(store, "atomic-claim-successors", prior, intent_digest)
        if payload["claimSucceeded"] and payload["observedRevision"] == prior.payload.get("expectedRevision"):
            raise BeadsStaleAuthorityError("successful conditional claim must return a new revision")
        state = "claimed" if payload["claimSucceeded"] else "stale"
        result_payload = {
            **{key: value for key, value in prior.payload.items() if key not in {"kind", "schemaVersion", "claimState"}},
            "claimState": state,
            "predecessorLeaseRecordSha256": prior.record_sha256,
            "observedRevision": payload["observedRevision"],
            "observedStatus": payload["observedStatus"],
        }
        result = _signed_record(store, "AtomicClaimLeaseV1", "atomic-claim-lease", result_payload, "claims")
        _transaction_receipt(store, directory, "advance-atomic-claim", result)
        return result


def record_atomic_claim_receipt_v1(request: RecordAtomicClaimReceiptRequestV1) -> AtomicClaimReceiptV1:
    payload = _request(request, "RecordAtomicClaimReceiptRequestV1")
    _required(payload, "leaseRecordSha256", "readBackRevision", "readBackStatus", "claimIdentitySha256")
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "record-atomic-claim-receipt", payload)
        resumed = _resume_transaction_result(
            store, directory, "record-atomic-claim-receipt", "AtomicClaimReceiptV1",
            "atomic-claim-receipt", "claim-receipts",
        )
        if resumed is not None:
            return resumed
        lease = _load_record(store, "AtomicClaimLeaseV1", "atomic-claim-lease", "claims", payload["leaseRecordSha256"])
        _same_repository(store, lease.payload)
        _require_current_authority_record(
            store, lease.payload.get("activeAuthorityRecordSha256"), "active"
        )
        if lease.payload.get("claimState") != "claimed":
            raise BeadsStaleAuthorityError("claim receipt requires a successful claimed lease")
        if payload["readBackRevision"] != lease.payload.get("observedRevision") or payload["readBackStatus"] != lease.payload.get("observedStatus"):
            raise BeadsStaleAuthorityError("claim read-back no longer matches the atomic observation")
        _digest(payload["claimIdentitySha256"], "claimIdentitySha256")
        _consume_capability(store, "atomic-claim-receipt-successors", lease, intent_digest)
        result = _signed_record(
            store,
            "AtomicClaimReceiptV1",
            "atomic-claim-receipt",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "leaseRecordSha256": lease.record_sha256,
                "taskId": lease.payload["taskId"],
                "revision": payload["readBackRevision"],
                "status": payload["readBackStatus"],
                "claimIdentitySha256": payload["claimIdentitySha256"],
                "activeAuthorityRecordSha256": lease.payload["activeAuthorityRecordSha256"],
            },
            "claim-receipts",
        )
        _transaction_receipt(store, directory, "record-atomic-claim-receipt", result)
        return result


def _current_authority(store: _Store, *, require_active: bool) -> _WireRecord:
    result = _load_current(store, "BeadsAuthorityEpochStateV1", "beads-authority-epoch-state", "authority")
    _same_repository(store, result.payload)
    if require_active and result.payload.get("authorityState") != "active":
        raise BeadsProtectedRuntimeError("ordinary Beads authority is not active")
    return result


def _require_current_authority_record(
    store: _Store,
    expected_record_sha256: Any,
    required_state: str,
) -> _WireRecord:
    expected = _digest(expected_record_sha256, f"{required_state}AuthorityRecordSha256")
    current = _current_authority(store, require_active=required_state == "active")
    if current.payload.get("authorityState") != required_state or current.record_sha256 != expected:
        raise BeadsStaleAuthorityError(
            f"protected operation no longer binds the current {required_state} authority"
        )
    return current


def authorize_claim_launch_v1(request: AuthorizeClaimLaunchRequestV1) -> LaunchAuthorizationV1:
    payload = _request(request, "AuthorizeClaimLaunchRequestV1")
    _required(payload, "claimReceiptRecordSha256", "launchNonce", "expiresAtUnix")
    _identifier(payload["launchNonce"], "launchNonce")
    _expiry(payload)
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "authorize-claim-launch", payload)
        resumed = _resume_transaction_result(
            store, directory, "authorize-claim-launch", "LaunchAuthorizationV1",
            "claim-launch-authorization", "claim-launch",
        )
        if resumed is not None:
            return resumed
        receipt = _load_record(store, "AtomicClaimReceiptV1", "atomic-claim-receipt", "claim-receipts", payload["claimReceiptRecordSha256"])
        authority = _require_current_authority_record(
            store, receipt.payload.get("activeAuthorityRecordSha256"), "active"
        )
        _consume_capability(store, "claim-launch-successors", receipt, intent_digest)
        result = _signed_record(
            store,
            "LaunchAuthorizationV1",
            "claim-launch-authorization",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "claimReceiptRecordSha256": receipt.record_sha256,
                "activeAuthorityRecordSha256": authority.record_sha256,
                "launchNonce": payload["launchNonce"],
                "expiresAtUnix": payload["expiresAtUnix"],
                "transactionIntentSha256": intent_digest,
            },
            "claim-launch",
        )
        _transaction_receipt(store, directory, "authorize-claim-launch", result)
        return result


def _preparation_sequence_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "bootstrapChangeKind", "preparationMode", "preparationSequenceKind",
        "preparationSequenceSha256", "remediationEvidenceSha256", "databasePathKind",
        "createStageDatabasePathLocatorSha256", "installedDatabaseSelectorBindingSha256",
        "selectorObservationASha256", "selectedStoreObservationASha256",
    )
    _required(payload, *fields)
    mode = payload["preparationMode"]
    change = payload["bootstrapChangeKind"]
    sequence = payload["preparationSequenceKind"]
    valid = {
        ("create", "create", "create"),
        ("runtime-change", "create", "remediation-authorized"),
        ("reconciliation", "create", "reconciliation"),
        ("reattest", "reattest", "reattest"),
        ("runtime-change", "reattest", "remediation-authorized"),
        ("reconciliation", "reattest", "reconciliation"),
    }
    if (change, mode, sequence) not in valid:
        raise BeadsProtectedRuntimeError("preparation tuple is outside the six registered cells")
    remediation = _digest(payload["remediationEvidenceSha256"], "remediationEvidenceSha256", nullable=True)
    if change in {"runtime-change", "reconciliation"} and remediation is None:
        raise BeadsProtectedRuntimeError("remediation/reconciliation sequence requires authenticated evidence")
    if change in {"create", "reattest"} and remediation is not None:
        raise BeadsProtectedRuntimeError("non-remediation sequence forbids remediation evidence")
    for field in fields:
        if field.endswith("Sha256"):
            _digest(payload[field], field, nullable=True)
    if mode == "create":
        if payload["databasePathKind"] != "stage" or payload["createStageDatabasePathLocatorSha256"] is None:
            raise BeadsProtectedRuntimeError("create sequence requires only the stage database path")
        if any(payload[field] is not None for field in ("installedDatabaseSelectorBindingSha256", "selectorObservationASha256", "selectedStoreObservationASha256")):
            raise BeadsProtectedRuntimeError("create sequence forbids installed selector/store fields")
    else:
        if payload["databasePathKind"] != "installed-selector" or payload["createStageDatabasePathLocatorSha256"] is not None:
            raise BeadsProtectedRuntimeError("reattest sequence requires only the installed selector")
        if any(payload[field] is None for field in ("installedDatabaseSelectorBindingSha256", "selectorObservationASha256", "selectedStoreObservationASha256")):
            raise BeadsProtectedRuntimeError("reattest sequence requires selector/store A evidence")
    return {field: payload[field] for field in fields}


def begin_beads_mutation_v1(request: BeginBeadsMutationRequestV1) -> BeadsMutationIntentV1:
    payload = _request(request, "BeginBeadsMutationRequestV1")
    _required(payload, "mutationClass", "mutationNonce", "commandArgv", "expiresAtUnix")
    _identifier(payload["mutationNonce"], "mutationNonce")
    _expiry(payload)
    mutation_class = payload["mutationClass"]
    if mutation_class not in {"ordinary", "preparation"}:
        raise BeadsProtectedRuntimeError("mutationClass must be ordinary or preparation")
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "begin-beads-mutation", payload)
        resumed = _resume_transaction_result(
            store, directory, "begin-beads-mutation", "BeadsMutationIntentV1",
            "beads-mutation-intent", "mutation-intents",
        )
        if resumed is not None:
            return resumed
        binding: dict[str, Any]
        if mutation_class == "ordinary":
            _required(payload, "launchAuthorizationRecordSha256")
            launch = _load_record(
                store, "LaunchAuthorizationV1", "claim-launch-authorization", "claim-launch",
                payload["launchAuthorizationRecordSha256"],
            )
            _expiry(launch.payload)
            authority = _require_current_authority_record(
                store, launch.payload.get("activeAuthorityRecordSha256"), "active"
            )
            _consume_capability(store, "claim-launch-authorizations", launch, intent_digest)
            binding = {
                "activeAuthorityRecordSha256": authority.record_sha256,
                "launchAuthorizationRecordSha256": launch.record_sha256,
            }
        else:
            _required(payload, "preparationLeaseRecordSha256", "preparationCommandIntentRecordSha256")
            lease = _load_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", payload["preparationLeaseRecordSha256"])
            command = _load_record(store, "BeadsPreparationCommandIntentV1", "beads-preparation-command-intent", "preparation-commands", payload["preparationCommandIntentRecordSha256"])
            if command.payload.get("leaseRecordSha256") != lease.record_sha256:
                raise BeadsProtectedRuntimeError("preparation mutation command/lease chain mismatch")
            if tuple(payload["commandArgv"]) != tuple(command.payload.get("argv", ())):
                raise BeadsProtectedRuntimeError("preparation mutation argv differs from authorized command intent")
            revoked = _require_current_authority_record(
                store, lease.payload.get("revokedAuthorityRecordSha256"), "revoked"
            )
            _consume_capability(store, "preparation-command-intents", command, intent_digest)
            binding = {
                "preparationLeaseRecordSha256": lease.record_sha256,
                "preparationCommandIntentRecordSha256": command.record_sha256,
                "revokedAuthorityRecordSha256": revoked.record_sha256,
                **_preparation_sequence_fields(lease.payload),
            }
        intent_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "mutationClass": mutation_class,
            "mutationNonce": payload["mutationNonce"],
            "argv": payload["commandArgv"],
            "argvSha256": sha256(canonical_bytes(payload["commandArgv"])),
            "expiresAtUnix": payload["expiresAtUnix"],
            "transactionIntentSha256": intent_digest,
            **binding,
        }
        result = _signed_record(store, "BeadsMutationIntentV1", "beads-mutation-intent", intent_payload, "mutation-intents")
        _transaction_receipt(store, directory, "begin-beads-mutation", result)
        return result


def finish_beads_mutation_v1(request: FinishBeadsMutationRequestV1) -> BeadsMutationResultV1:
    payload = _request(request, "FinishBeadsMutationRequestV1")
    _required(payload, "mutationClass", "mutationIntentRecordSha256", "exitCode", "stdoutSha256", "stderrSha256", "readBackSha256")
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "finish-beads-mutation", payload)
        resumed = _resume_transaction_result(
            store, directory, "finish-beads-mutation", "BeadsMutationResultV1",
            "beads-mutation-result", "mutation-results",
        )
        if resumed is not None:
            return resumed
        intent = _load_record(store, "BeadsMutationIntentV1", "beads-mutation-intent", "mutation-intents", payload["mutationIntentRecordSha256"])
        _expiry(intent.payload)
        if payload["mutationClass"] != intent.payload.get("mutationClass"):
            raise BeadsProtectedRuntimeError("mutation result class differs from the protected intent")
        if intent.payload.get("mutationClass") == "ordinary":
            _require_current_authority_record(
                store, intent.payload.get("activeAuthorityRecordSha256"), "active"
            )
        else:
            _require_current_authority_record(
                store, intent.payload.get("revokedAuthorityRecordSha256"), "revoked"
            )
        for field in ("stdoutSha256", "stderrSha256", "readBackSha256"):
            _digest(payload[field], field)
        if not isinstance(payload["exitCode"], int) or isinstance(payload["exitCode"], bool):
            raise BeadsProtectedRuntimeError("exitCode must be an integer")
        _consume_capability(store, "beads-mutation-intent-successors", intent, intent_digest)
        result_payload = {
            **{key: value for key, value in intent.payload.items() if key not in {"kind", "schemaVersion"}},
            "mutationIntentRecordSha256": intent.record_sha256,
            "exitCode": payload["exitCode"],
            "stdoutSha256": payload["stdoutSha256"],
            "stderrSha256": payload["stderrSha256"],
            "readBackSha256": payload["readBackSha256"],
        }
        result = _signed_record(store, "BeadsMutationResultV1", "beads-mutation-result", result_payload, "mutation-results")
        _transaction_receipt(store, directory, "finish-beads-mutation", result)
        return result


def _observe_path_locator(path: Path, label: str, *, require_directory: bool = False) -> dict[str, Any]:
    parent, leaf = _open_absolute_parent(path, label)
    try:
        parent_metadata = os.fstat(parent)
        try:
            metadata = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            if require_directory:
                raise BeadsProtectedRuntimeError(f"{label} is absent")
            return {
                "pathSha256": sha256(os.fsencode(str(path))),
                "leafNameSha256": sha256(os.fsencode(leaf)),
                "present": False,
                "parentIdentity": _directory_identity(parent_metadata),
            }
        if stat.S_ISLNK(metadata.st_mode):
            raise BeadsProtectedRuntimeError(f"{label} is a substituted symlink")
        if require_directory and not stat.S_ISDIR(metadata.st_mode):
            raise BeadsProtectedRuntimeError(f"{label} must be a directory")
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise BeadsProtectedRuntimeError(f"{label} must be caller-owned and private")
        return {
            "pathSha256": sha256(os.fsencode(str(path))),
            "leafNameSha256": sha256(os.fsencode(leaf)),
            "present": True,
            "parentIdentity": _directory_identity(parent_metadata),
            "identity": _directory_identity(metadata) if stat.S_ISDIR(metadata.st_mode) else {
                **_directory_identity(metadata),
                "fileType": "regular" if stat.S_ISREG(metadata.st_mode) else "special",
            },
        }
    finally:
        os.close(parent)


def _observe_executable(path: Path, expected_sha256: str) -> dict[str, Any]:
    expected = _digest(expected_sha256, "executableSha256")
    assert expected is not None
    parent, leaf = _open_absolute_parent(path, "Beads executable")
    try:
        descriptor = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        try:
            metadata = os.fstat(descriptor)
            data = _read_regular_descriptor(
                descriptor,
                "Beads executable",
                executable=True,
                max_bytes=MAX_EXECUTABLE_BYTES,
            )
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise BeadsProtectedRuntimeError(f"cannot open the protected Beads executable: {exc}") from exc
    finally:
        os.close(parent)
    observed = sha256(data)
    if observed != expected:
        raise BeadsProtectedRuntimeError("Beads executable bytes differ from executableSha256")
    return {
        "pathSha256": sha256(os.fsencode(str(path))),
        "bytesSha256": observed,
        **_directory_identity(metadata),
    }


def _open_verified_executable_descriptor(path: Path, expected_observation: Mapping[str, Any]) -> int:
    parent, leaf = _open_absolute_parent(path, "Beads executable")
    descriptor = -1
    try:
        descriptor = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        metadata = os.fstat(descriptor)
        data = _read_regular_descriptor(
            descriptor,
            "Beads executable",
            executable=True,
            max_bytes=MAX_EXECUTABLE_BYTES,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = {
            "pathSha256": sha256(os.fsencode(str(path))),
            "bytesSha256": sha256(data),
            **_directory_identity(metadata),
        }
        if canonical_bytes(observed) != canonical_bytes(expected_observation):
            raise BeadsProtectedRuntimeError("protected Beads executable identity changed before spawn")
        return descriptor
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _install_pinned_executable(
    store: _Store,
    source_path: Path,
    source_observation: Mapping[str, Any],
) -> tuple[Path, dict[str, Any]]:
    descriptor = _open_verified_executable_descriptor(source_path, source_observation)
    try:
        data = bytearray()
        while len(data) <= MAX_EXECUTABLE_BYTES:
            block = os.read(descriptor, min(65536, MAX_EXECUTABLE_BYTES + 1 - len(data)))
            if not block:
                break
            data.extend(block)
    finally:
        os.close(descriptor)
    if len(data) > MAX_EXECUTABLE_BYTES or sha256(bytes(data)) != source_observation.get("bytesSha256"):
        raise BeadsProtectedRuntimeError("approved executable changed while creating the immutable broker copy")
    pinned = store.directory("approved-executables") / (
        str(source_observation["bytesSha256"]).removeprefix("sha256:") + ".bin"
    )
    store.write_immutable_bytes(pinned, bytes(data), 0o500, max_bytes=MAX_EXECUTABLE_BYTES)
    pinned_observation = _observe_executable(pinned, str(source_observation["bytesSha256"]))
    current_source = _observe_executable(source_path, str(source_observation["bytesSha256"]))
    if canonical_bytes(current_source) != canonical_bytes(source_observation):
        raise BeadsProtectedRuntimeError("approved executable path changed while pinning its immutable copy")
    return pinned, pinned_observation


def _spawn_verified_executable_v1(
    path: Path,
    expected_observation: Mapping[str, Any],
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    logical_path: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Spawn the already verified inode, never the mutable pathname."""

    expected_argv_path = logical_path if logical_path is not None else path
    if not argv or argv[0] != str(expected_argv_path):
        raise BeadsProtectedRuntimeError("spawn argv does not bind the approved executable path")
    descriptor = _open_verified_executable_descriptor(path, expected_observation)
    before = os.fstat(descriptor)
    try:
        prefix = os.pread(descriptor, 2, 0)
        if prefix == b"#!":
            spawn_argv = ["/bin/sh", f"/dev/fd/{descriptor}", *argv[1:]]
        elif os.uname().sysname == "Linux":
            spawn_argv = [f"/proc/self/fd/{descriptor}", *argv[1:]]
        else:
            raise BeadsProtectedRuntimeError(
                "descriptor-pinned native executable spawn requires Linux; Darwin offline fixtures must be POSIX shell scripts"
            )
        completed = subprocess.run(
            spawn_argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=dict(env),
            timeout=30,
            check=False,
            pass_fds=(descriptor,),
        )
        after = os.fstat(descriptor)
        if (
            before.st_dev, before.st_ino, before.st_mode, before.st_uid,
            before.st_nlink, before.st_size,
        ) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid,
            after.st_nlink, after.st_size,
        ):
            raise BeadsProtectedRuntimeError("approved Beads executable changed during descriptor-pinned spawn")
        current = _observe_executable(path, str(expected_observation.get("bytesSha256")))
        if canonical_bytes(current) != canonical_bytes(expected_observation):
            raise BeadsProtectedRuntimeError(
                "Beads executable pathname was replaced during spawn; replacement was not executed"
            )
        return completed
    finally:
        os.close(descriptor)


def _hash_regular_at(parent: int, name: str, metadata: os.stat_result, label: str) -> str:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid():
        raise BeadsProtectedRuntimeError(f"{label} contains an unsafe non-regular or hardlinked file")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise BeadsProtectedRuntimeError(f"{label} contains a group/world-writable file")
    descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        hasher = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            total += len(block)
            if total > 67_108_864:
                raise BeadsProtectedRuntimeError(f"{label} contains a file larger than 64 MiB")
            hasher.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_nlink) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_nlink
    ):
        raise BeadsProtectedRuntimeError(f"{label} changed during physical observation")
    return "sha256:" + hasher.hexdigest()


def _observe_directory_tree(path: Path, label: str) -> dict[str, Any]:
    root, ancestry = _open_absolute_directory(path, label, private=True)
    entries: list[dict[str, Any]] = []

    def walk(descriptor: int, prefix: str, depth: int) -> None:
        if depth > 32:
            raise BeadsProtectedRuntimeError(f"{label} exceeds the maximum tree depth")
        names = sorted(entry.name for entry in os.scandir(descriptor))
        for name in names:
            if len(entries) >= 4096 or name in {"", ".", ".."} or len(os.fsencode(name)) > 255:
                raise BeadsProtectedRuntimeError(f"{label} contains too many or unsafe entries")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            relative = f"{prefix}/{name}" if prefix else name
            common = {
                "relativePathSha256": sha256(os.fsencode(relative)),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "owner": metadata.st_uid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "linkCount": metadata.st_nlink,
                "size": metadata.st_size,
            }
            if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise BeadsProtectedRuntimeError(f"{label} contains substituted or writable state")
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                opened = os.fstat(child)
                if (
                    metadata.st_dev, metadata.st_ino, metadata.st_mode,
                    metadata.st_uid, metadata.st_nlink,
                ) != (
                    opened.st_dev, opened.st_ino, opened.st_mode,
                    opened.st_uid, opened.st_nlink,
                ):
                    os.close(child)
                    raise BeadsProtectedRuntimeError(
                        f"{label} child identity changed between no-follow stat and open"
                    )
                entries.append({**common, "kind": "directory"})
                try:
                    walk(child, relative, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                entries.append({**common, "kind": "regular", "bytesSha256": _hash_regular_at(descriptor, name, metadata, label)})
            else:
                raise BeadsProtectedRuntimeError(f"{label} contains a special file")

    try:
        root_metadata = os.fstat(root)
        walk(root, "", 0)
    finally:
        os.close(root)
    projection = {
        "pathSha256": sha256(os.fsencode(str(path))),
        "rootIdentity": _directory_identity(root_metadata),
        "ancestrySha256": sha256(canonical_bytes(ancestry)),
        "entries": entries,
    }
    return {**projection, "treeSha256": sha256(canonical_bytes(projection))}


def _rename_directory_noreplace(
    source_parent: int,
    source_leaf: str,
    target_parent: int,
    target_leaf: str,
) -> None:
    """Atomically move one directory while refusing an existing target.

    Linux uses renameat2(RENAME_NOREPLACE), Darwin uses
    renameatx_np(RENAME_EXCL).  Other hosts fail closed because the portable
    POSIX rename primitive is allowed to clobber the destination.
    """

    try:
        source_before = os.stat(source_leaf, dir_fd=source_parent, follow_symlinks=False)
    except OSError as exc:
        raise BeadsProtectedRuntimeError(f"cannot inspect no-clobber install source: {exc}") from exc
    if not stat.S_ISDIR(source_before.st_mode):
        raise BeadsProtectedRuntimeError("no-clobber install source must be a directory")
    source_name = os.fsencode(source_leaf)
    target_name = os.fsencode(target_leaf)
    libc = ctypes.CDLL(None, use_errno=True)
    result: int
    if hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(source_parent, source_name, target_parent, target_name, 1)
    elif hasattr(libc, "renameatx_np"):
        function = libc.renameatx_np
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(source_parent, source_name, target_parent, target_name, 0x00000004)
    else:
        raise BeadsProtectedRuntimeError(
            "host lacks an atomic no-clobber directory rename; use Linux renameat2 or Darwin renameatx_np"
        )
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise BeadsProtectedRuntimeError("create install target appeared before atomic no-clobber install")
        raise BeadsProtectedRuntimeError(f"atomic no-clobber directory install failed: {os.strerror(error)}")
    try:
        target_descriptor = os.open(
            target_leaf,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=target_parent,
        )
        try:
            target_after = os.fstat(target_descriptor)
        finally:
            os.close(target_descriptor)
    except OSError as exc:
        raise BeadsProtectedRuntimeError(f"cannot reopen installed directory after atomic move: {exc}") from exc
    if (source_before.st_dev, source_before.st_ino) != (target_after.st_dev, target_after.st_ino):
        raise BeadsProtectedRuntimeError("atomic no-clobber install changed the source directory identity")


def _capture_directory(path: Path, label: str) -> dict[str, Any]:
    descriptor, ancestry = _open_absolute_directory(path, label, private=True)
    try:
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    return {
        "pathSha256": sha256(os.fsencode(str(path))),
        **_directory_identity(metadata),
        "ancestrySha256": sha256(canonical_bytes(ancestry)),
    }


def verify_beads_installed_database_selector_v1(
    repository_locator_sha256: str,
    source_authority_locator: BeadsAuthorityLocatorV1,
    source_preparation_pointer_record_sha256: str,
) -> VerifiedBeadsInstalledDatabaseSelectorV1:
    repository_digest = _digest(repository_locator_sha256, "repositoryLocatorSha256")
    pointer_digest = _digest(source_preparation_pointer_record_sha256, "sourcePreparationPointerRecordSha256")
    assert repository_digest is not None and pointer_digest is not None
    locator = _plain(source_authority_locator.payload)
    _required(
        locator,
        "repositoryPath",
        "databaseName",
        "verifiedReceiptRecordSha256",
        "repositoryLocatorSha256",
        "authorityStateRecordSha256",
        "authorityStateFullBytesSha256",
        "predecessorCurrentFullBytesSha256",
    )
    if set(locator) != {
        "repositoryLocatorSha256", "authorityStateRecordSha256", "authorityStateFullBytesSha256",
        "predecessorCurrentFullBytesSha256", "verifiedReceiptRecordSha256", "repositoryPath", "databaseName",
    }:
        raise BeadsProtectedRuntimeError("authority locator contains an unknown or missing field")
    if locator.get("repositoryLocatorSha256") != repository_digest:
        raise BeadsProtectedRuntimeError("installed selector authority locator repository mismatch")
    if source_authority_locator.record_sha256 is None or source_authority_locator.full_bytes_sha256 is None:
        raise BeadsProtectedRuntimeError("installed selector requires a digest-bound authority locator")
    store = _store_for_repository(repository_digest)
    receipt = _load_record(
        store,
        "BeadsAuthorityTransitionReceiptV1",
        "beads-authority-transition-receipt",
        "authority-transition-receipts",
        locator["verifiedReceiptRecordSha256"],
    )
    verified_receipt = VerifiedBeadsAuthorityTransitionReceiptV1(
        payload=receipt.payload,
        auth=receipt.auth,
        record_sha256=receipt.record_sha256,
        full_bytes_sha256=receipt.full_bytes_sha256,
    )
    expected_locator = project_beads_authority_predecessor_locator_v1(verified_receipt)
    if (
        canonical_bytes(expected_locator.payload) != canonical_bytes(locator)
        or expected_locator.record_sha256 != source_authority_locator.record_sha256
        or expected_locator.full_bytes_sha256 != source_authority_locator.full_bytes_sha256
    ):
        raise BeadsProtectedRuntimeError("authority locator is not the exact authenticated receipt projection")
    candidate = receipt.payload.get("candidate")
    if not isinstance(candidate, Mapping) or candidate.get("preparationPointerRecordSha256") != pointer_digest:
        raise BeadsProtectedRuntimeError("installed selector source pointer does not match the authenticated authority candidate")
    repository = Path(str(locator["repositoryPath"]))
    database_name = _identifier(locator["databaseName"], "databaseName")
    selector = repository / ".beads" / "embeddeddolt"
    selected = selector / database_name
    dolt_root = selected / ".dolt"
    selector_observation = _capture_directory(selector, "installed selector")
    selected_observation = _capture_directory(selected, "selected store")
    dolt_observation = _capture_directory(dolt_root, "selected Dolt root")
    binding_payload = {
        "repositoryLocatorSha256": repository_digest,
        "sourcePreparationPointerRecordSha256": pointer_digest,
        "selectorPath": str(selector),
        "selectedStorePath": str(selected),
        "doltRootPath": str(dolt_root),
        "databaseName": database_name,
        "selectorObservation": selector_observation,
        "selectedStoreObservation": selected_observation,
        "doltRootObservation": dolt_observation,
    }
    return VerifiedBeadsInstalledDatabaseSelectorV1(
        payload=binding_payload,
        record_sha256=sha256(canonical_bytes(binding_payload)),
        full_bytes_sha256=sha256(canonical_bytes(binding_payload)),
    )


def authorize_beads_preparation_v1(request: AuthorizeBeadsPreparationRequestV1) -> BeadsPreparationAuthorizationV1:
    payload = _request(request, "AuthorizeBeadsPreparationRequestV1")
    _required(
        payload,
        "planSha256", "executableSha256", "operatorIdentitySha256", "authorizationNonce",
        "expiresAtUnix", "runtimeApiManifestRecordSha256", "adapterReleaseManifestRecordSha256",
        "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256",
    )
    fields = _preparation_sequence_fields(payload)
    for field in (
        "planSha256", "executableSha256", "operatorIdentitySha256",
        "runtimeApiManifestRecordSha256", "adapterReleaseManifestRecordSha256",
        "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256",
    ):
        _digest(payload[field], field)
    _identifier(payload["authorizationNonce"], "authorizationNonce")
    _expiry(payload)
    store = _Store(payload)
    executable_path = Path(str(payload.get("executablePath", "")))
    executable_observation = _observe_executable(executable_path, str(payload["executableSha256"]))
    if payload["preparationMode"] == "create":
        _required(
            payload,
            "createStageDatabasePath", "executablePath", "repositoryPath", "databaseName",
            "installPath", "cleanupPath", "statusConfigValue",
        )
        repository_path = Path(str(payload["repositoryPath"]))
        _capture_directory(repository_path, "Beads repository")
        database_name = _identifier(payload["databaseName"], "databaseName")
        if not isinstance(payload["statusConfigValue"], str) or not payload["statusConfigValue"] or len(payload["statusConfigValue"].encode("utf-8")) > 65536:
            raise BeadsProtectedRuntimeError("statusConfigValue must be a bounded non-empty literal")
        stage_path = Path(str(payload["createStageDatabasePath"]))
        install_path = Path(str(payload["installPath"]))
        cleanup_path = Path(str(payload["cleanupPath"]))
        expected_install_path = repository_path / ".beads" / "embeddeddolt" / database_name
        if install_path != expected_install_path:
            raise BeadsProtectedRuntimeError("create install path is not the exact repository selector/database target")
        if stage_path.parent != cleanup_path or stage_path.name != database_name:
            raise BeadsProtectedRuntimeError("create stage path must be the database child of its cleanup scaffold")
        stage_observation = _observe_path_locator(stage_path, "create stage database path")
        install_observation = _observe_path_locator(install_path, "create install path")
        cleanup_observation = _observe_path_locator(cleanup_path, "create cleanup path")
        cleanup_tree_observation = _observe_directory_tree(cleanup_path, "create cleanup scaffold")
        cleanup_entries = cleanup_tree_observation.get("entries")
        if (
            stage_observation.get("present") is not False
            or install_observation.get("present") is not False
            or cleanup_observation.get("present") is not True
            or not isinstance(cleanup_entries, list)
            or len(cleanup_entries) != 1
            or cleanup_entries[0].get("relativePathSha256") != sha256(os.fsencode(".gitignore"))
            or cleanup_entries[0].get("kind") != "regular"
        ):
            raise BeadsProtectedRuntimeError("create requires absent stage/install and an exact private .gitignore cleanup scaffold")
        derived_stage_locator = sha256(canonical_bytes(stage_observation))
        if derived_stage_locator != payload["createStageDatabasePathLocatorSha256"]:
            raise BeadsProtectedRuntimeError("create stage locator differs from direct no-follow observation")
        path_bindings = {
            "repositoryPath": str(repository_path),
            "databaseName": database_name,
            "createStageDatabasePath": str(stage_path),
            "installPath": str(install_path),
            "cleanupPath": str(cleanup_path),
            "statusConfigValue": payload["statusConfigValue"],
            "createStageObservationA": stage_observation,
            "installObservationA": install_observation,
            "cleanupObservationA": cleanup_observation,
            "cleanupTreeObservationA": cleanup_tree_observation,
            "executablePath": str(executable_path),
            "executableObservation": executable_observation,
        }
    else:
        _required(
            payload,
            "sourceAuthorityTransitionReceiptRecordSha256", "sourcePreparationPointerRecordSha256",
            "installedSelectorPath", "selectedStorePath", "doltRootPath", "executablePath",
        )
        source_receipt = _load_record(
            store,
            "BeadsAuthorityTransitionReceiptV1",
            "beads-authority-transition-receipt",
            "authority-transition-receipts",
            payload["sourceAuthorityTransitionReceiptRecordSha256"],
        )
        verified_receipt = VerifiedBeadsAuthorityTransitionReceiptV1(
            payload=source_receipt.payload,
            auth=source_receipt.auth,
            record_sha256=source_receipt.record_sha256,
            full_bytes_sha256=source_receipt.full_bytes_sha256,
        )
        source_locator = project_beads_authority_predecessor_locator_v1(verified_receipt)
        with use_beads_protected_runtime_v1(str(payload["protectedRoot"]), str(payload["hmacKeyPath"])):
            verified_selector = verify_beads_installed_database_selector_v1(
                str(payload["repositoryLocatorSha256"]),
                source_locator,
                str(payload["sourcePreparationPointerRecordSha256"]),
            )
        expected_paths = {
            "installedSelectorPath": verified_selector.payload["selectorPath"],
            "selectedStorePath": verified_selector.payload["selectedStorePath"],
            "doltRootPath": verified_selector.payload["doltRootPath"],
        }
        if any(str(payload[name]) != value for name, value in expected_paths.items()):
            raise BeadsProtectedRuntimeError("reattest path literals differ from the authenticated selector projection")
        selector_a = sha256(canonical_bytes(verified_selector.payload["selectorObservation"]))
        selected_a = sha256(canonical_bytes(verified_selector.payload["selectedStoreObservation"]))
        binding_sha = sha256(canonical_bytes(verified_selector.payload))
        if (
            payload["installedDatabaseSelectorBindingSha256"] != binding_sha
            or payload["selectorObservationASha256"] != selector_a
            or payload["selectedStoreObservationASha256"] != selected_a
        ):
            raise BeadsProtectedRuntimeError("reattest selector/store A digests differ from direct observation")
        path_bindings = {
            **expected_paths,
            "sourceAuthorityTransitionReceiptRecordSha256": source_receipt.record_sha256,
            "sourcePreparationPointerRecordSha256": payload["sourcePreparationPointerRecordSha256"],
            "verifiedInstalledSelector": _plain(verified_selector.payload),
            "executablePath": str(executable_path),
            "executableObservation": executable_observation,
        }
    with store.locked():
        pinned_executable_path, pinned_executable_observation = _install_pinned_executable(
            store, executable_path, executable_observation
        )
        path_bindings.update(
            {
                "pinnedExecutablePath": str(pinned_executable_path),
                "pinnedExecutableObservation": pinned_executable_observation,
            }
        )
        runtime_manifest = _load_record(
            store,
            "BeadsProtectedRuntimeApiManifestV1",
            "beads-protected-runtime-api-manifest",
            "runtime-api-manifests",
            payload["runtimeApiManifestRecordSha256"],
        )
        release_manifest = _load_record(
            store,
            "BeadsAdapterReleaseManifestV1",
            "beads-adapter-release-manifest",
            "adapter-release-manifests",
            payload["adapterReleaseManifestRecordSha256"],
        )
        current_runtime = _load_current(store, "BeadsProtectedRuntimeApiManifestV1", "beads-protected-runtime-api-manifest", "runtime-api-manifests")
        current_release = _load_current(store, "BeadsAdapterReleaseManifestV1", "beads-adapter-release-manifest", "adapter-release-manifests")
        if current_runtime.record_sha256 != runtime_manifest.record_sha256 or current_release.record_sha256 != release_manifest.record_sha256:
            raise BeadsStaleAuthorityError("preparation requires current runtime and adapter release manifests")
        if runtime_manifest.record_sha256 != release_manifest.payload.get("runtimeApiManifestRecordSha256"):
            raise BeadsProtectedRuntimeError("preparation runtime/release manifest join mismatch")
        authority = _current_authority(store, require_active=False)
        if authority.payload.get("authorityState") != "revoked":
            raise BeadsProtectedRuntimeError("preparation authorization requires revoked authority")
        authorization_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "planSha256": payload["planSha256"],
            "executableSha256": payload["executableSha256"],
            "operatorIdentitySha256": payload["operatorIdentitySha256"],
            "authorizationNonce": payload["authorizationNonce"],
            "expiresAtUnix": payload["expiresAtUnix"],
            "runtimeApiManifestRecordSha256": runtime_manifest.record_sha256,
            "adapterReleaseManifestRecordSha256": release_manifest.record_sha256,
            "bootstrapRuntimeCoreSha256": payload["bootstrapRuntimeCoreSha256"],
            "adapterReleaseCoreSha256": payload["adapterReleaseCoreSha256"],
            "revokedAuthorityRecordSha256": authority.record_sha256,
            **path_bindings,
            **fields,
        }
        return _signed_record(store, "BeadsPreparationAuthorizationV1", "beads-preparation-authorization", authorization_payload, "preparation-authorizations")


def begin_beads_preparation_v1(request: BeginBeadsPreparationRequestV1) -> BeadsPreparationLeaseV1:
    payload = _request(request, "BeginBeadsPreparationRequestV1")
    _required(payload, "authorizationRecordSha256", "leaseNonce", "expiresAtUnix")
    _identifier(payload["leaseNonce"], "leaseNonce")
    _expiry(payload)
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "begin-beads-preparation", payload)
        resumed = _resume_transaction_result(
            store, directory, "begin-beads-preparation", "BeadsPreparationLeaseV1",
            "beads-preparation-lease", "preparation-leases",
        )
        if resumed is not None:
            return resumed
        authorization = _load_record(
            store,
            "BeadsPreparationAuthorizationV1",
            "beads-preparation-authorization",
            "preparation-authorizations",
            payload["authorizationRecordSha256"],
        )
        _expiry(authorization.payload)
        _same_repository(store, authorization.payload)
        _require_current_authority_record(
            store, authorization.payload.get("revokedAuthorityRecordSha256"), "revoked"
        )
        _revalidate_preparation_physical(authorization)
        _consume_capability(store, "preparation-authorizations", authorization, intent_digest)
        lease_payload = {
            **{key: value for key, value in authorization.payload.items() if key not in {"kind", "schemaVersion", "authorizationNonce"}},
            "authorizationRecordSha256": authorization.record_sha256,
            "leaseNonce": payload["leaseNonce"],
            "expiresAtUnix": min(payload["expiresAtUnix"], authorization.payload["expiresAtUnix"]),
            "transactionIntentSha256": intent_digest,
            "nextCommandOrdinal": 0,
            "preparationState": "leased",
        }
        result = _signed_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", lease_payload, "preparation-leases")
        _transaction_receipt(store, directory, "begin-beads-preparation", result)
        return result


def _revalidate_preparation_physical(record: _WireRecord) -> None:
    executable_path = Path(str(record.payload.get("executablePath", "")))
    executable_digest = record.payload.get("executableSha256")
    observation = _observe_executable(executable_path, str(executable_digest))
    if canonical_bytes(observation) != canonical_bytes(record.payload.get("executableObservation")):
        raise BeadsProtectedRuntimeError("protected Beads executable identity changed after authorization")
    pinned_observation = _observe_executable(
        Path(str(record.payload.get("pinnedExecutablePath", ""))),
        str(executable_digest),
    )
    if canonical_bytes(pinned_observation) != canonical_bytes(
        record.payload.get("pinnedExecutableObservation")
    ):
        raise BeadsProtectedRuntimeError("immutable broker executable identity changed after authorization")
    if record.payload.get("preparationMode") == "create":
        checks = (
            ("createStageDatabasePath", "createStageObservationA", "create stage database path"),
            ("installPath", "installObservationA", "create install path"),
            ("cleanupPath", "cleanupObservationA", "create cleanup path"),
        )
        for path_field, observation_field, label in checks:
            current = _observe_path_locator(Path(str(record.payload.get(path_field, ""))), label)
            expected_field = (
                "createStageObservationCurrent"
                if path_field == "createStageDatabasePath" and record.payload.get("createStageObservationCurrent") is not None
                else observation_field
            )
            expected = record.payload.get(expected_field)
            stage_may_be_new = (
                path_field == "createStageDatabasePath"
                and isinstance(record.payload.get("nextCommandOrdinal"), int)
                and record.payload.get("nextCommandOrdinal") >= 2
                and isinstance(expected, Mapping)
                and expected.get("present") is False
                and current.get("present") is True
            )
            cleanup_child_added = (
                path_field == "cleanupPath"
                and isinstance(record.payload.get("nextCommandOrdinal"), int)
                and record.payload.get("nextCommandOrdinal") >= 2
                and isinstance(expected, Mapping)
                and isinstance(current, Mapping)
                and {
                    key: value for key, value in _plain(expected).items()
                    if key != "identity"
                } == {
                    key: value for key, value in _plain(current).items()
                    if key != "identity"
                }
                and {
                    key: value for key, value in _plain(expected.get("identity", {})).items()
                    if key != "linkCount"
                } == {
                    key: value for key, value in _plain(current.get("identity", {})).items()
                    if key != "linkCount"
                }
            )
            if not stage_may_be_new and not cleanup_child_added and canonical_bytes(current) != canonical_bytes(expected):
                raise BeadsProtectedRuntimeError(f"{label} identity changed after authorization")
    else:
        verified = record.payload.get("verifiedInstalledSelector")
        if not isinstance(verified, Mapping):
            raise BeadsProtectedRuntimeError("reattest authorization lacks verified selector evidence")
        observations = {
            "selectorObservation": _capture_directory(Path(str(record.payload.get("installedSelectorPath"))), "installed selector"),
            "selectedStoreObservation": _capture_directory(Path(str(record.payload.get("selectedStorePath"))), "selected store"),
            "doltRootObservation": _capture_directory(Path(str(record.payload.get("doltRootPath"))), "selected Dolt root"),
        }
        for field, current in observations.items():
            if canonical_bytes(current) != canonical_bytes(verified.get(field)):
                raise BeadsProtectedRuntimeError(f"reattest {field} changed after authorization")


def _expected_preparation_command(lease: _WireRecord, command_kind: str, argv: Sequence[Any]) -> tuple[str, ...]:
    mode = lease.payload.get("preparationMode")
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)) or not all(isinstance(item, str) for item in argv):
        raise BeadsProtectedRuntimeError("preparation argv must be an ordered string array")
    if len(argv) > 16 or any(not item or len(item.encode("utf-8")) > 4096 for item in argv):
        raise BeadsProtectedRuntimeError("preparation argv is empty or oversized")
    if mode == "reattest":
        if command_kind != "status-config-readback":
            raise BeadsProtectedRuntimeError("reattest permits only status-config-readback")
        selector = lease.payload.get("installedSelectorPath")
        if not isinstance(selector, str):
            raise BeadsProtectedRuntimeError("reattest lease has no separately verified installed selector path")
        binary = lease.payload.get("executablePath")
        if not isinstance(binary, str):
            raise BeadsProtectedRuntimeError("preparation lease has no protected executable path")
        expected = [binary, "--db", selector, "--json", "--sandbox", "config", "list"]
        if list(argv) != expected:
            raise BeadsProtectedRuntimeError("reattest argv is not the exact registered selector-root literal")
        return tuple(expected)
    else:
        allowed = ("binary-proof", "initialize", "status-config-write", "status-config-readback")
        ordinal = lease.payload.get("nextCommandOrdinal")
        if not isinstance(ordinal, int) or ordinal >= len(allowed) or command_kind != allowed[ordinal]:
            raise BeadsProtectedRuntimeError("create preparation command is absent, repeated or out of order")
        stage_path = lease.payload.get("createStageDatabasePath")
        binary = lease.payload.get("executablePath")
        config_value = lease.payload.get("statusConfigValue")
        if not all(isinstance(value, str) and value for value in (stage_path, binary, config_value)):
            raise BeadsProtectedRuntimeError("create preparation lease lacks exact binary/stage/config literals")
        exact_by_kind = {
            "binary-proof": [binary, "version", "--json"],
            "initialize": [binary, "--db", stage_path, "--json", "--sandbox", "init"],
            "status-config-write": [
                binary, "--db", stage_path, "--json", "--sandbox",
                "config", "set", "status.custom", config_value,
            ],
            "status-config-readback": [
                binary, "--db", stage_path, "--json", "--sandbox", "config", "list",
            ],
        }
        expected = exact_by_kind[command_kind]
        if list(argv) != expected:
            raise BeadsProtectedRuntimeError("create preparation argv is not the exact registered literal")
        return tuple(expected)


def _frozen_preparation_environment(store: _Store, lease: _WireRecord, intent_digest: str) -> dict[str, str]:
    home = store.directory("command-homes", intent_digest.removeprefix("sha256:"))
    repository = str(lease.payload.get("repositoryPath"))
    if not Path(repository).is_absolute():
        raise BeadsProtectedRuntimeError("preparation lease repository path is not absolute")
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "BEADS_DIR": str(Path(repository) / ".beads"),
        "BEADS_DOLT_AUTO_START": "0",
        "BEADS_DISABLE_HOOKS": "1",
        "BEADS_DISABLE_METRICS": "1",
        "BEADS_DISABLE_EVENTS": "1",
        "BD_JSON_ENVELOPE": "1",
    }


def advance_beads_preparation_v1(request: AdvanceBeadsPreparationRequestV1) -> BeadsPreparationStepV1:
    payload = _request(request, "AdvanceBeadsPreparationRequestV1")
    _required(payload, "leaseRecordSha256", "commandOrdinal", "commandKind", "argv")
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "advance-beads-preparation", payload)
        resumed = _resume_transaction_result(
            store, directory, "advance-beads-preparation", "BeadsPreparationStepV1",
            "beads-preparation-step", "preparation-steps",
        )
        if resumed is not None:
            return resumed
        lease = _load_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", payload["leaseRecordSha256"])
        _expiry(lease.payload)
        _same_repository(store, lease.payload)
        _require_current_authority_record(
            store, lease.payload.get("revokedAuthorityRecordSha256"), "revoked"
        )
        if payload["commandOrdinal"] != lease.payload.get("nextCommandOrdinal"):
            raise BeadsStaleAuthorityError("preparation command ordinal is stale or non-contiguous")
        exact_argv = _expected_preparation_command(lease, str(payload["commandKind"]), payload["argv"])
        _revalidate_preparation_physical(lease)
        command_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "leaseRecordSha256": lease.record_sha256,
            "commandOrdinal": payload["commandOrdinal"],
            "commandKind": payload["commandKind"],
            "argv": list(exact_argv),
            "argvSha256": sha256(canonical_bytes(list(exact_argv))),
            "transactionIntentSha256": intent_digest,
            **_preparation_sequence_fields(lease.payload),
        }
        if _capability_consumed_by(store, "preparation-lease-successors", lease, intent_digest):
            command = _load_record(
                store, "BeadsPreparationCommandIntentV1", "beads-preparation-command-intent",
                "preparation-commands", sha256(canonical_bytes({"kind": "beads-preparation-command-intent", "schemaVersion": 1, **command_payload})),
            )
            uncertain = _signed_record(
                store,
                "BeadsPreparationStepV1",
                "beads-preparation-step",
                {
                    **command_payload,
                    "commandIntentRecordSha256": command.record_sha256,
                    "outcome": "outcome-uncertain",
                    "exitCode": None,
                    "stdoutSha256": None,
                    "stderrSha256": None,
                    "successorLeaseRecordSha256": None,
                },
                "preparation-steps",
            )
            _transaction_receipt(store, directory, "advance-beads-preparation", uncertain)
            return uncertain
        command = _signed_record(store, "BeadsPreparationCommandIntentV1", "beads-preparation-command-intent", command_payload, "preparation-commands")
        _consume_capability(store, "preparation-lease-successors", lease, intent_digest)
        mutation_intent = _signed_record(
            store,
            "BeadsMutationIntentV1",
            "beads-mutation-intent",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "mutationClass": "preparation",
                "mutationNonce": intent_digest.removeprefix("sha256:"),
                "argv": list(exact_argv),
                "argvSha256": sha256(canonical_bytes(list(exact_argv))),
                "expiresAtUnix": lease.payload["expiresAtUnix"],
                "preparationLeaseRecordSha256": lease.record_sha256,
                "preparationCommandIntentRecordSha256": command.record_sha256,
                "transactionIntentSha256": intent_digest,
                **_preparation_sequence_fields(lease.payload),
            },
            "mutation-intents",
        )
        _fault("preparation-command-intent-written")
        _require_current_authority_record(
            store, lease.payload.get("revokedAuthorityRecordSha256"), "revoked"
        )
        environment = _frozen_preparation_environment(store, lease, intent_digest)
        try:
            completed = _spawn_verified_executable_v1(
                Path(str(lease.payload["pinnedExecutablePath"])),
                lease.payload["pinnedExecutableObservation"],
                list(exact_argv),
                cwd=Path(str(lease.payload["repositoryPath"])),
                env=environment,
                logical_path=Path(str(lease.payload["executablePath"])),
            )
            stdout = completed.stdout
            stderr = completed.stderr
            if len(stdout) > MAX_CANONICAL_BYTES or len(stderr) > MAX_CANONICAL_BYTES:
                raise BeadsProtectedRuntimeError("preparation command output exceeds 1048576 bytes")
            exit_code: int | None = completed.returncode
            outcome = "succeeded" if completed.returncode == 0 else "failed"
            stdout_digest = sha256(stdout)
            stderr_digest = sha256(stderr)
        except subprocess.TimeoutExpired as exc:
            stdout = bytes(exc.stdout or b"")[:MAX_CANONICAL_BYTES]
            stderr = bytes(exc.stderr or b"")[:MAX_CANONICAL_BYTES]
            exit_code = None
            outcome = "outcome-uncertain"
            stdout_digest = sha256(stdout)
            stderr_digest = sha256(stderr)
        mutation_result = _signed_record(
            store,
            "BeadsMutationResultV1",
            "beads-mutation-result",
            {
                **{key: value for key, value in mutation_intent.payload.items() if key not in {"kind", "schemaVersion"}},
                "mutationIntentRecordSha256": mutation_intent.record_sha256,
                "exitCode": exit_code,
                "stdoutSha256": stdout_digest,
                "stderrSha256": stderr_digest,
                "readBackSha256": stdout_digest if payload["commandKind"] == "status-config-readback" else None,
                "observedByBroker": True,
            },
            "mutation-results",
        )
        base_step_payload = {
            **command_payload,
            "commandIntentRecordSha256": command.record_sha256,
            "mutationIntentRecordSha256": mutation_intent.record_sha256,
            "mutationResultRecordSha256": mutation_result.record_sha256,
            "outcome": outcome,
            "exitCode": exit_code,
            "stdoutSha256": stdout_digest,
            "stderrSha256": stderr_digest,
        }
        if outcome != "succeeded":
            result = _signed_record(store, "BeadsPreparationStepV1", "beads-preparation-step", {**base_step_payload, "successorLeaseRecordSha256": None}, "preparation-steps")
            _transaction_receipt(store, directory, "advance-beads-preparation", result)
            return result
        successor_payload = {
            **{key: value for key, value in lease.payload.items() if key not in {"kind", "schemaVersion", "nextCommandOrdinal", "preparationState"}},
            "predecessorLeaseRecordSha256": lease.record_sha256,
            "lastCommandIntentRecordSha256": command.record_sha256,
            "nextCommandOrdinal": payload["commandOrdinal"] + 1,
            "preparationState": "commands-complete" if (
                lease.payload.get("preparationMode") == "reattest" or payload["commandOrdinal"] == 3
            ) else "leased",
        }
        if lease.payload.get("preparationMode") == "create" and payload["commandOrdinal"] >= 1:
            successor_payload["createStageObservationCurrent"] = _observe_path_locator(
                Path(str(lease.payload["createStageDatabasePath"])),
                "create stage database path",
                require_directory=True,
            )
        successor = _signed_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", successor_payload, "preparation-leases")
        result = _signed_record(
            store,
            "BeadsPreparationStepV1",
            "beads-preparation-step",
            {**base_step_payload, "successorLeaseRecordSha256": successor.record_sha256},
            "preparation-steps",
        )
        _transaction_receipt(store, directory, "advance-beads-preparation", result)
        return result


def observe_beads_store_v1(request: ObserveBeadsStoreRequestV1) -> BeadsStoreObservationV1:
    payload = _request(request, "ObserveBeadsStoreRequestV1")
    _required(payload, "leaseRecordSha256", "observationPhase")
    if payload["observationPhase"] not in {"pre", "post"}:
        raise BeadsProtectedRuntimeError("store observation phase is invalid")
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "observe-beads-store", payload)
        resumed = _resume_transaction_result(
            store, directory, "observe-beads-store", "BeadsStoreObservationV1",
            "beads-store-observation", "store-observations",
        )
        if resumed is not None:
            return resumed
        lease = _load_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", payload["leaseRecordSha256"])
        _expiry(lease.payload)
        _same_repository(store, lease.payload)
        _require_current_authority_record(
            store, lease.payload.get("revokedAuthorityRecordSha256"), "revoked"
        )
        _revalidate_preparation_physical(lease)
        phase = payload["observationPhase"]
        if lease.payload.get("preparationMode") == "create":
            expected_ordinal = 3 if phase == "pre" else 4
            if lease.payload.get("nextCommandOrdinal") != expected_ordinal:
                raise BeadsStaleAuthorityError("create observation is outside the config-readback boundary")
            primary = _observe_directory_tree(Path(str(lease.payload["createStageDatabasePath"])), "create stage database")
        else:
            expected_ordinal = 0 if phase == "pre" else 1
            if lease.payload.get("nextCommandOrdinal") != expected_ordinal:
                raise BeadsStaleAuthorityError("reattest observation is outside the config-readback boundary")
            primary = _observe_directory_tree(Path(str(lease.payload["installedSelectorPath"])), "installed selector tree")
        state = {
            "primaryStore": primary,
            "executableObservation": _observe_executable(
                Path(str(lease.payload["executablePath"])),
                str(lease.payload["executableSha256"]),
            ),
            "installObservation": (
                _observe_path_locator(Path(str(lease.payload["installPath"])), "create install path")
                if lease.payload.get("preparationMode") == "create" else None
            ),
            "cleanupObservation": (
                _observe_path_locator(Path(str(lease.payload["cleanupPath"])), "create cleanup path")
                if lease.payload.get("preparationMode") == "create" else None
            ),
            "selectedStoreObservation": (
                _capture_directory(Path(str(lease.payload["selectedStorePath"])), "selected store")
                if lease.payload.get("preparationMode") == "reattest" else None
            ),
            "doltRootObservation": (
                _capture_directory(Path(str(lease.payload["doltRootPath"])), "selected Dolt root")
                if lease.payload.get("preparationMode") == "reattest" else None
            ),
        }
        state_digest = sha256(canonical_bytes({"kind": "beads-store-state-projection", "schemaVersion": 1, **state}))
        observation_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "leaseRecordSha256": lease.record_sha256,
            "observationPhase": payload["observationPhase"],
            "stateProjection": state,
            "storeStateSha256": state_digest,
            "acceptedConfigEnvelopeSha256": payload.get("acceptedConfigEnvelopeSha256"),
            "predecessorObservationRecordSha256": payload.get("predecessorObservationRecordSha256"),
            "configReadbackStepRecordSha256": payload.get("configReadbackStepRecordSha256"),
            "transactionIntentSha256": intent_digest,
            **_preparation_sequence_fields(lease.payload),
        }
        if phase == "pre":
            if any(observation_payload[field] is not None for field in (
                "acceptedConfigEnvelopeSha256", "predecessorObservationRecordSha256",
                "configReadbackStepRecordSha256",
            )):
                raise BeadsProtectedRuntimeError("pre observation forbids config output, step and predecessor")
        else:
            _digest(observation_payload["acceptedConfigEnvelopeSha256"], "acceptedConfigEnvelopeSha256")
            predecessor = _load_record(store, "BeadsStoreObservationV1", "beads-store-observation", "store-observations", observation_payload["predecessorObservationRecordSha256"])
            if predecessor.payload.get("observationPhase") != "pre" or predecessor.payload.get("storeStateSha256") != state_digest:
                raise BeadsProtectedRuntimeError("post observation physical state differs from pre observation")
            step = _load_record(
                store,
                "BeadsPreparationStepV1",
                "beads-preparation-step",
                "preparation-steps",
                observation_payload["configReadbackStepRecordSha256"],
            )
            if (
                step.payload.get("commandKind") != "status-config-readback"
                or step.payload.get("outcome") != "succeeded"
                or step.payload.get("stdoutSha256") != observation_payload["acceptedConfigEnvelopeSha256"]
                or predecessor.payload.get("leaseRecordSha256") != step.payload.get("leaseRecordSha256")
                or step.payload.get("successorLeaseRecordSha256") != lease.record_sha256
            ):
                raise BeadsProtectedRuntimeError("post observation does not join the broker-observed config read-back")
        _consume_capability(store, f"beads-store-{phase}-observation-successors", lease, intent_digest)
        result = _signed_record(store, "BeadsStoreObservationV1", "beads-store-observation", observation_payload, "store-observations")
        _transaction_receipt(store, directory, "observe-beads-store", result)
        return result


def derive_beads_status_profile_dynamic_bindings_v1(
    lease: BeadsPreparationLeaseV1,
    pre: BeadsStoreObservationV1,
    post: BeadsStoreObservationV1,
    accepted_config_envelope_canonical_sha256: str,
) -> VerifiedBeadsStatusProfileDynamicBindingsV1:
    config_digest = _digest(accepted_config_envelope_canonical_sha256, "acceptedConfigEnvelopeCanonicalSha256")
    assert config_digest is not None
    if lease.auth is None or pre.auth is None or post.auth is None:
        raise BeadsProtectedRuntimeError("dynamic bindings require broker-authenticated lease and observations")
    repository_digest = lease.payload.get("repositoryLocatorSha256")
    if not isinstance(repository_digest, str):
        raise BeadsProtectedRuntimeError("dynamic binding lease has no repository identity")
    store = _store_for_repository(repository_digest)
    protected_lease = _load_record(
        store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", str(lease.record_sha256)
    )
    protected_pre = _load_record(
        store, "BeadsStoreObservationV1", "beads-store-observation", "store-observations", str(pre.record_sha256)
    )
    protected_post = _load_record(
        store, "BeadsStoreObservationV1", "beads-store-observation", "store-observations", str(post.record_sha256)
    )
    if any(
        canonical_bytes(expected.to_dict()) != canonical_bytes(observed.to_dict())
        for expected, observed in ((lease, protected_lease), (pre, protected_pre), (post, protected_post))
    ):
        raise BeadsProtectedRuntimeError("dynamic bindings received a changed or non-protected wire projection")
    if post.payload.get("leaseRecordSha256") != lease.record_sha256:
        raise BeadsProtectedRuntimeError("dynamic binding post observation/final lease mismatch")
    if pre.payload.get("observationPhase") != "pre" or post.payload.get("observationPhase") != "post":
        raise BeadsProtectedRuntimeError("dynamic binding observations are out of order")
    if post.payload.get("predecessorObservationRecordSha256") != pre.record_sha256:
        raise BeadsProtectedRuntimeError("dynamic binding post observation does not name its exact predecessor")
    if pre.payload.get("storeStateSha256") != post.payload.get("storeStateSha256"):
        raise BeadsProtectedRuntimeError("dynamic binding physical store changed during config read-back")
    if post.payload.get("acceptedConfigEnvelopeSha256") != config_digest:
        raise BeadsProtectedRuntimeError("dynamic binding config envelope digest mismatch")
    result = {
        "schemaVersion": 1,
        "repositoryLocatorSha256": lease.payload.get("repositoryLocatorSha256"),
        "preparationLeaseRecordSha256": lease.record_sha256,
        "preObservationRecordSha256": pre.record_sha256,
        "postObservationRecordSha256": post.record_sha256,
        "storeStateSha256": pre.payload.get("storeStateSha256"),
        "acceptedConfigEnvelopeCanonicalSha256": config_digest,
        **_preparation_sequence_fields(lease.payload),
    }
    digest = sha256(canonical_bytes(result))
    return VerifiedBeadsStatusProfileDynamicBindingsV1(payload=result, record_sha256=digest, full_bytes_sha256=digest)


def _canonical_json_text(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise BeadsProtectedRuntimeError(f"{label} must be bounded canonical JSON text")
    raw = value.encode("utf-8")
    try:
        parsed = json.loads(raw, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BeadsProtectedRuntimeError(f"{label} contains malformed JSON") from exc
    if canonical_bytes(parsed) != raw:
        raise BeadsProtectedRuntimeError(f"{label} is not exact compact sorted-key JSON")
    return raw


def _install_and_cleanup_create(
    store: _Store,
    lease: _WireRecord,
    post: _WireRecord,
    transaction_intent_sha256: str,
) -> dict[str, str]:
    stage = Path(str(lease.payload["createStageDatabasePath"]))
    install = Path(str(lease.payload["installPath"]))
    cleanup = Path(str(lease.payload["cleanupPath"]))
    expected_stage_tree = post.payload.get("stateProjection", {}).get("primaryStore")
    if not isinstance(expected_stage_tree, Mapping):
        raise BeadsProtectedRuntimeError("create installation lacks the exact post-observation stage tree")
    install_intent = _signed_record(
        store,
        "BeadsPreparationStepV1",
        "beads-preparation-install-intent",
        {
            "repositoryLocatorSha256": store.repository_digest,
            "leaseRecordSha256": lease.record_sha256,
            "postObservationRecordSha256": post.record_sha256,
            "stagePathSha256": sha256(os.fsencode(str(stage))),
            "installPathSha256": sha256(os.fsencode(str(install))),
            "cleanupPathSha256": sha256(os.fsencode(str(cleanup))),
            "expectedStageTreeSha256": expected_stage_tree.get("treeSha256"),
            "transactionIntentSha256": transaction_intent_sha256,
            **_preparation_sequence_fields(lease.payload),
        },
        "preparation-install-intents",
    )
    stage_locator = _observe_path_locator(stage, "create stage database path")
    install_locator = _observe_path_locator(install, "create install path")
    if stage_locator.get("present") is True and install_locator.get("present") is False:
        current_stage_tree = _observe_directory_tree(stage, "create stage database before install")
        if canonical_bytes(current_stage_tree) != canonical_bytes(expected_stage_tree):
            raise BeadsProtectedRuntimeError("create stage tree changed after protected post observation")
        source_parent, source_leaf = _open_absolute_parent(stage, "create stage database")
        target_parent, target_leaf = _open_absolute_parent(install, "create install database")
        try:
            if canonical_bytes(_directory_identity(os.fstat(source_parent))) != canonical_bytes(
                stage_locator.get("parentIdentity")
            ):
                raise BeadsProtectedRuntimeError("create stage parent identity changed before install")
            if canonical_bytes(_directory_identity(os.fstat(target_parent))) != canonical_bytes(
                install_locator.get("parentIdentity")
            ):
                raise BeadsProtectedRuntimeError("create install parent identity changed before install")
            _rename_directory_noreplace(source_parent, source_leaf, target_parent, target_leaf)
            os.fsync(source_parent)
            os.fsync(target_parent)
        finally:
            os.close(source_parent)
            os.close(target_parent)
        _fault("preparation-install-renamed")
    elif not (stage_locator.get("present") is False and install_locator.get("present") is True):
        raise BeadsProtectedRuntimeError("create install recovery state is ambiguous")
    installed_tree = _observe_directory_tree(install, "installed Beads database")
    if (
        canonical_bytes(installed_tree.get("rootIdentity")) != canonical_bytes(expected_stage_tree.get("rootIdentity"))
        or canonical_bytes(installed_tree.get("entries")) != canonical_bytes(expected_stage_tree.get("entries"))
    ):
        raise BeadsProtectedRuntimeError("installed Beads tree differs from the protected stage observation")
    install_observed = _signed_record(
        store,
        "BeadsPreparationStepV1",
        "beads-preparation-install-observed",
        {
            "repositoryLocatorSha256": store.repository_digest,
            "leaseRecordSha256": lease.record_sha256,
            "installIntentRecordSha256": install_intent.record_sha256,
            "installedTree": installed_tree,
            "installedTreeSha256": installed_tree["treeSha256"],
            "transactionIntentSha256": transaction_intent_sha256,
            **_preparation_sequence_fields(lease.payload),
        },
        "preparation-install-observed",
    )
    cleanup_intent = _signed_record(
        store,
        "BeadsPreparationStepV1",
        "beads-preparation-cleanup-intent",
        {
            "repositoryLocatorSha256": store.repository_digest,
            "leaseRecordSha256": lease.record_sha256,
            "installObservedRecordSha256": install_observed.record_sha256,
            "cleanupTreeObservationA": lease.payload.get("cleanupTreeObservationA"),
            "transactionIntentSha256": transaction_intent_sha256,
            **_preparation_sequence_fields(lease.payload),
        },
        "preparation-cleanup-intents",
    )
    cleanup_locator = _observe_path_locator(cleanup, "create cleanup scaffold")
    if cleanup_locator.get("present") is True:
        descriptor, _ = _open_absolute_directory(cleanup, "create cleanup scaffold", private=True)
        try:
            entries = sorted(entry.name for entry in os.scandir(descriptor))
            if entries != [".gitignore"]:
                raise BeadsProtectedRuntimeError("cleanup scaffold contains an unbound entry after install")
            metadata = os.stat(".gitignore", dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise BeadsProtectedRuntimeError("cleanup .gitignore changed type")
            expected_entries = lease.payload.get("cleanupTreeObservationA", {}).get("entries", ())
            expected_entry = expected_entries[0] if len(expected_entries) == 1 else None
            observed_digest = _hash_regular_at(descriptor, ".gitignore", metadata, "cleanup .gitignore")
            if not isinstance(expected_entry, Mapping) or observed_digest != expected_entry.get("bytesSha256"):
                raise BeadsProtectedRuntimeError("cleanup .gitignore changed after authorization")
            os.unlink(".gitignore", dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        cleanup_parent, cleanup_leaf = _open_absolute_parent(cleanup, "create cleanup scaffold")
        try:
            os.rmdir(cleanup_leaf, dir_fd=cleanup_parent)
            os.fsync(cleanup_parent)
        finally:
            os.close(cleanup_parent)
        _fault("preparation-cleanup-removed")
    elif cleanup_locator.get("present") is not False:
        raise BeadsProtectedRuntimeError("cleanup scaffold recovery state is ambiguous")
    if _observe_path_locator(cleanup, "create cleanup scaffold").get("present") is not False:
        raise BeadsProtectedRuntimeError("cleanup scaffold remains after protected cleanup")
    cleanup_observed = _signed_record(
        store,
        "BeadsPreparationStepV1",
        "beads-preparation-cleanup-observed",
        {
            "repositoryLocatorSha256": store.repository_digest,
            "leaseRecordSha256": lease.record_sha256,
            "cleanupIntentRecordSha256": cleanup_intent.record_sha256,
            "installObservedRecordSha256": install_observed.record_sha256,
            "cleanupAbsentObservation": _observe_path_locator(cleanup, "create cleanup scaffold"),
            "transactionIntentSha256": transaction_intent_sha256,
            **_preparation_sequence_fields(lease.payload),
        },
        "preparation-cleanup-observed",
    )
    return {
        "installIntentRecordSha256": install_intent.record_sha256,
        "installObservedRecordSha256": install_observed.record_sha256,
        "cleanupIntentRecordSha256": cleanup_intent.record_sha256,
        "cleanupObservedRecordSha256": cleanup_observed.record_sha256,
    }


def finish_beads_preparation_v1(request: FinishBeadsPreparationRequestV1) -> FinishBeadsPreparationResultV1:
    payload = _request(request, "FinishBeadsPreparationRequestV1")
    _required(
        payload,
        "leaseRecordSha256", "preObservationRecordSha256", "postObservationRecordSha256",
        "dynamicBindingsCanonicalJson", "statusProfilePayloadCanonicalJson",
        "preparedStorePayloadCanonicalJson", "expectedCurrentPointerFullBytesSha256",
    )
    dynamic_bytes = _canonical_json_text(payload["dynamicBindingsCanonicalJson"], "dynamic bindings")
    status_bytes = _canonical_json_text(payload["statusProfilePayloadCanonicalJson"], "status profile payload")
    prepared_bytes = _canonical_json_text(payload["preparedStorePayloadCanonicalJson"], "prepared store payload")
    expected_current = _digest(payload["expectedCurrentPointerFullBytesSha256"], "expectedCurrentPointerFullBytesSha256", nullable=True)
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "finish-beads-preparation", payload)
        resumed_pointer = _resume_transaction_result(
            store,
            directory,
            "finish-beads-preparation",
            "BeadsPreparationCurrentV1",
            "beads-preparation-current",
            "preparation-current",
        )
        if resumed_pointer is None:
            resumed_pointer = _recover_current_transaction_result(
                store,
                directory,
                "finish-beads-preparation",
                "BeadsPreparationCurrentV1",
                "beads-preparation-current",
                "preparation-current",
                intent_digest,
            )
        if resumed_pointer is not None:
            return _finish_preparation_projection(store, resumed_pointer)
        lease = _load_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", payload["leaseRecordSha256"])
        if lease.payload.get("preparationState") != "commands-complete":
            raise BeadsProtectedRuntimeError("preparation cannot finish before its exact command sequence completes")
        authority = _current_authority(store, require_active=False)
        if (
            authority.payload.get("authorityState") != "revoked"
            or authority.record_sha256 != lease.payload.get("revokedAuthorityRecordSha256")
        ):
            raise BeadsStaleAuthorityError("preparation finish no longer binds the current revoked authority")
        runtime_manifest = _load_current(
            store,
            "BeadsProtectedRuntimeApiManifestV1",
            "beads-protected-runtime-api-manifest",
            "runtime-api-manifests",
        )
        release_manifest = _load_current(
            store,
            "BeadsAdapterReleaseManifestV1",
            "beads-adapter-release-manifest",
            "adapter-release-manifests",
        )
        if (
            runtime_manifest.record_sha256 != lease.payload.get("runtimeApiManifestRecordSha256")
            or release_manifest.record_sha256 != lease.payload.get("adapterReleaseManifestRecordSha256")
            or release_manifest.payload.get("runtimeApiManifestRecordSha256") != runtime_manifest.record_sha256
            or runtime_manifest.payload.get("bootstrapRuntimeCoreSha256") != lease.payload.get("bootstrapRuntimeCoreSha256")
            or release_manifest.payload.get("bootstrapRuntimeCoreSha256") != lease.payload.get("bootstrapRuntimeCoreSha256")
            or release_manifest.payload.get("adapterReleaseCoreSha256") != lease.payload.get("adapterReleaseCoreSha256")
        ):
            raise BeadsStaleAuthorityError("preparation finish runtime/release/core authority changed")
        core = _load_change_plan_core_by_digest(
            store, "bootstrapRuntimeCoreSha256", str(lease.payload.get("bootstrapRuntimeCoreSha256"))
        )
        if (
            core.record_sha256 != runtime_manifest.payload.get("changePlanCoreRecordSha256")
            or core.record_sha256 != release_manifest.payload.get("changePlanCoreRecordSha256")
            or core.payload.get("adapterReleaseCoreSha256") != lease.payload.get("adapterReleaseCoreSha256")
        ):
            raise BeadsProtectedRuntimeError("preparation finish cannot reproduce protected change-plan core joins")
        recovering_create_install = (
            lease.payload.get("preparationMode") == "create"
            and _observe_path_locator(
                Path(str(lease.payload.get("createStageDatabasePath"))), "create stage database path"
            ).get("present") is False
            and _observe_path_locator(
                Path(str(lease.payload.get("installPath"))), "create install path"
            ).get("present") is True
        )
        if recovering_create_install:
            _observe_executable(
                Path(str(lease.payload.get("executablePath"))),
                str(lease.payload.get("executableSha256")),
            )
        else:
            _revalidate_preparation_physical(lease)
        pre = _load_record(store, "BeadsStoreObservationV1", "beads-store-observation", "store-observations", payload["preObservationRecordSha256"])
        post = _load_record(store, "BeadsStoreObservationV1", "beads-store-observation", "store-observations", payload["postObservationRecordSha256"])
        with use_beads_protected_runtime_v1(str(payload["protectedRoot"]), str(payload["hmacKeyPath"])):
            dynamic = derive_beads_status_profile_dynamic_bindings_v1(
                lease,
                pre,
                post,
                str(post.payload.get("acceptedConfigEnvelopeSha256")),
            )
        if canonical_bytes(dynamic.payload) != dynamic_bytes:
            raise BeadsProtectedRuntimeError("task-#2 dynamic binding bytes differ from task-#3 derivation")
        _consume_capability(store, "preparation-finish-successors", lease, intent_digest)
        if lease.payload.get("preparationMode") == "create":
            installation_evidence = _install_and_cleanup_create(store, lease, post, intent_digest)
        else:
            installation_evidence = {
                "installIntentRecordSha256": None,
                "installObservedRecordSha256": None,
                "cleanupIntentRecordSha256": None,
                "cleanupObservedRecordSha256": None,
            }
        generation = 1
        current_path = store.directory("preparation-current") / "current.json"
        if store.exists(current_path):
            current_envelope = store.read_json(current_path, "current preparation pointer")
            current_body, _, _, current_full = store.verify(current_envelope, "beads-preparation-current")
            if current_full != expected_current:
                raise BeadsStaleAuthorityError("preparation pointer predecessor changed")
            generation = _generation(current_body.get("generation")) + 1
        elif expected_current is not None:
            raise BeadsStaleAuthorityError("preparation pointer expected a missing predecessor")
        _generation(generation)
        status_record = _signed_record(
            store,
            "BeadsStatusProfileV1",
            "beads-status-profile",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "leaseRecordSha256": lease.record_sha256,
                "payloadCanonicalSha256": sha256(status_bytes),
                "payloadCanonicalJson": payload["statusProfilePayloadCanonicalJson"],
                "dynamicBindingsCanonicalSha256": sha256(dynamic_bytes),
                "transactionIntentSha256": intent_digest,
                **_preparation_sequence_fields(lease.payload),
            },
            "status-profiles",
        )
        prepared_record = _signed_record(
            store,
            "FinishBeadsPreparationResultV1",
            "beads-preparation-result",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "leaseRecordSha256": lease.record_sha256,
                "preObservationRecordSha256": pre.record_sha256,
                "postObservationRecordSha256": post.record_sha256,
                "statusProfileRecordSha256": status_record.record_sha256,
                "preparedPayloadCanonicalSha256": sha256(prepared_bytes),
                "preparedPayloadCanonicalJson": payload["preparedStorePayloadCanonicalJson"],
                "transactionIntentSha256": intent_digest,
                **installation_evidence,
                **_preparation_sequence_fields(lease.payload),
            },
            "preparation-results",
        )
        _, result_stored_journal_head = _journal_binding_for_record(
            store,
            prepared_record.record_sha256,
            prepared_record.full_bytes_sha256,
            require_current=True,
        )
        pointer_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "generation": generation,
            "predecessorCurrentFullBytesSha256": expected_current,
            "resultRecordSha256": prepared_record.record_sha256,
            "resultStoredJournalHeadSha256": result_stored_journal_head,
            "statusProfileRecordSha256": status_record.record_sha256,
            "leaseRecordSha256": lease.record_sha256,
            "transactionIntentSha256": intent_digest,
            **installation_evidence,
            **_preparation_sequence_fields(lease.payload),
        }
        pointer = _write_current(
            store,
            "BeadsPreparationCurrentV1",
            "beads-preparation-current",
            "preparation-current",
            pointer_payload,
            expected_current,
        )
        activation = _signed_record(
            store,
            "BeadsPreparationActivationReceiptV1",
            "beads-preparation-activation-receipt",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "pointerRecordSha256": pointer.record_sha256,
                "pointerFullBytesSha256": pointer.full_bytes_sha256,
                "resultRecordSha256": prepared_record.record_sha256,
                "resultStoredJournalHeadSha256": result_stored_journal_head,
                "statusProfileRecordSha256": status_record.record_sha256,
                **installation_evidence,
                **_preparation_sequence_fields(lease.payload),
            },
            "preparation-activation-receipts",
        )
        _transaction_receipt(store, directory, "finish-beads-preparation", pointer)
        result_body = {
            **{key: value for key, value in prepared_record.payload.items() if key not in {"kind", "schemaVersion"}},
            "resultStoredJournalHeadSha256": result_stored_journal_head,
            "pointerRecordSha256": pointer.record_sha256,
            "currentPointerFullBytesSha256": pointer.full_bytes_sha256,
            "activationReceiptRecordSha256": activation.record_sha256,
        }
        return FinishBeadsPreparationResultV1(
            payload=result_body,
            auth=prepared_record.auth,
            record_sha256=prepared_record.record_sha256,
            full_bytes_sha256=prepared_record.full_bytes_sha256,
        )


def _finish_preparation_projection(store: _Store, pointer: _WireRecord) -> FinishBeadsPreparationResultV1:
    result = _load_record(
        store,
        "FinishBeadsPreparationResultV1",
        "beads-preparation-result",
        "preparation-results",
        str(pointer.payload.get("resultRecordSha256")),
    )
    expected_activation_payload = {
        "repositoryLocatorSha256": store.repository_digest,
        "pointerRecordSha256": pointer.record_sha256,
        "pointerFullBytesSha256": pointer.full_bytes_sha256,
        "resultRecordSha256": result.record_sha256,
        "resultStoredJournalHeadSha256": pointer.payload.get("resultStoredJournalHeadSha256"),
        "statusProfileRecordSha256": result.payload.get("statusProfileRecordSha256"),
        "installIntentRecordSha256": result.payload.get("installIntentRecordSha256"),
        "installObservedRecordSha256": result.payload.get("installObservedRecordSha256"),
        "cleanupIntentRecordSha256": result.payload.get("cleanupIntentRecordSha256"),
        "cleanupObservedRecordSha256": result.payload.get("cleanupObservedRecordSha256"),
        **_preparation_sequence_fields(pointer.payload),
    }
    _, _, activation_digest, _ = store.sign(
        "beads-preparation-activation-receipt", expected_activation_payload
    )
    _verify_preparation_pointer(store, pointer, historical=True)
    return FinishBeadsPreparationResultV1(
        payload={
            **{key: value for key, value in result.payload.items() if key not in {"kind", "schemaVersion"}},
            "resultStoredJournalHeadSha256": pointer.payload.get("resultStoredJournalHeadSha256"),
            "pointerRecordSha256": pointer.record_sha256,
            "currentPointerFullBytesSha256": pointer.full_bytes_sha256,
            "activationReceiptRecordSha256": activation_digest,
        },
        auth=result.auth,
        record_sha256=result.record_sha256,
        full_bytes_sha256=result.full_bytes_sha256,
    )


def _verify_preparation_pointer(store: _Store, pointer: _WireRecord, *, historical: bool) -> _WireRecord:
    result = _load_record(store, "FinishBeadsPreparationResultV1", "beads-preparation-result", "preparation-results", pointer.payload["resultRecordSha256"])
    sequence = _preparation_sequence_fields(pointer.payload)
    expected_activation_payload = {
        "repositoryLocatorSha256": store.repository_digest,
        "pointerRecordSha256": pointer.record_sha256,
        "pointerFullBytesSha256": pointer.full_bytes_sha256,
        "resultRecordSha256": result.record_sha256,
        "resultStoredJournalHeadSha256": pointer.payload.get("resultStoredJournalHeadSha256"),
        "statusProfileRecordSha256": result.payload.get("statusProfileRecordSha256"),
        "installIntentRecordSha256": result.payload.get("installIntentRecordSha256"),
        "installObservedRecordSha256": result.payload.get("installObservedRecordSha256"),
        "cleanupIntentRecordSha256": result.payload.get("cleanupIntentRecordSha256"),
        "cleanupObservedRecordSha256": result.payload.get("cleanupObservedRecordSha256"),
        **sequence,
    }
    _, _, expected_activation_record, _ = store.sign(
        "beads-preparation-activation-receipt",
        expected_activation_payload,
    )
    activation = _load_record(
        store,
        "BeadsPreparationActivationReceiptV1",
        "beads-preparation-activation-receipt",
        "preparation-activation-receipts",
        expected_activation_record,
    )
    exact_pointer_joins = {
        "repositoryLocatorSha256": store.repository_digest,
        "resultRecordSha256": result.record_sha256,
        "resultStoredJournalHeadSha256": pointer.payload.get("resultStoredJournalHeadSha256"),
        "statusProfileRecordSha256": result.payload.get("statusProfileRecordSha256"),
        "leaseRecordSha256": result.payload.get("leaseRecordSha256"),
        "installIntentRecordSha256": result.payload.get("installIntentRecordSha256"),
        "installObservedRecordSha256": result.payload.get("installObservedRecordSha256"),
        "cleanupIntentRecordSha256": result.payload.get("cleanupIntentRecordSha256"),
        "cleanupObservedRecordSha256": result.payload.get("cleanupObservedRecordSha256"),
    }
    if any(pointer.payload.get(key) != value for key, value in exact_pointer_joins.items()):
        raise BeadsProtectedRuntimeError("preparation pointer terminal suffix join mismatch")
    _, actual_result_stored_head = _journal_binding_for_record(
        store, result.record_sha256, result.full_bytes_sha256
    )
    if actual_result_stored_head != pointer.payload.get("resultStoredJournalHeadSha256"):
        raise BeadsProtectedRuntimeError("preparation pointer does not bind the actual result-stored journal head")
    if canonical_bytes(_plain(activation.payload)) != canonical_bytes(
        {"kind": "beads-preparation-activation-receipt", "schemaVersion": 1, **expected_activation_payload}
    ):
        raise BeadsProtectedRuntimeError("preparation activation receipt is not the exact terminal suffix")
    verified_type = "VerifiedHistoricalBeadsPreparationV1" if historical else "VerifiedCurrentBeadsPreparationV1"
    verified_payload = {
        "repositoryLocatorSha256": store.repository_digest,
        "pointerRecordSha256": pointer.record_sha256,
        "pointerFullBytesSha256": pointer.full_bytes_sha256,
        "resultRecordSha256": result.record_sha256,
        "activationReceiptRecordSha256": activation.record_sha256,
        "historicalOnly": historical,
        **_preparation_sequence_fields(pointer.payload),
    }
    return globals()[verified_type](
        payload=verified_payload,
        auth=pointer.auth,
        record_sha256=pointer.record_sha256,
        full_bytes_sha256=pointer.full_bytes_sha256,
    )


def verify_current_beads_preparation_v1(repository_locator_sha256: str) -> VerifiedCurrentBeadsPreparationV1:
    store = _store_for_repository(repository_locator_sha256)
    with store.locked():
        pointer = _load_current(store, "BeadsPreparationCurrentV1", "beads-preparation-current", "preparation-current")
        verified = _verify_preparation_pointer(store, pointer, historical=False)
        authority = _current_authority(store, require_active=True)
        if authority.payload.get("preparationPointerRecordSha256") != pointer.record_sha256:
            raise BeadsProtectedRuntimeError("active authority does not join the current preparation pointer")
        return verified


def verify_historical_beads_preparation_v1(
    repository_locator_sha256: str,
    pointer_record_sha256: str,
) -> VerifiedHistoricalBeadsPreparationV1:
    store = _store_for_repository(repository_locator_sha256)
    with store.locked():
        pointer = _load_record(
            store,
            "BeadsPreparationCurrentV1",
            "beads-preparation-current",
            "preparation-current",
            pointer_record_sha256,
        )
        return _verify_preparation_pointer(store, pointer, historical=True)


_CORE_CELLS = {
    ("create", "create"),
    ("reattest", "reattest"),
    ("reattest", "adapter-change"),
    ("runtime-change", "adapter-change"),
    ("runtime-change", "runtime-rollforward"),
    ("reconciliation", "reconciliation"),
}


def _build_core(inputs: _WireRecord, expected_type: str, kind: str) -> bytes:
    payload = _request(inputs, expected_type)
    _required(payload, "bootstrapChangeKind", "adapterChangeKind", "remediationEvidenceSha256", "baselineCommit")
    if payload["baselineCommit"] != BEADS_BASELINE_COMMIT:
        raise BeadsProtectedRuntimeError("change-plan core baselineCommit is not the supported Beads baseline")
    cell = (payload["bootstrapChangeKind"], payload["adapterChangeKind"])
    if cell not in _CORE_CELLS:
        raise BeadsProtectedRuntimeError("change-plan core is outside the six registered cells")
    remediation = _digest(payload["remediationEvidenceSha256"], "remediationEvidenceSha256", nullable=True)
    if cell in {("runtime-change", "adapter-change"), ("runtime-change", "runtime-rollforward"), ("reconciliation", "reconciliation")}:
        if remediation is None:
            raise BeadsProtectedRuntimeError("change-plan core requires remediation evidence")
    elif remediation is not None:
        raise BeadsProtectedRuntimeError("change-plan core forbids remediation evidence")
    body = {"kind": kind, "schemaVersion": 1, **payload}
    return canonical_bytes(body)


def build_beads_bootstrap_runtime_core_v1(inputs: BeadsBootstrapRuntimeCoreInputsV1) -> bytes:
    return _build_core(inputs, "BeadsBootstrapRuntimeCoreInputsV1", "beads-bootstrap-runtime-core")


def build_beads_adapter_release_core_v1(inputs: BeadsAdapterReleaseCoreInputsV1) -> bytes:
    return _build_core(inputs, "BeadsAdapterReleaseCoreInputsV1", "beads-adapter-release-core")


def record_beads_change_plan_core_v1(request: RecordBeadsChangePlanCoreRequestV1) -> VerifiedBeadsChangePlanCoreRecordV1:
    payload = _request(request, "RecordBeadsChangePlanCoreRequestV1")
    _required(payload, "bootstrapRuntimeCoreCanonicalJson", "adapterReleaseCoreCanonicalJson")
    bootstrap = _canonical_json_text(payload["bootstrapRuntimeCoreCanonicalJson"], "bootstrap runtime core")
    adapter = _canonical_json_text(payload["adapterReleaseCoreCanonicalJson"], "adapter release core")
    bootstrap_value = json.loads(bootstrap)
    adapter_value = json.loads(adapter)
    expected_core_fields = {
        "kind", "schemaVersion", "bootstrapChangeKind", "adapterChangeKind",
        "remediationEvidenceSha256", "baselineCommit",
    }
    if set(bootstrap_value) != expected_core_fields or set(adapter_value) != expected_core_fields:
        raise BeadsProtectedRuntimeError("change-plan core canonical bytes have unknown or missing fields")
    rebuilt_bootstrap = build_beads_bootstrap_runtime_core_v1(
        BeadsBootstrapRuntimeCoreInputsV1(
            payload={key: value for key, value in bootstrap_value.items() if key not in {"kind", "schemaVersion"}}
        )
    )
    rebuilt_adapter = build_beads_adapter_release_core_v1(
        BeadsAdapterReleaseCoreInputsV1(
            payload={key: value for key, value in adapter_value.items() if key not in {"kind", "schemaVersion"}}
        )
    )
    if rebuilt_bootstrap != bootstrap or rebuilt_adapter != adapter:
        raise BeadsProtectedRuntimeError("change-plan core cannot be rebuilt byte-for-byte from its exact input schema")
    bootstrap_cell = (bootstrap_value.get("bootstrapChangeKind"), bootstrap_value.get("adapterChangeKind"))
    adapter_cell = (adapter_value.get("bootstrapChangeKind"), adapter_value.get("adapterChangeKind"))
    if bootstrap_cell != adapter_cell or bootstrap_cell not in _CORE_CELLS:
        raise BeadsProtectedRuntimeError("bootstrap/adapter core cell mismatch")
    if bootstrap_value.get("remediationEvidenceSha256") != adapter_value.get("remediationEvidenceSha256"):
        raise BeadsProtectedRuntimeError("bootstrap/adapter remediation evidence mismatch")
    store = _Store(payload)
    with store.locked():
        intent_digest, directory = _transaction_intent(store, "record-beads-change-plan-core", payload)
        result = _signed_record(
            store,
            "VerifiedBeadsChangePlanCoreRecordV1",
            "beads-change-plan-core-record",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "bootstrapRuntimeCoreSha256": sha256(bootstrap),
                "adapterReleaseCoreSha256": sha256(adapter),
                "bootstrapRuntimeCoreCanonicalJson": payload["bootstrapRuntimeCoreCanonicalJson"],
                "adapterReleaseCoreCanonicalJson": payload["adapterReleaseCoreCanonicalJson"],
                "bootstrapChangeKind": bootstrap_cell[0],
                "adapterChangeKind": bootstrap_cell[1],
                "remediationEvidenceSha256": bootstrap_value.get("remediationEvidenceSha256"),
                "transactionIntentSha256": intent_digest,
            },
            "change-plan-cores",
        )
        result_envelope = store.read_json(
            store.directory("change-plan-cores", "history")
            / (result.record_sha256.removeprefix("sha256:") + ".json"),
            "change-plan core deterministic source",
        )
        for field in ("bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256"):
            store.write_immutable(
                store.directory("change-plan-cores", "by-core")
                / (result.payload[field].removeprefix("sha256:") + ".json"),
                result_envelope,
            )
        _transaction_receipt(store, directory, "record-beads-change-plan-core", result)
        return result


def _load_change_plan_core_by_digest(
    store: _Store,
    field: str,
    digest: str,
) -> _WireRecord:
    _digest(digest, field)
    path = store.directory("change-plan-cores", "by-core") / (digest.removeprefix("sha256:") + ".json")
    envelope = store.read_json(path, "change-plan core deterministic index")
    body, _, record_digest, _ = store.verify(envelope, "beads-change-plan-core-record")
    result = _load_record(
        store,
        "VerifiedBeadsChangePlanCoreRecordV1",
        "beads-change-plan-core-record",
        "change-plan-cores",
        record_digest,
    )
    if (
        canonical_bytes(envelope) != canonical_bytes({"payload": _plain(result.payload), "auth": result.auth})
        or body.get(field) != digest
    ):
        raise BeadsProtectedRuntimeError("change-plan core deterministic index mismatch")
    return result


def verify_beads_change_plan_core_record_v1(
    repository_locator_sha256: str,
    core_record_sha256: str,
) -> VerifiedBeadsChangePlanCoreRecordV1:
    store = _store_for_repository(repository_locator_sha256)
    with store.locked():
        return _load_record(
            store,
            "VerifiedBeadsChangePlanCoreRecordV1",
            "beads-change-plan-core-record",
            "change-plan-cores",
            core_record_sha256,
        )


def authorize_beads_authority_transition_v1(
    request: AuthorizeBeadsAuthorityTransitionRequestV1,
) -> BeadsAuthorityTransitionAuthorizationV1:
    payload = _request(request, "AuthorizeBeadsAuthorityTransitionRequestV1")
    _required(payload, "command", "authorizationNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256")
    if payload["command"] not in {"revoke", "stage", "activate"}:
        raise BeadsProtectedRuntimeError("authority transition command must be revoke, stage or activate")
    _identifier(payload["authorizationNonce"], "authorizationNonce")
    _expiry(payload)
    _digest(payload["expectedCurrentFullBytesSha256"], "expectedCurrentFullBytesSha256", nullable=True)
    sequence = _preparation_sequence_fields(payload)
    store = _Store(payload)
    with store.locked():
        candidate = payload.get("candidate")
        if payload["command"] in {"stage", "activate"}:
            candidate = _verify_authority_candidate(store, candidate)
        elif candidate is not None:
            raise BeadsProtectedRuntimeError("revoke authority transition forbids a candidate")
        current: _WireRecord | None = None
        try:
            current = _current_authority(store, require_active=False)
        except BeadsProtectedRuntimeError as exc:
            if "no current" not in str(exc):
                raise
        if (current.full_bytes_sha256 if current else None) != payload["expectedCurrentFullBytesSha256"]:
            raise BeadsStaleAuthorityError("authority transition predecessor changed")
        authorization_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "command": payload["command"],
            "authorizationNonce": payload["authorizationNonce"],
            "expiresAtUnix": payload["expiresAtUnix"],
            "expectedCurrentFullBytesSha256": payload["expectedCurrentFullBytesSha256"],
            "candidate": candidate,
            **sequence,
        }
        return _signed_record(
            store,
            "BeadsAuthorityTransitionAuthorizationV1",
            "beads-authority-transition-authorization",
            authorization_payload,
            "authority-transition-authorizations",
        )


_AUTHORITY_CANDIDATE_FIELDS = {
    "preparationPointerRecordSha256",
    "preparationActivationReceiptRecordSha256",
    "adapterReleaseManifestRecordSha256",
    "runtimeApiManifestRecordSha256",
    "repositoryPath",
    "databaseName",
}


def _verify_completed_preparation_physical(
    store: _Store,
    result: _WireRecord,
    lease: _WireRecord,
) -> None:
    executable_observation = _observe_executable(
        Path(str(lease.payload.get("executablePath", ""))),
        str(lease.payload.get("executableSha256", "")),
    )
    if canonical_bytes(executable_observation) != canonical_bytes(
        lease.payload.get("executableObservation")
    ):
        raise BeadsProtectedRuntimeError(
            "terminal preparation executable inode differs from the authorized lease"
        )
    evidence_fields = (
        "installIntentRecordSha256", "installObservedRecordSha256",
        "cleanupIntentRecordSha256", "cleanupObservedRecordSha256",
    )
    if lease.payload.get("preparationMode") != "create":
        if any(result.payload.get(field) is not None for field in evidence_fields):
            raise BeadsProtectedRuntimeError("reattest terminal result contains forbidden install/cleanup evidence")
        _revalidate_preparation_physical(lease)
        return
    for field in evidence_fields:
        _digest(result.payload.get(field), field)
    install_intent = _load_record(
        store, "BeadsPreparationStepV1", "beads-preparation-install-intent",
        "preparation-install-intents", result.payload["installIntentRecordSha256"],
    )
    install_observed = _load_record(
        store, "BeadsPreparationStepV1", "beads-preparation-install-observed",
        "preparation-install-observed", result.payload["installObservedRecordSha256"],
    )
    cleanup_intent = _load_record(
        store, "BeadsPreparationStepV1", "beads-preparation-cleanup-intent",
        "preparation-cleanup-intents", result.payload["cleanupIntentRecordSha256"],
    )
    cleanup_observed = _load_record(
        store, "BeadsPreparationStepV1", "beads-preparation-cleanup-observed",
        "preparation-cleanup-observed", result.payload["cleanupObservedRecordSha256"],
    )
    if (
        install_observed.payload.get("installIntentRecordSha256") != install_intent.record_sha256
        or cleanup_intent.payload.get("installObservedRecordSha256") != install_observed.record_sha256
        or cleanup_observed.payload.get("cleanupIntentRecordSha256") != cleanup_intent.record_sha256
        or cleanup_observed.payload.get("installObservedRecordSha256") != install_observed.record_sha256
        or any(record.payload.get("leaseRecordSha256") != lease.record_sha256 for record in (
            install_intent, install_observed, cleanup_intent, cleanup_observed
        ))
    ):
        raise BeadsProtectedRuntimeError("terminal install/cleanup predecessor chain mismatch")
    installed_tree = _observe_directory_tree(Path(str(lease.payload["installPath"])), "installed Beads database")
    if canonical_bytes(installed_tree) != canonical_bytes(install_observed.payload.get("installedTree")):
        raise BeadsProtectedRuntimeError("installed Beads database changed after cleanup observation")
    if _observe_path_locator(Path(str(lease.payload["cleanupPath"])), "create cleanup scaffold").get("present") is not False:
        raise BeadsProtectedRuntimeError("cleanup scaffold reappeared after terminal observation")


def _verify_authority_candidate(store: _Store, candidate: Any) -> dict[str, Any]:
    if not isinstance(candidate, Mapping) or set(candidate) != _AUTHORITY_CANDIDATE_FIELDS:
        raise BeadsProtectedRuntimeError("authority candidate has unknown or missing protected fields")
    result = _plain(candidate)
    for field in (
        "preparationPointerRecordSha256",
        "preparationActivationReceiptRecordSha256",
        "adapterReleaseManifestRecordSha256",
        "runtimeApiManifestRecordSha256",
    ):
        _digest(result[field], field)
    repository_path = Path(str(result["repositoryPath"]))
    _capture_directory(repository_path, "authority candidate repository")
    _identifier(result["databaseName"], "databaseName")

    pointer = _load_record(
        store,
        "BeadsPreparationCurrentV1",
        "beads-preparation-current",
        "preparation-current",
        result["preparationPointerRecordSha256"],
    )
    verified_pointer = _verify_preparation_pointer(store, pointer, historical=True)
    if verified_pointer.payload.get("activationReceiptRecordSha256") != result["preparationActivationReceiptRecordSha256"]:
        raise BeadsProtectedRuntimeError("authority candidate activation receipt is not the pointer-keyed terminal receipt")
    preparation_result = _load_record(
        store,
        "FinishBeadsPreparationResultV1",
        "beads-preparation-result",
        "preparation-results",
        pointer.payload["resultRecordSha256"],
    )
    lease = _load_record(
        store,
        "BeadsPreparationLeaseV1",
        "beads-preparation-lease",
        "preparation-leases",
        preparation_result.payload["leaseRecordSha256"],
    )
    _verify_completed_preparation_physical(store, preparation_result, lease)
    if (
        lease.payload.get("repositoryPath") != str(repository_path)
        or lease.payload.get("databaseName") != result["databaseName"]
    ):
        raise BeadsProtectedRuntimeError("authority candidate repository/database differs from terminal preparation")

    runtime_manifest = _load_record(
        store,
        "BeadsProtectedRuntimeApiManifestV1",
        "beads-protected-runtime-api-manifest",
        "runtime-api-manifests",
        result["runtimeApiManifestRecordSha256"],
    )
    release_manifest = _load_record(
        store,
        "BeadsAdapterReleaseManifestV1",
        "beads-adapter-release-manifest",
        "adapter-release-manifests",
        result["adapterReleaseManifestRecordSha256"],
    )
    if release_manifest.payload.get("runtimeApiManifestRecordSha256") != runtime_manifest.record_sha256:
        raise BeadsProtectedRuntimeError("authority candidate release/runtime manifest join mismatch")
    current_runtime = _load_current(
        store, "BeadsProtectedRuntimeApiManifestV1", "beads-protected-runtime-api-manifest", "runtime-api-manifests"
    )
    current_release = _load_current(
        store, "BeadsAdapterReleaseManifestV1", "beads-adapter-release-manifest", "adapter-release-manifests"
    )
    if current_runtime.record_sha256 != runtime_manifest.record_sha256 or current_release.record_sha256 != release_manifest.record_sha256:
        raise BeadsStaleAuthorityError("authority candidate runtime/release manifest is no longer current")
    core = _load_change_plan_core_by_digest(
        store, "bootstrapRuntimeCoreSha256", release_manifest.payload.get("bootstrapRuntimeCoreSha256")
    )
    observations = release_manifest.payload.get("runtimeManifestObservations")
    if (
        core.record_sha256 != release_manifest.payload.get("changePlanCoreRecordSha256")
        or core.payload.get("adapterReleaseCoreSha256") != release_manifest.payload.get("adapterReleaseCoreSha256")
        or runtime_manifest.payload.get("changePlanCoreRecordSha256") != core.record_sha256
        or not isinstance(observations, (list, tuple))
        or [item.get("phase") for item in observations if isinstance(item, Mapping)] != ["A", "B", "C"]
    ):
        raise BeadsProtectedRuntimeError("authority candidate cannot independently reproduce release evidence")
    expected_observation_fields = {
        "phase", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256",
        "runtimeApiManifestRecordSha256", "adapterPayloadSha256", "remediationEvidenceSha256",
    }
    for observation in observations:
        if not isinstance(observation, Mapping) or set(observation) != expected_observation_fields:
            raise BeadsProtectedRuntimeError("authority candidate release observation schema mismatch")
        for field in expected_observation_fields - {"phase"}:
            if observation.get(field) != release_manifest.payload.get(field):
                raise BeadsProtectedRuntimeError("authority candidate release observation join mismatch")
    if (
        lease.payload.get("runtimeApiManifestRecordSha256") != runtime_manifest.record_sha256
        or lease.payload.get("adapterReleaseManifestRecordSha256") != release_manifest.record_sha256
        or lease.payload.get("bootstrapRuntimeCoreSha256") != runtime_manifest.payload.get("bootstrapRuntimeCoreSha256")
        or lease.payload.get("bootstrapRuntimeCoreSha256") != release_manifest.payload.get("bootstrapRuntimeCoreSha256")
        or lease.payload.get("adapterReleaseCoreSha256") != release_manifest.payload.get("adapterReleaseCoreSha256")
    ):
        raise BeadsProtectedRuntimeError("authority candidate does not reproduce preparation/core manifest joins")
    return result


def _authority_transition_result(
    store: _Store,
    receipt: _WireRecord,
    result_type: str,
) -> _WireRecord:
    state = _load_record(
        store,
        "BeadsAuthorityEpochStateV1",
        "beads-authority-epoch-state",
        "authority",
        receipt.payload.get("authorityStateRecordSha256"),
    )
    if state.full_bytes_sha256 != receipt.payload.get("authorityStateFullBytesSha256"):
        raise BeadsProtectedRuntimeError("authority receipt/state full-bytes join mismatch")
    step = _load_record(
        store,
        "BeadsAuthorityTransitionStepV1",
        "beads-authority-transition-step",
        "authority-transition-steps",
        receipt.payload.get("transitionStepRecordSha256"),
    )
    if (
        step.payload.get("authorityStateRecordSha256") != state.record_sha256
        or step.payload.get("authorityStateFullBytesSha256") != state.full_bytes_sha256
        or step.payload.get("transactionIntentSha256") != state.payload.get("transitionIntentSha256")
        or receipt.payload.get("transactionIntentSha256") != state.payload.get("transitionIntentSha256")
        or receipt.payload.get("authorizationRecordSha256") != state.payload.get("transitionAuthorizationRecordSha256")
    ):
        raise BeadsProtectedRuntimeError("authority transition intent/step/receipt chain mismatch")
    result_payload = {
        **{key: value for key, value in state.payload.items() if key not in {"kind", "schemaVersion"}},
        "transitionReceiptRecordSha256": receipt.record_sha256,
    }
    return globals()[result_type](
        payload=result_payload,
        auth=state.auth,
        record_sha256=state.record_sha256,
        full_bytes_sha256=state.full_bytes_sha256,
    )


def _store_authority_transition_receipt_link(store: _Store, state: _WireRecord, receipt: _WireRecord) -> None:
    path = store.directory("authority-transition-receipts", "by-state") / (
        state.record_sha256.removeprefix("sha256:") + ".json"
    )
    envelope = store.read_json(
        store.directory("authority-transition-receipts", "history")
        / (receipt.record_sha256.removeprefix("sha256:") + ".json"),
        "authority transition receipt deterministic source",
    )
    store.write_immutable(path, envelope)


def _load_authority_transition_receipt_for_state(store: _Store, state: _WireRecord) -> _WireRecord:
    path = store.directory("authority-transition-receipts", "by-state") / (
        state.record_sha256.removeprefix("sha256:") + ".json"
    )
    envelope = store.read_json(path, "authority transition state-keyed receipt")
    body, _, record_digest, _ = store.verify(envelope, "beads-authority-transition-receipt")
    receipt = _load_record(
        store,
        "BeadsAuthorityTransitionReceiptV1",
        "beads-authority-transition-receipt",
        "authority-transition-receipts",
        record_digest,
    )
    if (
        canonical_bytes(envelope) != canonical_bytes({"payload": _plain(receipt.payload), "auth": receipt.auth})
        or body.get("authorityStateRecordSha256") != state.record_sha256
    ):
        raise BeadsProtectedRuntimeError("authority state-keyed receipt is renamed, changed or belongs to another state")
    return receipt


def _authority_transition(
    request: _WireRecord,
    request_type: str,
    command: str,
    expected_state: str | None,
    next_state: str,
    result_type: str,
) -> _WireRecord:
    payload = _request(request, request_type)
    _required(payload, "authorizationRecordSha256")
    store = _Store(payload)
    with store.locked():
        authorization = _load_record(
            store,
            "BeadsAuthorityTransitionAuthorizationV1",
            "beads-authority-transition-authorization",
            "authority-transition-authorizations",
            payload["authorizationRecordSha256"],
        )
        _expiry(authorization.payload)
        if authorization.payload.get("command") != command:
            raise BeadsProtectedRuntimeError("authority transition capability command mismatch")
        intent_digest, directory = _transaction_intent(store, f"{command}-beads-authority", payload)
        resumed = _resume_transaction_result(
            store,
            directory,
            f"{command}-beads-authority",
            "BeadsAuthorityTransitionReceiptV1",
            "beads-authority-transition-receipt",
            "authority-transition-receipts",
        )
        if resumed is not None:
            return _authority_transition_result(store, resumed, result_type)
        current: _WireRecord | None = None
        try:
            current = _current_authority(store, require_active=False)
        except BeadsProtectedRuntimeError as exc:
            if "no current" not in str(exc):
                raise
        if (
            current is not None
            and current.payload.get("transitionIntentSha256") == intent_digest
            and _capability_consumed_by(store, "authority-transition-authorizations", authorization, intent_digest)
        ):
            candidate = authorization.payload.get("candidate")
            if command in {"stage", "activate"}:
                candidate = _verify_authority_candidate(store, candidate)
            step = _signed_record(
                store,
                "BeadsAuthorityTransitionStepV1",
                "beads-authority-transition-step",
                {
                    "repositoryLocatorSha256": store.repository_digest,
                    "command": command,
                    "transactionIntentSha256": intent_digest,
                    "authorizationRecordSha256": authorization.record_sha256,
                    "authorityStateRecordSha256": current.record_sha256,
                    "authorityStateFullBytesSha256": current.full_bytes_sha256,
                    "predecessorCurrentFullBytesSha256": current.payload.get("predecessorCurrentFullBytesSha256"),
                    "candidate": candidate,
                    **_preparation_sequence_fields(authorization.payload),
                },
                "authority-transition-steps",
            )
            receipt = _signed_record(
                store,
                "BeadsAuthorityTransitionReceiptV1",
                "beads-authority-transition-receipt",
                {
                    "repositoryLocatorSha256": store.repository_digest,
                    "command": command,
                    "transactionIntentSha256": intent_digest,
                    "authorizationRecordSha256": authorization.record_sha256,
                    "transitionStepRecordSha256": step.record_sha256,
                    "authorityStateRecordSha256": current.record_sha256,
                    "authorityStateFullBytesSha256": current.full_bytes_sha256,
                    "predecessorCurrentFullBytesSha256": current.payload.get("predecessorCurrentFullBytesSha256"),
                    "candidate": candidate,
                    **_preparation_sequence_fields(authorization.payload),
                },
                "authority-transition-receipts",
            )
            _store_authority_transition_receipt_link(store, current, receipt)
            _transaction_receipt(store, directory, f"{command}-beads-authority", receipt)
            return _authority_transition_result(store, receipt, result_type)
        if (current.full_bytes_sha256 if current else None) != authorization.payload.get("expectedCurrentFullBytesSha256"):
            raise BeadsStaleAuthorityError("authority current changed after transition authorization")
        if expected_state is None:
            if current is not None and current.payload.get("authorityState") not in {"active", "pending", "revoked"}:
                raise BeadsProtectedRuntimeError("authority state is unknown")
        elif current is None or current.payload.get("authorityState") != expected_state:
            raise BeadsProtectedRuntimeError(f"{command} requires {expected_state} authority")
        _consume_capability(store, "authority-transition-authorizations", authorization, intent_digest)
        generation = 1 if current is None else _generation(current.payload.get("generation")) + 1
        _generation(generation)
        candidate = authorization.payload.get("candidate")
        if command in {"stage", "activate"}:
            candidate = _verify_authority_candidate(store, candidate)
        elif candidate is not None:
            raise BeadsProtectedRuntimeError("revoke authority transition forbids a candidate")
        state_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "generation": generation,
            "authorityState": next_state,
            "predecessorCurrentFullBytesSha256": current.full_bytes_sha256 if current else None,
            "transitionAuthorizationRecordSha256": authorization.record_sha256,
            "transitionIntentSha256": intent_digest,
            "candidate": candidate,
            "preparationPointerRecordSha256": candidate.get("preparationPointerRecordSha256") if isinstance(candidate, Mapping) else None,
            "adapterReleaseManifestRecordSha256": candidate.get("adapterReleaseManifestRecordSha256") if isinstance(candidate, Mapping) else None,
            "runtimeApiManifestRecordSha256": candidate.get("runtimeApiManifestRecordSha256") if isinstance(candidate, Mapping) else None,
            **_preparation_sequence_fields(authorization.payload),
        }
        state = _write_current(
            store,
            "BeadsAuthorityEpochStateV1",
            "beads-authority-epoch-state",
            "authority",
            state_payload,
            current.full_bytes_sha256 if current else None,
        )
        _fault(f"{command}-authority-current-written")
        step = _signed_record(
            store,
            "BeadsAuthorityTransitionStepV1",
            "beads-authority-transition-step",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "command": command,
                "transactionIntentSha256": intent_digest,
                "authorizationRecordSha256": authorization.record_sha256,
                "authorityStateRecordSha256": state.record_sha256,
                "authorityStateFullBytesSha256": state.full_bytes_sha256,
                "predecessorCurrentFullBytesSha256": current.full_bytes_sha256 if current else None,
                "candidate": candidate,
                **_preparation_sequence_fields(authorization.payload),
            },
            "authority-transition-steps",
        )
        receipt = _signed_record(
            store,
            "BeadsAuthorityTransitionReceiptV1",
            "beads-authority-transition-receipt",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "command": command,
                "transactionIntentSha256": intent_digest,
                "authorizationRecordSha256": authorization.record_sha256,
                "transitionStepRecordSha256": step.record_sha256,
                "authorityStateRecordSha256": state.record_sha256,
                "authorityStateFullBytesSha256": state.full_bytes_sha256,
                "predecessorCurrentFullBytesSha256": current.full_bytes_sha256 if current else None,
                "candidate": candidate,
                **_preparation_sequence_fields(authorization.payload),
            },
            "authority-transition-receipts",
        )
        _store_authority_transition_receipt_link(store, state, receipt)
        _transaction_receipt(store, directory, f"{command}-beads-authority", receipt)
        return _authority_transition_result(store, receipt, result_type)


def revoke_beads_authority_epoch_v1(request: RevokeBeadsAuthorityEpochRequestV1) -> VerifiedRevokedBeadsAuthorityV1:
    return _authority_transition(request, "RevokeBeadsAuthorityEpochRequestV1", "revoke", None, "revoked", "VerifiedRevokedBeadsAuthorityV1")


def stage_beads_authority_epoch_v1(request: StageBeadsAuthorityEpochRequestV1) -> VerifiedPendingBeadsAuthorityV1:
    return _authority_transition(request, "StageBeadsAuthorityEpochRequestV1", "stage", "revoked", "pending", "VerifiedPendingBeadsAuthorityV1")


def activate_beads_authority_epoch_v1(request: ActivateBeadsAuthorityEpochRequestV1) -> VerifiedActiveBeadsAuthorityV1:
    return _authority_transition(request, "ActivateBeadsAuthorityEpochRequestV1", "activate", "pending", "active", "VerifiedActiveBeadsAuthorityV1")


def verify_active_beads_authority_v1(repository_locator_sha256: str) -> VerifiedActiveBeadsAuthorityV1:
    store = _store_for_repository(repository_locator_sha256)
    with store.locked():
        state = _current_authority(store, require_active=True)
        receipt = _load_authority_transition_receipt_for_state(store, state)
        _authority_transition_result(store, receipt, "VerifiedActiveBeadsAuthorityV1")
        candidate = _verify_authority_candidate(store, state.payload.get("candidate"))
        if canonical_bytes(candidate) != canonical_bytes(receipt.payload.get("candidate")):
            raise BeadsProtectedRuntimeError("active authority candidate differs from terminal transition receipt")
        pointer = _load_record(
            store,
            "BeadsPreparationCurrentV1",
            "beads-preparation-current",
            "preparation-current",
            state.payload["preparationPointerRecordSha256"],
        )
        _verify_preparation_pointer(store, pointer, historical=True)
        release = _load_current(store, "BeadsAdapterReleaseManifestV1", "beads-adapter-release-manifest", "adapter-release-manifests")
        runtime_manifest = _load_current(store, "BeadsProtectedRuntimeApiManifestV1", "beads-protected-runtime-api-manifest", "runtime-api-manifests")
        if release.record_sha256 != state.payload["adapterReleaseManifestRecordSha256"] or runtime_manifest.record_sha256 != state.payload["runtimeApiManifestRecordSha256"]:
            raise BeadsStaleAuthorityError("active authority release/runtime manifest is no longer current")
        return VerifiedActiveBeadsAuthorityV1(
            payload=state.payload,
            auth=state.auth,
            record_sha256=state.record_sha256,
            full_bytes_sha256=state.full_bytes_sha256,
        )


def verify_beads_authority_transition_receipt_v1(
    request: VerifyBeadsAuthorityTransitionReceiptRequestV1,
) -> VerifiedBeadsAuthorityTransitionReceiptV1:
    payload = _request(request, "VerifyBeadsAuthorityTransitionReceiptRequestV1")
    _required(payload, "receiptRecordSha256")
    store = _Store(payload)
    with store.locked():
        receipt = _load_record(
            store,
            "BeadsAuthorityTransitionReceiptV1",
            "beads-authority-transition-receipt",
            "authority-transition-receipts",
            payload["receiptRecordSha256"],
        )
        verified_state = _authority_transition_result(store, receipt, "VerifiedActiveBeadsAuthorityV1")
        linked = _load_authority_transition_receipt_for_state(
            store,
            _load_record(
                store,
                "BeadsAuthorityEpochStateV1",
                "beads-authority-epoch-state",
                "authority",
                receipt.payload["authorityStateRecordSha256"],
            ),
        )
        if linked.record_sha256 != receipt.record_sha256 or verified_state.payload.get("transitionReceiptRecordSha256") != receipt.record_sha256:
            raise BeadsProtectedRuntimeError("authority transition receipt deterministic link mismatch")
        return VerifiedBeadsAuthorityTransitionReceiptV1(
            payload=receipt.payload,
            auth=receipt.auth,
            record_sha256=receipt.record_sha256,
            full_bytes_sha256=receipt.full_bytes_sha256,
        )


def project_beads_authority_predecessor_locator_v1(
    verified_receipt: VerifiedBeadsAuthorityTransitionReceiptV1,
) -> BeadsAuthorityLocatorV1:
    if verified_receipt.auth is None or verified_receipt.record_sha256 is None:
        raise BeadsProtectedRuntimeError("authority locator projection requires a verified receipt")
    payload = {
        "repositoryLocatorSha256": verified_receipt.payload.get("repositoryLocatorSha256"),
        "authorityStateRecordSha256": verified_receipt.payload.get("authorityStateRecordSha256"),
        "authorityStateFullBytesSha256": verified_receipt.payload.get("authorityStateFullBytesSha256"),
        "predecessorCurrentFullBytesSha256": verified_receipt.payload.get("predecessorCurrentFullBytesSha256"),
        "verifiedReceiptRecordSha256": verified_receipt.record_sha256,
        "repositoryPath": (
            verified_receipt.payload.get("candidate", {}).get("repositoryPath")
            if isinstance(verified_receipt.payload.get("candidate"), Mapping) else None
        ),
        "databaseName": (
            verified_receipt.payload.get("candidate", {}).get("databaseName")
            if isinstance(verified_receipt.payload.get("candidate"), Mapping) else None
        ),
    }
    digest = sha256(canonical_bytes(payload))
    return BeadsAuthorityLocatorV1(payload=payload, record_sha256=digest, full_bytes_sha256=digest)


_FUNCTION_EXPORTS = (
    "prepare_atomic_claim_v1", "advance_atomic_claim_v1", "record_atomic_claim_receipt_v1",
    "authorize_claim_launch_v1", "begin_beads_mutation_v1", "finish_beads_mutation_v1",
    "verify_beads_installed_database_selector_v1", "authorize_beads_preparation_v1",
    "begin_beads_preparation_v1", "observe_beads_store_v1", "advance_beads_preparation_v1",
    "derive_beads_status_profile_dynamic_bindings_v1", "finish_beads_preparation_v1",
    "verify_current_beads_preparation_v1", "verify_historical_beads_preparation_v1",
    "build_beads_bootstrap_runtime_core_v1", "build_beads_adapter_release_core_v1",
    "record_beads_change_plan_core_v1", "verify_beads_change_plan_core_record_v1",
    "authorize_beads_authority_transition_v1", "revoke_beads_authority_epoch_v1",
    "stage_beads_authority_epoch_v1", "activate_beads_authority_epoch_v1",
    "verify_active_beads_authority_v1", "verify_beads_authority_transition_receipt_v1",
    "project_beads_authority_predecessor_locator_v1",
    "authorize_beads_runtime_api_manifest_record_v1", "record_beads_protected_runtime_api_manifest_v1",
    "verify_current_beads_protected_runtime_api_manifest_v1",
    "verify_historical_beads_protected_runtime_api_manifest_v1",
    "authorize_beads_adapter_release_manifest_record_v1", "record_beads_adapter_release_manifest_v1",
    "verify_current_beads_adapter_release_manifest_v1",
)


def beads_protected_runtime_schema_v1() -> bytes:
    return canonical_bytes(
        {
            "schemaVersion": 1,
            "baselineCommit": BEADS_BASELINE_COMMIT,
            "module": "startup_factory_cli.beads_protected_runtime",
            "types": sorted(_TYPE_NAMES),
            "typeSchemas": {
                name: {
                    "fields": sorted(_TYPE_SCHEMAS[name]["fields"]),
                    "nullable": sorted(_TYPE_SCHEMAS[name]["nullable"]),
                    "required": sorted(_TYPE_SCHEMAS[name]["required"]),
                }
                for name in sorted(_TYPE_NAMES)
            },
            "functions": sorted(_FUNCTION_EXPORTS),
            "generationRange": [1, MAX_GENERATION],
            "reattestArgv": ["B", "--db", "S", "--json", "--sandbox", "config", "list"],
        }
    )


def authorize_beads_runtime_api_manifest_record_v1(
    request: AuthorizeBeadsRuntimeApiManifestRecordRequestV1,
) -> BeadsRuntimeApiManifestRecordCapabilityV1:
    payload = _request(request, "AuthorizeBeadsRuntimeApiManifestRecordRequestV1")
    _required(
        payload,
        "mode", "capabilityNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256",
        "bootstrapRuntimeCoreSha256", "runtimeTransactionAuthorityBinding",
    )
    if payload["mode"] not in {"revoked-bootstrap", "revoked-successor"}:
        raise BeadsProtectedRuntimeError("runtime API manifest mode must be revoked-bootstrap or revoked-successor")
    _identifier(payload["capabilityNonce"], "capabilityNonce")
    _expiry(payload)
    _digest(payload["expectedCurrentFullBytesSha256"], "expectedCurrentFullBytesSha256", nullable=True)
    _digest(payload["bootstrapRuntimeCoreSha256"], "bootstrapRuntimeCoreSha256")
    binding = payload["runtimeTransactionAuthorityBinding"]
    if not isinstance(binding, Mapping) or set(binding) != {"kind", "identitySha256"}:
        raise BeadsProtectedRuntimeError("runtime manifest requires an exact direct transaction authority binding")
    _identifier(binding["kind"], "runtime transaction authority kind")
    _digest(binding["identitySha256"], "runtime transaction authority identitySha256")
    store = _Store(payload)
    with store.locked():
        core = _load_change_plan_core_by_digest(
            store, "bootstrapRuntimeCoreSha256", payload["bootstrapRuntimeCoreSha256"]
        )
        authority = _current_authority(store, require_active=False)
        if authority.payload.get("authorityState") != "revoked":
            raise BeadsProtectedRuntimeError("runtime API manifest recording requires revoked authority")
        current_path = store.directory("runtime-api-manifests") / "current.json"
        current_digest = sha256(store._read_bytes(current_path, "current runtime manifest")) if store.exists(current_path) else None
        if current_digest != payload["expectedCurrentFullBytesSha256"]:
            raise BeadsStaleAuthorityError("runtime API manifest predecessor changed")
        return _signed_record(
            store,
            "BeadsRuntimeApiManifestRecordCapabilityV1",
            "beads-runtime-api-manifest-record-capability",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "mode": payload["mode"],
                "capabilityNonce": payload["capabilityNonce"],
                "expiresAtUnix": payload["expiresAtUnix"],
                "expectedCurrentFullBytesSha256": payload["expectedCurrentFullBytesSha256"],
                "bootstrapRuntimeCoreSha256": payload["bootstrapRuntimeCoreSha256"],
                "runtimeTransactionAuthorityBinding": _plain(binding),
                "runtimeTransactionAuthorityBindingSha256": sha256(canonical_bytes(binding)),
                "changePlanCoreRecordSha256": core.record_sha256,
                "revokedAuthorityRecordSha256": authority.record_sha256,
            },
            "runtime-api-manifest-capabilities",
        )


def record_beads_protected_runtime_api_manifest_v1(
    request: RecordBeadsProtectedRuntimeApiManifestRequestV1,
    capability: BeadsRuntimeApiManifestRecordCapabilityV1,
) -> BeadsProtectedRuntimeApiManifestV1:
    payload = _request(request, "RecordBeadsProtectedRuntimeApiManifestRequestV1")
    _required(payload, "moduleSha256", "schemaFixtureSha256", "exports", "bootstrapRuntimeCoreSha256")
    for field in ("moduleSha256", "schemaFixtureSha256", "bootstrapRuntimeCoreSha256"):
        _digest(payload[field], field)
    if sorted(payload["exports"]) != sorted((*_TYPE_NAMES, *_FUNCTION_EXPORTS)) or len(payload["exports"]) != len(set(payload["exports"])):
        raise BeadsProtectedRuntimeError("runtime API manifest export set is incomplete, duplicated or unknown")
    if payload["schemaFixtureSha256"] != sha256(beads_protected_runtime_schema_v1()):
        raise BeadsProtectedRuntimeError("runtime API manifest schema fixture digest mismatch")
    store = _Store(payload)
    with store.locked():
        protected_capability = _load_record(
            store,
            "BeadsRuntimeApiManifestRecordCapabilityV1",
            "beads-runtime-api-manifest-record-capability",
            "runtime-api-manifest-capabilities",
            capability.record_sha256,
        )
        intent_digest, directory = _transaction_intent(store, "record-runtime-api-manifest", payload)
        resumed = _resume_transaction_result(
            store,
            directory,
            "record-runtime-api-manifest",
            "BeadsProtectedRuntimeApiManifestV1",
            "beads-protected-runtime-api-manifest",
            "runtime-api-manifests",
        )
        if resumed is not None:
            return resumed
        recovered = _recover_current_transaction_result(
            store,
            directory,
            "record-runtime-api-manifest",
            "BeadsProtectedRuntimeApiManifestV1",
            "beads-protected-runtime-api-manifest",
            "runtime-api-manifests",
            intent_digest,
        )
        if recovered is not None:
            return recovered
        _expiry(protected_capability.payload)
        authority = _current_authority(store, require_active=False)
        if authority.payload.get("authorityState") != "revoked" or authority.record_sha256 != protected_capability.payload.get("revokedAuthorityRecordSha256"):
            raise BeadsStaleAuthorityError("runtime manifest capability no longer binds current revoked authority")
        if protected_capability.payload.get("bootstrapRuntimeCoreSha256") != payload["bootstrapRuntimeCoreSha256"]:
            raise BeadsProtectedRuntimeError("runtime manifest bootstrap core differs from capability")
        _consume_capability(store, "runtime-api-manifest-capabilities", protected_capability, intent_digest)
        _fault("runtime-manifest-capability-consumed")
        current_path = store.directory("runtime-api-manifests") / "current.json"
        generation = 1
        if store.exists(current_path):
            current_envelope = store.read_json(current_path, "current runtime API manifest")
            current_body, _, _, current_full = store.verify(current_envelope, "beads-protected-runtime-api-manifest")
            if current_full != protected_capability.payload.get("expectedCurrentFullBytesSha256"):
                raise BeadsStaleAuthorityError("runtime API manifest predecessor changed after capability issue")
            generation = _generation(current_body.get("generation")) + 1
        elif protected_capability.payload.get("expectedCurrentFullBytesSha256") is not None:
            raise BeadsStaleAuthorityError("runtime API manifest expected a missing predecessor")
        _generation(generation)
        manifest_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "generation": generation,
            "predecessorCurrentFullBytesSha256": protected_capability.payload.get("expectedCurrentFullBytesSha256"),
            "capabilityRecordSha256": protected_capability.record_sha256,
            "mode": protected_capability.payload["mode"],
            "moduleSha256": payload["moduleSha256"],
            "schemaFixtureSha256": payload["schemaFixtureSha256"],
            "exports": sorted(payload["exports"]),
            "bootstrapRuntimeCoreSha256": payload["bootstrapRuntimeCoreSha256"],
            "runtimeTransactionAuthorityBinding": protected_capability.payload["runtimeTransactionAuthorityBinding"],
            "runtimeTransactionAuthorityBindingSha256": protected_capability.payload["runtimeTransactionAuthorityBindingSha256"],
            "changePlanCoreRecordSha256": protected_capability.payload["changePlanCoreRecordSha256"],
            "transactionIntentSha256": intent_digest,
        }
        result = _write_current(
            store,
            "BeadsProtectedRuntimeApiManifestV1",
            "beads-protected-runtime-api-manifest",
            "runtime-api-manifests",
            manifest_payload,
            protected_capability.payload.get("expectedCurrentFullBytesSha256"),
        )
        _fault("runtime-manifest-current-written")
        _transaction_receipt(store, directory, "record-runtime-api-manifest", result)
        return result


def verify_current_beads_protected_runtime_api_manifest_v1(
    request: VerifyBeadsProtectedRuntimeApiManifestRequestV1,
) -> VerifiedBeadsProtectedRuntimeApiManifestV1:
    payload = _request(request, "VerifyBeadsProtectedRuntimeApiManifestRequestV1")
    _required(payload, "expectedManifestRecordSha256", "expectedModuleSha256", "expectedSchemaFixtureSha256")
    store = _Store(payload)
    with store.locked():
        manifest = _load_current(store, "BeadsProtectedRuntimeApiManifestV1", "beads-protected-runtime-api-manifest", "runtime-api-manifests")
        if manifest.record_sha256 != payload["expectedManifestRecordSha256"]:
            raise BeadsStaleAuthorityError("current runtime API manifest record changed")
        if manifest.payload.get("moduleSha256") != payload["expectedModuleSha256"] or manifest.payload.get("schemaFixtureSha256") != payload["expectedSchemaFixtureSha256"]:
            raise BeadsProtectedRuntimeError("runtime API manifest code/schema identity mismatch")
        binding = manifest.payload.get("runtimeTransactionAuthorityBinding")
        if (
            not isinstance(binding, Mapping)
            or set(binding) != {"kind", "identitySha256"}
            or sha256(canonical_bytes(binding)) != manifest.payload.get("runtimeTransactionAuthorityBindingSha256")
        ):
            raise BeadsProtectedRuntimeError("runtime API manifest transaction authority binding mismatch")
        core = _load_change_plan_core_by_digest(
            store, "bootstrapRuntimeCoreSha256", manifest.payload.get("bootstrapRuntimeCoreSha256")
        )
        if core.record_sha256 != manifest.payload.get("changePlanCoreRecordSha256"):
            raise BeadsProtectedRuntimeError("runtime API manifest core identity mismatch")
        return VerifiedBeadsProtectedRuntimeApiManifestV1(payload=manifest.payload, auth=manifest.auth, record_sha256=manifest.record_sha256, full_bytes_sha256=manifest.full_bytes_sha256)


def verify_historical_beads_protected_runtime_api_manifest_v1(
    repository_locator_sha256: str,
    generation: int,
    manifest_record_sha256: str,
) -> VerifiedHistoricalBeadsProtectedRuntimeApiManifestV1:
    expected_generation = _generation(generation)
    store = _store_for_repository(repository_locator_sha256)
    with store.locked():
        manifest = _load_record(store, "BeadsProtectedRuntimeApiManifestV1", "beads-protected-runtime-api-manifest", "runtime-api-manifests", manifest_record_sha256)
        if manifest.payload.get("generation") != expected_generation:
            raise BeadsProtectedRuntimeError("historical runtime API manifest generation mismatch")
        return VerifiedHistoricalBeadsProtectedRuntimeApiManifestV1(
            payload={**_plain(manifest.payload), "historicalOnly": True},
            auth=manifest.auth,
            record_sha256=manifest.record_sha256,
            full_bytes_sha256=manifest.full_bytes_sha256,
        )


def authorize_beads_adapter_release_manifest_record_v1(
    request: AuthorizeBeadsAdapterReleaseManifestRecordRequestV1,
) -> BeadsAdapterReleaseManifestRecordCapabilityV1:
    payload = _request(request, "AuthorizeBeadsAdapterReleaseManifestRecordRequestV1")
    _required(
        payload,
        "capabilityNonce", "expiresAtUnix", "expectedCurrentFullBytesSha256",
        "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256",
    )
    _identifier(payload["capabilityNonce"], "capabilityNonce")
    _expiry(payload)
    for field in ("bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256"):
        _digest(payload[field], field)
    _digest(payload["expectedCurrentFullBytesSha256"], "expectedCurrentFullBytesSha256", nullable=True)
    store = _Store(payload)
    with store.locked():
        core = _load_change_plan_core_by_digest(
            store, "bootstrapRuntimeCoreSha256", payload["bootstrapRuntimeCoreSha256"]
        )
        if core.payload.get("adapterReleaseCoreSha256") != payload["adapterReleaseCoreSha256"]:
            raise BeadsProtectedRuntimeError("adapter release capability core pair mismatch")
        authority = _current_authority(store, require_active=False)
        if authority.payload.get("authorityState") != "revoked":
            raise BeadsProtectedRuntimeError("adapter release manifest recording requires revoked authority")
        runtime_manifest = _load_record(
            store,
            "BeadsProtectedRuntimeApiManifestV1",
            "beads-protected-runtime-api-manifest",
            "runtime-api-manifests",
            payload["runtimeApiManifestRecordSha256"],
        )
        if (
            runtime_manifest.payload.get("bootstrapRuntimeCoreSha256") != payload["bootstrapRuntimeCoreSha256"]
            or runtime_manifest.payload.get("changePlanCoreRecordSha256") != core.record_sha256
        ):
            raise BeadsProtectedRuntimeError("adapter release capability runtime/core join mismatch")
        current_path = store.directory("adapter-release-manifests") / "current.json"
        current_digest = sha256(store._read_bytes(current_path, "current adapter release manifest")) if store.exists(current_path) else None
        if current_digest != payload["expectedCurrentFullBytesSha256"]:
            raise BeadsStaleAuthorityError("adapter release manifest predecessor changed")
        return _signed_record(
            store,
            "BeadsAdapterReleaseManifestRecordCapabilityV1",
            "beads-adapter-release-manifest-record-capability",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "capabilityNonce": payload["capabilityNonce"],
                "expiresAtUnix": payload["expiresAtUnix"],
                "expectedCurrentFullBytesSha256": payload["expectedCurrentFullBytesSha256"],
                "bootstrapRuntimeCoreSha256": payload["bootstrapRuntimeCoreSha256"],
                "adapterReleaseCoreSha256": payload["adapterReleaseCoreSha256"],
                "runtimeApiManifestRecordSha256": runtime_manifest.record_sha256,
                "changePlanCoreRecordSha256": core.record_sha256,
                "revokedAuthorityRecordSha256": authority.record_sha256,
            },
            "adapter-release-manifest-capabilities",
        )


def record_beads_adapter_release_manifest_v1(
    request: RecordBeadsAdapterReleaseManifestRequestV1,
    capability: BeadsAdapterReleaseManifestRecordCapabilityV1,
) -> BeadsAdapterReleaseManifestV1:
    payload = _request(request, "RecordBeadsAdapterReleaseManifestRequestV1")
    _required(
        payload,
        "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256",
        "runtimeManifestObservations", "adapterPayloadSha256", "releaseIdentitySha256",
        "remediationEvidenceSha256",
    )
    for field in ("bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256", "adapterPayloadSha256", "releaseIdentitySha256"):
        _digest(payload[field], field)
    _digest(payload["remediationEvidenceSha256"], "remediationEvidenceSha256", nullable=True)
    observations = payload["runtimeManifestObservations"]
    if not isinstance(observations, list) or len(observations) != 3:
        raise BeadsProtectedRuntimeError("adapter release requires exact A/B/C runtime manifest observations")
    observation_fields = {
        "phase", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256",
        "runtimeApiManifestRecordSha256", "adapterPayloadSha256", "remediationEvidenceSha256",
    }
    for index, observation in enumerate(observations):
        if not isinstance(observation, Mapping) or set(observation) != observation_fields:
            raise BeadsProtectedRuntimeError("runtime manifest observation is malformed")
        if observation.get("phase") != ("A", "B", "C")[index]:
            raise BeadsProtectedRuntimeError("runtime manifest observations must be unique ordered A/B/C")
        for field in (
            "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256",
            "runtimeApiManifestRecordSha256", "adapterPayloadSha256", "remediationEvidenceSha256",
        ):
            if observation.get(field) != payload.get(field):
                raise BeadsProtectedRuntimeError(f"runtime manifest observation {index} join mismatch")
    store = _Store(payload)
    with store.locked():
        protected_capability = _load_record(
            store,
            "BeadsAdapterReleaseManifestRecordCapabilityV1",
            "beads-adapter-release-manifest-record-capability",
            "adapter-release-manifest-capabilities",
            capability.record_sha256,
        )
        intent_digest, directory = _transaction_intent(store, "record-adapter-release-manifest", payload)
        resumed = _resume_transaction_result(
            store,
            directory,
            "record-adapter-release-manifest",
            "BeadsAdapterReleaseManifestV1",
            "beads-adapter-release-manifest",
            "adapter-release-manifests",
        )
        if resumed is not None:
            return resumed
        recovered = _recover_current_transaction_result(
            store,
            directory,
            "record-adapter-release-manifest",
            "BeadsAdapterReleaseManifestV1",
            "beads-adapter-release-manifest",
            "adapter-release-manifests",
            intent_digest,
        )
        if recovered is not None:
            return recovered
        _expiry(protected_capability.payload)
        authority = _current_authority(store, require_active=False)
        if authority.payload.get("authorityState") != "revoked" or authority.record_sha256 != protected_capability.payload.get("revokedAuthorityRecordSha256"):
            raise BeadsStaleAuthorityError("adapter release capability no longer binds current revoked authority")
        for field in ("bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256"):
            if protected_capability.payload.get(field) != payload[field]:
                raise BeadsProtectedRuntimeError(f"adapter release capability {field} mismatch")
        core = _load_change_plan_core_by_digest(
            store, "bootstrapRuntimeCoreSha256", payload["bootstrapRuntimeCoreSha256"]
        )
        runtime_manifest = _load_record(
            store,
            "BeadsProtectedRuntimeApiManifestV1",
            "beads-protected-runtime-api-manifest",
            "runtime-api-manifests",
            payload["runtimeApiManifestRecordSha256"],
        )
        if (
            core.record_sha256 != protected_capability.payload.get("changePlanCoreRecordSha256")
            or core.payload.get("adapterReleaseCoreSha256") != payload["adapterReleaseCoreSha256"]
            or runtime_manifest.payload.get("bootstrapRuntimeCoreSha256") != payload["bootstrapRuntimeCoreSha256"]
            or runtime_manifest.payload.get("changePlanCoreRecordSha256") != core.record_sha256
            or core.payload.get("remediationEvidenceSha256") != payload["remediationEvidenceSha256"]
        ):
            raise BeadsProtectedRuntimeError("adapter release protected core/runtime/remediation join mismatch")
        _consume_capability(store, "adapter-release-manifest-capabilities", protected_capability, intent_digest)
        _fault("adapter-release-capability-consumed")
        current_path = store.directory("adapter-release-manifests") / "current.json"
        generation = 1
        if store.exists(current_path):
            current_envelope = store.read_json(current_path, "current adapter release manifest")
            current_body, _, _, current_full = store.verify(current_envelope, "beads-adapter-release-manifest")
            if current_full != protected_capability.payload.get("expectedCurrentFullBytesSha256"):
                raise BeadsStaleAuthorityError("adapter release manifest predecessor changed after capability issue")
            generation = _generation(current_body.get("generation")) + 1
        elif protected_capability.payload.get("expectedCurrentFullBytesSha256") is not None:
            raise BeadsStaleAuthorityError("adapter release manifest expected a missing predecessor")
        _generation(generation)
        result = _write_current(
            store,
            "BeadsAdapterReleaseManifestV1",
            "beads-adapter-release-manifest",
            "adapter-release-manifests",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "generation": generation,
                "predecessorCurrentFullBytesSha256": protected_capability.payload.get("expectedCurrentFullBytesSha256"),
                "capabilityRecordSha256": protected_capability.record_sha256,
                "bootstrapRuntimeCoreSha256": payload["bootstrapRuntimeCoreSha256"],
                "adapterReleaseCoreSha256": payload["adapterReleaseCoreSha256"],
                "runtimeApiManifestRecordSha256": payload["runtimeApiManifestRecordSha256"],
                "changePlanCoreRecordSha256": core.record_sha256,
                "runtimeManifestObservations": observations,
                "adapterPayloadSha256": payload["adapterPayloadSha256"],
                "releaseIdentitySha256": payload["releaseIdentitySha256"],
                "remediationEvidenceSha256": payload.get("remediationEvidenceSha256"),
                "transactionIntentSha256": intent_digest,
            },
            protected_capability.payload.get("expectedCurrentFullBytesSha256"),
        )
        _fault("adapter-release-current-written")
        _transaction_receipt(store, directory, "record-adapter-release-manifest", result)
        return result


def verify_current_beads_adapter_release_manifest_v1(
    request: VerifyBeadsAdapterReleaseManifestRequestV1,
) -> VerifiedBeadsAdapterReleaseManifestV1:
    payload = _request(request, "VerifyBeadsAdapterReleaseManifestRequestV1")
    _required(payload, "expectedManifestRecordSha256", "expectedRuntimeApiManifestRecordSha256", "expectedReleaseIdentitySha256")
    store = _Store(payload)
    with store.locked():
        manifest = _load_current(store, "BeadsAdapterReleaseManifestV1", "beads-adapter-release-manifest", "adapter-release-manifests")
        if manifest.record_sha256 != payload["expectedManifestRecordSha256"]:
            raise BeadsStaleAuthorityError("current adapter release manifest record changed")
        if manifest.payload.get("runtimeApiManifestRecordSha256") != payload["expectedRuntimeApiManifestRecordSha256"] or manifest.payload.get("releaseIdentitySha256") != payload["expectedReleaseIdentitySha256"]:
            raise BeadsProtectedRuntimeError("adapter release manifest expected identity mismatch")
        core = _load_change_plan_core_by_digest(
            store, "bootstrapRuntimeCoreSha256", manifest.payload.get("bootstrapRuntimeCoreSha256")
        )
        runtime_manifest = _load_record(
            store,
            "BeadsProtectedRuntimeApiManifestV1",
            "beads-protected-runtime-api-manifest",
            "runtime-api-manifests",
            manifest.payload.get("runtimeApiManifestRecordSha256"),
        )
        if (
            core.record_sha256 != manifest.payload.get("changePlanCoreRecordSha256")
            or core.payload.get("adapterReleaseCoreSha256") != manifest.payload.get("adapterReleaseCoreSha256")
            or core.payload.get("remediationEvidenceSha256") != manifest.payload.get("remediationEvidenceSha256")
            or runtime_manifest.payload.get("bootstrapRuntimeCoreSha256") != manifest.payload.get("bootstrapRuntimeCoreSha256")
            or runtime_manifest.payload.get("changePlanCoreRecordSha256") != core.record_sha256
        ):
            raise BeadsProtectedRuntimeError("current adapter release independently reproduced core/runtime join mismatch")
        observations = manifest.payload.get("runtimeManifestObservations")
        if not isinstance(observations, (list, tuple)) or [item.get("phase") for item in observations if isinstance(item, Mapping)] != ["A", "B", "C"]:
            raise BeadsProtectedRuntimeError("current adapter release lacks unique complete A/B/C observations")
        expected_fields = {
            "phase", "bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256",
            "runtimeApiManifestRecordSha256", "adapterPayloadSha256", "remediationEvidenceSha256",
        }
        for observation in observations:
            if not isinstance(observation, Mapping) or set(observation) != expected_fields:
                raise BeadsProtectedRuntimeError("current adapter release observation schema mismatch")
            for field in expected_fields - {"phase"}:
                if observation.get(field) != manifest.payload.get(field):
                    raise BeadsProtectedRuntimeError("current adapter release observation join mismatch")
        return VerifiedBeadsAdapterReleaseManifestV1(payload=manifest.payload, auth=manifest.auth, record_sha256=manifest.record_sha256, full_bytes_sha256=manifest.full_bytes_sha256)


__all__ = [
    "BEADS_BASELINE_COMMIT",
    "BeadsProtectedRuntimeError",
    "BeadsStaleAuthorityError",
    "BeadsCapabilityConsumedError",
    "beads_protected_runtime_schema_v1",
    "canonical_bytes",
    "sha256",
    "use_beads_protected_runtime_v1",
    *_TYPE_NAMES,
    *_FUNCTION_EXPORTS,
]
