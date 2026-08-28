"""Fixed Linux controller protocol for protected Beads runtime authority.

The production client deliberately has no configuration, endpoint, key, or
verifier parameter.  It reads one root-owned closed configuration and connects
to one root-owned AF_UNIX SOCK_SEQPACKET endpoint.  Stored controller receipts
are evidence only: callers must validate them through a fresh authenticated
connection before using current authority.
"""

from __future__ import annotations

import argparse
import array
import base64
import ctypes
import dataclasses
import errno
import fcntl
import grp
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import select
import signal
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any, Final, Mapping

from . import beads_native_boundary_v27 as native_boundary_v27


CONFIG_PATH: Final = Path("/etc/startup-factory/beads-boundary-controller-v1.json")
ENDPOINT_PATH: Final = Path("/run/startup-factory/beads-boundary-controller-v1.sock")
STATE_ROOT: Final = Path("/var/lib/startup-factory/beads-boundary-controller/v1")
REPOSITORY_HANDOFF_ROOT_V27: Final = Path(
    "/var/lib/startup-factory/beads-handoff"
)
CONTROLLER_KEY_PATH: Final = Path("/etc/startup-factory/beads-boundary-controller-v1.key")
OPERATOR_KEY_PATH: Final = Path("/etc/startup-factory/beads-local-operator-v1.key")
OPERATOR_STATE_PATH: Final = Path("/etc/startup-factory/beads-local-operator-v1.state.json")
PROTOCOL: Final = "startup-factory/beads-boundary-controller/v1"
PRODUCTION_PROVENANCE: Final = "startup-factory/beads-boundary-controller/production/v1"
MAX_MESSAGE_BYTES: Final = 1_048_576
MAX_CLOCK_SKEW_SECONDS: Final = 30
MAX_OPERATION_SECONDS: Final = 300
CONNECTION_DEADLINE_SECONDS: Final = 5.0
LISTEN_BACKLOG: Final = 128
_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_NONCE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9._:-]{15,255}\Z")
_OPERATION_ID = re.compile(r"\A[0-9a-f]{64}\Z")
_HMAC = re.compile(r"\Ahmac-sha256:[0-9a-f]{64}\Z")
_EMPTY_SHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_OPERATOR_HMAC_DOMAIN: Final = b"startup-factory/beads/local-operator-state/v1\0"
_WORKER_PROTOCOL: Final = "startup-factory/beads-native-worker/v27"
_WORKER_WAIT_SECONDS: Final = 150.0
_WORKER_RESULT_SELINUX_CONTEXT_V27: Final = (
    b"system_u:object_r:beads_runtime_result_t:s0"
)
_WORKER_STATUS_MAX_BYTES_V27: Final = 65_536
_WORKER_CGROUP_ROLES_V27: Final = (
    "worker-directory",
    "payload-directory",
    "payload-events",
    "payload-kill",
)
_CGROUP2_SUPER_MAGIC_V27: Final = 0x63677270
_SUPERVISOR_CGROUP_MODE_V27: Final = 0o2710
_WORKER_CGROUP_MODE_V27: Final = 0o700
_PAYLOAD_CGROUP_MODE_V27: Final = 0o2710
_LIFECYCLE_CGROUP_MODE_V27: Final = 0o770
_DELEGATED_CONTROLLERS_V27: Final = ("cpu", "memory", "pids")
_SPLIT_RUNTIME_MODE_V27: Final = 0o750
_SPLIT_PAYLOAD_MODE_V27: Final = 0o755
_SPLIT_PAYLOAD_NAME_V27 = re.compile(r"\Alibpod-payload-[0-9a-f]{64}\Z")
_CGROUP_STAT_CONTROLLER_V27 = re.compile(r"\A[a-z][a-z0-9_]{0,31}\Z")
_CGROUP_RETIRE_RETRIES_V27: Final = 20
_CGROUP_DYING_QUIESCENCE_SECONDS_V27: Final = 5.0
_RESULT_ARENA_CONTROLLER_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/controller-result-arena\0"
)
_RETIREMENT_CONTROLLER_DOMAINS_V27: Final = {
    "intent": b"startup-factory/beads/v27/controller-retirement-intent\0",
    "receipt": b"startup-factory/beads/v27/controller-retirement-receipt\0",
}
_WORKER_RESULT_OFFER_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/worker-result-offer\0"
)
_WORKER_RESULT_OFFER_ACK_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/worker-result-offer-ack\0"
)
_WORKER_PRE_EFFECT_FAILURE_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/worker-launch-pre-effect-failed\0"
)
_WORKER_LAUNCH_UNRESOLVED_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/worker-launch-unresolved\0"
)
_CONTROLLER_PRE_EFFECT_PROOF_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/controller-launch-pre-effect-proof\0"
)
_REPOSITORY_CUSTODY_RELEASE_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/repository-custody-release\0"
)

ALLOWED_OPERATIONS: Final = (
    "prepare_atomic_claim_v1",
    "advance_atomic_claim_v1",
    "record_atomic_claim_receipt_v1",
    "authorize_claim_launch_v1",
    "begin_beads_mutation_v1",
    "finish_beads_mutation_v1",
    "verify_beads_installed_database_selector_v1",
    "authorize_beads_preparation_v1",
    "begin_beads_preparation_v1",
    "observe_beads_store_v1",
    "advance_beads_preparation_v1",
    "derive_beads_status_profile_dynamic_bindings_v1",
    "finish_beads_preparation_v1",
    "verify_current_beads_preparation_v1",
    "verify_historical_beads_preparation_v1",
    "record_beads_change_plan_core_v1",
    "verify_beads_change_plan_core_record_v1",
    "authorize_beads_authority_transition_v1",
    "revoke_beads_authority_epoch_v1",
    "stage_beads_authority_epoch_v1",
    "activate_beads_authority_epoch_v1",
    "verify_active_beads_authority_v1",
    "verify_beads_authority_transition_receipt_v1",
    "authorize_beads_runtime_api_manifest_record_v1",
    "record_beads_protected_runtime_api_manifest_v1",
    "verify_current_beads_protected_runtime_api_manifest_v1",
    "verify_historical_beads_protected_runtime_api_manifest_v1",
    "authorize_beads_adapter_release_manifest_record_v1",
    "record_beads_adapter_release_manifest_v1",
    "verify_current_beads_adapter_release_manifest_v1",
)

_CONFIG_FIELDS = {
    "beadsEnabled",
    "schemaVersion",
    "protocol",
    "endpointPath",
    "stateRoot",
    "controllerKeyPath",
    "protectedRoot",
    "recordHmacKeyPath",
    "controllerUid",
    "brokerUid",
    "workerUid",
    "transportGid",
    "runtimeManifestPath",
    "modulePath",
    "schemaPath",
    "runtimeManifestSha256",
    "moduleSha256",
    "schemaSha256",
    "nativeBoundaryManifestPath",
    "nativeBoundaryManifestSha256",
    "nativeModulePath",
    "nativeModuleSha256",
    "configEpoch",
    "keyEpoch",
    "allowedOperations",
}
_REQUEST_FIELDS = {"schemaVersion", "protocol", "action", "request"}
_OPEN_FIELDS = {
    "operationId",
    "clientNonce",
    "operation",
    "repositoryLocatorSha256",
    "rootSetSha256",
    "requestSha256",
    "runtimeManifestSha256",
    "moduleSha256",
    "schemaSha256",
    "configEpoch",
    "keyEpoch",
    "issuedAtUnix",
    "expiresAtUnix",
}
_STEP_FIELDS = {
    "operationId",
    "sessionNonce",
    "stepNonce",
    "predecessorReceiptSha256",
    "targetState",
    "transactionIntentSha256",
    "resultSha256",
}
_VALIDATE_FIELDS = {
    "operationId",
    "validationNonce",
    "storedReceiptSha256",
    "expectedState",
    "expectedResultSha256",
}
_RECOVER_FIELDS = {
    "operationId",
    "recoveryNonce",
    "recoveryPhase",
    "operation",
    "repositoryLocatorSha256",
    "rootSetSha256",
    "requestSha256",
    "transactionIntentSha256",
    "runtimeManifestSha256",
    "moduleSha256",
    "schemaSha256",
    "configEpoch",
    "keyEpoch",
    "sessionNonce",
    "predecessorReceiptSha256",
    "effectAuthorizationReceiptSha256",
    "publicationIntentSha256",
    "recoveryResultSha256",
}
_EXECUTE_FIELDS = {
    "operationId",
    "sessionNonce",
    "executionNonce",
    "predecessorReceiptSha256",
    "authorizationRecordSha256",
}
_RESPONSE_FIELDS = {
    "schemaVersion",
    "protocol",
    "action",
    "provenanceDomain",
    "status",
    "state",
    "requestSha256",
    "operationId",
    "sessionNonce",
    "resultSha256",
    "controllerHmac",
    "receiptSha256",
}
_RECOVERY_RESPONSE_EXTRA_FIELDS = {
    "effectAuthorizationReceiptSha256",
    "operationExpiresAtUnix",
    "recoveryPublicationIntentSha256",
}
_EXECUTE_RESPONSE_EXTRA_FIELDS = {"nativeResult"}
_NORMAL_STATES = (
    "accepted",
    "intent-bound",
    "effect-authorized",
    "result-stored",
    "completed",
)
_RECOVERY_STATES = (
    "publication-recovery-authorized",
    "publication-recovered",
)
_STATES = _NORMAL_STATES + _RECOVERY_STATES


class ControllerProtocolError(RuntimeError):
    """A fixed controller/config/protocol invariant failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise ControllerProtocolError(f"controller value is not canonical JSON: {exc}") from exc
    if not encoded or len(encoded) > MAX_MESSAGE_BYTES:
        raise ControllerProtocolError("controller message is empty or oversized")
    return encoded


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _controller_result_arena_envelope_v27(
    preparation: Mapping[str, Any], plan: Mapping[str, Any],
    request_key: bytes, controller_key: bytes,
) -> dict[str, Any]:
    try:
        verified = native_boundary_v27._validate_result_arena_request_v27(
            preparation, plan, request_key
        )
    except native_boundary_v27.NativeBoundaryV27Error as exc:
        raise ControllerProtocolError(str(exc)) from exc
    unsigned = {
        "arena": verified["arena"],
        "requestKeyHmac": verified["requestKeyHmac"],
    }
    return {
        **unsigned,
        "controllerHmac": "hmac-sha256:" + hmac.new(
            controller_key,
            _RESULT_ARENA_CONTROLLER_DOMAIN_V27 + _canonical(unsigned),
            hashlib.sha256,
        ).hexdigest(),
    }


def _verify_controller_result_arena_v27(
    value: Any, controller_key: bytes, *, payload_name: str,
    stage_plan_sha256: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "arena", "requestKeyHmac", "controllerHmac"
    } or not isinstance(value["arena"], Mapping):
        raise ControllerProtocolError(
            "controller-authenticated result arena shape changed"
        )
    unsigned = {
        "arena": dict(value["arena"]),
        "requestKeyHmac": value["requestKeyHmac"],
    }
    expected = "hmac-sha256:" + hmac.new(
        controller_key,
        _RESULT_ARENA_CONTROLLER_DOMAIN_V27 + _canonical(unsigned),
        hashlib.sha256,
    ).hexdigest()
    arena = unsigned["arena"]
    if (
        not hmac.compare_digest(str(value["controllerHmac"]), expected)
        or arena.get("payloadName") != payload_name
        or arena.get("stagePlanSha256") != stage_plan_sha256
        or not isinstance(arena.get("operationLock"), Mapping)
        or not isinstance(arena.get("resultDirectory"), Mapping)
    ):
        raise ControllerProtocolError(
            "controller-authenticated result arena binding changed"
        )
    return {**unsigned, "controllerHmac": expected}


def _controller_retirement_envelope_v27(
    *, kind: str, plan: Mapping[str, Any], payload_name: str,
    payload_identity: Mapping[str, Any], arena_record_sha256: str,
    predecessor_artifact_sha256: str | None, body: Mapping[str, Any],
    controller_key: bytes,
) -> dict[str, Any]:
    if kind not in _RETIREMENT_CONTROLLER_DOMAINS_V27:
        raise ControllerProtocolError("controller retirement artifact kind changed")
    artifact = {
        "schemaVersion": 27,
        "kind": kind,
        "operationId": plan["operationId"],
        "stageLocation": plan["stageLocation"],
        "stagePlanSha256": plan["stagePlanSha256"],
        "requestKeyId": plan["requestKeyId"],
        "payloadName": payload_name,
        "payloadIdentity": dict(payload_identity),
        "arenaRecordSha256": arena_record_sha256,
        "predecessorArtifactSha256": predecessor_artifact_sha256,
        "body": dict(body),
    }
    return {
        "artifact": artifact,
        "controllerHmac": "hmac-sha256:" + hmac.new(
            controller_key,
            _RETIREMENT_CONTROLLER_DOMAINS_V27[kind] + _canonical(artifact),
            hashlib.sha256,
        ).hexdigest(),
    }


def _verify_controller_retirement_envelope_v27(
    value: Any, *, kind: str, controller_key: bytes, payload_name: str,
    stage_plan_sha256: str, arena_record_sha256: str,
    predecessor_artifact_sha256: str | None,
) -> tuple[dict[str, Any], str]:
    if (
        kind not in _RETIREMENT_CONTROLLER_DOMAINS_V27
        or not isinstance(value, Mapping)
        or set(value) != {"artifact", "controllerHmac"}
        or not isinstance(value["artifact"], Mapping)
    ):
        raise ControllerProtocolError(
            "controller retirement authentication envelope changed"
        )
    artifact = dict(value["artifact"])
    if set(artifact) != {
        "schemaVersion", "kind", "operationId", "stageLocation",
        "stagePlanSha256", "requestKeyId", "payloadName", "payloadIdentity",
        "arenaRecordSha256", "predecessorArtifactSha256", "body",
    }:
        raise ControllerProtocolError(
            "controller retirement authentication fields changed"
        )
    expected = "hmac-sha256:" + hmac.new(
        controller_key,
        _RETIREMENT_CONTROLLER_DOMAINS_V27[kind] + _canonical(artifact),
        hashlib.sha256,
    ).hexdigest()
    if (
        artifact["schemaVersion"] != 27
        or artifact["kind"] != kind
        or artifact["payloadName"] != payload_name
        or artifact["stagePlanSha256"] != stage_plan_sha256
        or artifact["arenaRecordSha256"] != arena_record_sha256
        or artifact["predecessorArtifactSha256"]
        != predecessor_artifact_sha256
        or not hmac.compare_digest(str(value["controllerHmac"]), expected)
    ):
        raise ControllerProtocolError(
            "controller retirement authentication binding changed"
        )
    try:
        if kind == "intent":
            body = native_boundary_v27._decode_controller_retirement_intent_v27(
                artifact["body"]
            )
            if artifact["payloadIdentity"] != body["payloadIdentity"]:
                raise ControllerProtocolError(
                    "controller retirement intent payload identity changed"
                )
        else:
            raw_body = artifact["body"]
            if not isinstance(raw_body, Mapping):
                raise ControllerProtocolError(
                    "controller retirement receipt body changed"
                )
            body = native_boundary_v27._decode_controller_retirement_v27(
                raw_body, raw_body.get("placementMask")
            )
        native_boundary_v27._retirement_payload_identity_v27(
            artifact["payloadIdentity"]
        )
    except native_boundary_v27.NativeBoundaryV27Error as exc:
        raise ControllerProtocolError(str(exc)) from exc
    envelope = {"artifact": artifact, "controllerHmac": expected}
    return body, _sha(_canonical(envelope))


def _verify_controller_retirement_chain_v27(
    value: Any,
    *,
    plan: Mapping[str, Any],
    request_key: bytes,
    controller_key: bytes,
    expected_placement_mask: int | None,
) -> dict[str, Any]:
    """Verify the controller-only arena -> intent -> receipt authority chain."""

    if not isinstance(value, Mapping) or set(value) != {
        "arena", "intent", "receipt"
    }:
        raise ControllerProtocolError(
            "controller retirement recovery chain shape changed"
        )
    payload_name = _payload_cgroup_name_v27(plan)
    arena_value = value["arena"]
    arena = _verify_controller_result_arena_v27(
        arena_value,
        controller_key,
        payload_name=payload_name,
        stage_plan_sha256=plan["stagePlanSha256"],
    )
    try:
        request_verified = native_boundary_v27._validate_result_arena_request_v27(
            {
                "arena": arena["arena"],
                "requestKeyHmac": arena["requestKeyHmac"],
            },
            plan,
            request_key,
        )
    except native_boundary_v27.NativeBoundaryV27Error as exc:
        raise ControllerProtocolError(str(exc)) from exc
    arena_body = request_verified["arena"]
    if (
        arena_body.get("operationId") != plan["operationId"]
        or arena_body.get("stageLocation") != plan["stageLocation"]
        or arena_body.get("stagePlanSha256") != plan["stagePlanSha256"]
        or arena_body.get("requestKeyId") != plan["requestKeyId"]
        or arena_body.get("payloadName") != payload_name
    ):
        raise ControllerProtocolError(
            "controller retirement recovery arena differs from the stage plan"
        )
    arena_sha256 = _sha(_canonical(dict(arena_value)))
    intent, intent_sha256 = _verify_controller_retirement_envelope_v27(
        value["intent"],
        kind="intent",
        controller_key=controller_key,
        payload_name=payload_name,
        stage_plan_sha256=plan["stagePlanSha256"],
        arena_record_sha256=arena_sha256,
        predecessor_artifact_sha256=None,
    )
    receipt, _receipt_sha256 = _verify_controller_retirement_envelope_v27(
        value["receipt"],
        kind="receipt",
        controller_key=controller_key,
        payload_name=payload_name,
        stage_plan_sha256=plan["stagePlanSha256"],
        arena_record_sha256=arena_sha256,
        predecessor_artifact_sha256=intent_sha256,
    )
    intent_artifact = value["intent"]["artifact"]
    receipt_artifact = value["receipt"]["artifact"]
    for label, artifact in (
        ("intent", intent_artifact),
        ("receipt", receipt_artifact),
    ):
        if (
            artifact["operationId"] != plan["operationId"]
            or artifact["stageLocation"] != plan["stageLocation"]
            or artifact["stagePlanSha256"] != plan["stagePlanSha256"]
            or artifact["requestKeyId"] != plan["requestKeyId"]
            or artifact["payloadName"] != payload_name
        ):
            raise ControllerProtocolError(
                f"controller retirement {label} differs from the stage plan"
            )
    if (
        intent_artifact["payloadIdentity"] != intent["payloadIdentity"]
        or receipt_artifact["payloadIdentity"] != intent["payloadIdentity"]
        or receipt["visibleDescendants"] != intent["visibleDescendants"]
        or receipt["placementMask"] != intent["placementMask"]
        or receipt["controllerTrackedPlacementMask"]
        != intent["placementMask"]
        or receipt["initControllers"] != intent["initControllers"]
        or receipt["preRemovalCgroupStat"] != intent["preRemovalCgroupStat"]
        or receipt["terminalCgroupStat"]["nr_descendants"] != 0
        or (
            expected_placement_mask is not None
            and receipt["placementMask"] != expected_placement_mask
        )
    ):
        raise ControllerProtocolError(
            "controller retirement recovery chain bodies differ"
        )
    return receipt


def _controller_pre_effect_proof_envelope_v27(
    *,
    plan: Mapping[str, Any],
    payload_name: str,
    arena_record_sha256: str,
    consumed_current_record_sha256: str,
    worker_failure: Mapping[str, Any],
    first_empty_observation: Mapping[str, Any],
    second_empty_observation: Mapping[str, Any],
    controller_retirement: Mapping[str, Any],
    controller_key: bytes,
) -> dict[str, Any]:
    """Authenticate the exact no-launch proof with a controller-only key."""

    retirement_sha256 = _sha(_canonical(dict(controller_retirement)))
    proof = {
        "schemaVersion": 27,
        "operationId": plan["operationId"],
        "stageLocation": plan["stageLocation"],
        "stagePlanSha256": plan["stagePlanSha256"],
        "requestKeyId": plan["requestKeyId"],
        "payloadName": payload_name,
        "arenaRecordSha256": arena_record_sha256,
        "consumedCurrentRecordSha256": consumed_current_record_sha256,
        "workerFailure": dict(worker_failure),
        "firstEmptyObservation": dict(first_empty_observation),
        "secondEmptyObservation": dict(second_empty_observation),
        "controllerRetirement": dict(controller_retirement),
        "controllerRetirementSha256": retirement_sha256,
    }
    return {
        "proof": proof,
        "controllerHmac": "hmac-sha256:" + hmac.new(
            controller_key,
            _CONTROLLER_PRE_EFFECT_PROOF_DOMAIN_V27 + _canonical(proof),
            hashlib.sha256,
        ).hexdigest(),
    }


def _verify_controller_pre_effect_proof_v27(
    value: Any,
    *,
    plan: Mapping[str, Any],
    controller_key: bytes,
    arena_record_sha256: str,
    retirement: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a relayed proof; the worker never establishes its authority."""

    if (
        not isinstance(value, Mapping)
        or set(value) != {"proof", "controllerHmac"}
        or not isinstance(value["proof"], Mapping)
    ):
        raise ControllerProtocolError(
            "controller pre-effect proof envelope changed"
        )
    proof = dict(value["proof"])
    if set(proof) != {
        "schemaVersion", "operationId", "stageLocation",
        "stagePlanSha256", "requestKeyId", "payloadName",
        "arenaRecordSha256", "consumedCurrentRecordSha256",
        "workerFailure", "firstEmptyObservation", "secondEmptyObservation",
        "controllerRetirement", "controllerRetirementSha256",
    }:
        raise ControllerProtocolError("controller pre-effect proof fields changed")
    expected_hmac = "hmac-sha256:" + hmac.new(
        controller_key,
        _CONTROLLER_PRE_EFFECT_PROOF_DOMAIN_V27 + _canonical(proof),
        hashlib.sha256,
    ).hexdigest()
    worker_failure = proof["workerFailure"]
    first_empty = proof["firstEmptyObservation"]
    second_empty = proof["secondEmptyObservation"]
    retirement_sha256 = _sha(_canonical(dict(retirement)))
    if (
        proof["schemaVersion"] != 27
        or proof["operationId"] != plan["operationId"]
        or proof["stageLocation"] != plan["stageLocation"]
        or proof["stagePlanSha256"] != plan["stagePlanSha256"]
        or proof["requestKeyId"] != plan["requestKeyId"]
        or proof["payloadName"] != _payload_cgroup_name_v27(plan)
        or proof["arenaRecordSha256"] != arena_record_sha256
        or not isinstance(proof["consumedCurrentRecordSha256"], str)
        or not _DIGEST.fullmatch(proof["consumedCurrentRecordSha256"])
        or not isinstance(worker_failure, Mapping)
        or set(worker_failure) != {"evidenceSha256", "classification"}
        or not isinstance(first_empty, Mapping)
        or first_empty != second_empty
        or first_empty.get("schemaVersion") != 27
        or first_empty.get("knownNoChild") is not True
        or first_empty.get("placementMask") != 0
        or proof["controllerRetirement"] != dict(retirement)
        or proof["controllerRetirementSha256"] != retirement_sha256
        or retirement.get("placementMask") != 0
        or not hmac.compare_digest(str(value["controllerHmac"]), expected_hmac)
    ):
        raise ControllerProtocolError(
            "controller pre-effect proof authentication or binding changed"
        )
    return proof


def _closed_mapping(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ControllerProtocolError(f"{label} has an unknown or missing field")
    return value


def _digest(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ControllerProtocolError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _installed_digest(value: Any, label: str) -> str:
    observed = _digest(value, label)
    assert observed is not None
    hexadecimal = observed.removeprefix("sha256:")
    if observed == _EMPTY_SHA256 or len(set(hexadecimal)) == 1:
        raise ControllerProtocolError(f"{label} is a forbidden sentinel digest")
    return observed


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ControllerProtocolError(f"{label} must be a non-empty string")
    return value


def _nonce(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _NONCE.fullmatch(value):
        raise ControllerProtocolError(f"{label} is invalid")
    return value


def _operation_id(value: Any, label: str = "operationId") -> str:
    if not isinstance(value, str) or not _OPERATION_ID.fullmatch(value):
        raise ControllerProtocolError(f"{label} is invalid")
    return value


def _absolute_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ControllerProtocolError(f"{label} must be a normalized absolute path")
    path = Path(value)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ControllerProtocolError(f"{label} must be a normalized absolute path")
    return path


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 99_999_999_999_999_999_999:
        raise ControllerProtocolError(f"{label} must be a bounded positive integer")
    return value


@dataclasses.dataclass(frozen=True, slots=True)
class ControllerConfig:
    beads_enabled: bool
    protected_root: Path
    record_hmac_key_path: Path
    controller_uid: int
    broker_uid: int
    worker_uid: int
    transport_gid: int
    runtime_manifest_path: Path
    module_path: Path
    schema_path: Path
    runtime_manifest_sha256: str
    module_sha256: str
    schema_sha256: str
    config_epoch: int
    key_epoch: int
    native_boundary_manifest_path: Path
    native_boundary_manifest_sha256: str
    native_module_path: Path
    native_module_sha256: str

    @property
    def root_set_sha256(self) -> str:
        return _sha(_canonical({
            "beadsEnabled": self.beads_enabled,
            "protectedRoot": str(self.protected_root),
            "recordHmacKeyPath": str(self.record_hmac_key_path),
            "nativeBoundaryManifestPath": str(self.native_boundary_manifest_path),
            "nativeBoundaryManifestSha256": self.native_boundary_manifest_sha256,
            "nativeModulePath": str(self.native_module_path),
            "nativeModuleSha256": self.native_module_sha256,
        }))


def _operator_state_auth(payload: Mapping[str, Any], operator_key: bytes) -> str:
    if not isinstance(operator_key, bytes) or not 32 <= len(operator_key) <= 4096:
        raise ControllerProtocolError(
            "local operator key must contain 32..4096 bytes"
        )
    return "hmac-sha256:" + hmac.new(
        operator_key,
        _OPERATOR_HMAC_DOMAIN + _canonical(dict(payload)),
        hashlib.sha256,
    ).hexdigest()


def _read_operator_key(path: Path = OPERATOR_KEY_PATH) -> bytes:
    try:
        metadata = os.lstat(path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ControllerProtocolError(
                "local operator key must be a root-owned mode-0600 single-link file"
            )
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_nlink,
                opened.st_size,
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_nlink,
                metadata.st_size,
            ):
                raise ControllerProtocolError("local operator key changed before open")
            key = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot read local operator key: {exc}") from exc
    if not 32 <= len(key) <= 4096:
        raise ControllerProtocolError("local operator key must contain 32..4096 bytes")
    return key


def _read_operator_state_v1(
    config: ControllerConfig,
    operator_key: bytes,
    *,
    state_path: Path = OPERATOR_STATE_PATH,
    missing_ok: bool = False,
) -> tuple[dict[str, Any], bytes] | None:
    try:
        descriptor = os.open(
            state_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ControllerProtocolError(
            "local operator Apply has not produced authenticated activation state"
        )
    except OSError as exc:
        raise ControllerProtocolError(f"cannot open local operator state: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        expected_owner = 0 if state_path == OPERATOR_STATE_PATH else os.getuid()
        expected_group = (
            config.transport_gid if state_path == OPERATOR_STATE_PATH else metadata.st_gid
        )
        expected_mode = 0o640 if state_path == OPERATOR_STATE_PATH else 0o600
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_owner
            or metadata.st_gid != expected_group
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_size <= 0
            or metadata.st_size > MAX_MESSAGE_BYTES
        ):
            raise ControllerProtocolError("local operator state metadata is unsafe")
        raw = os.read(descriptor, metadata.st_size + 1)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("local operator state is malformed") from exc
    if raw != _canonical(value) or not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "payload",
        "auth",
    }:
        raise ControllerProtocolError("local operator state is not canonical schema v1")
    payload = value["payload"]
    if not isinstance(payload, dict) or set(payload) != {
        "configEpoch",
        "generation",
        "operatorState",
        "predecessorStateSha256",
        "rootSetSha256",
        "transition",
    }:
        raise ControllerProtocolError("local operator state payload is not closed")
    if (
        value["schemaVersion"] != 1
        or value["auth"] != _operator_state_auth(payload, operator_key)
    ):
        raise ControllerProtocolError("local operator state authentication failed")
    if (
        payload["rootSetSha256"] != config.root_set_sha256
        or payload["configEpoch"] != config.config_epoch
        or type(payload["generation"]) is not int
        or payload["generation"] < 1
        or payload["operatorState"] not in {"active", "disabled"}
    ):
        raise ControllerProtocolError("local operator state configuration binding changed")
    return dict(value), raw


def verify_operator_lifecycle_v1(
    config: ControllerConfig,
    operator_key: bytes,
    *,
    state_path: Path = OPERATOR_STATE_PATH,
    require_active: bool = False,
) -> dict[str, Any]:
    observed = _read_operator_state_v1(
        config, operator_key, state_path=state_path
    )
    assert observed is not None
    state = observed[0]
    if require_active and state["payload"]["operatorState"] != "active":
        raise ControllerProtocolError("local operator state is not active")
    if require_active and not config.beads_enabled:
        raise ControllerProtocolError("Beads configuration remains disabled")
    return dict(state["payload"])


def preview_operator_lifecycle_v1(
    config: ControllerConfig,
    action: str,
    *,
    state_path: Path = OPERATOR_STATE_PATH,
    operator_key: bytes | None = None,
) -> dict[str, Any]:
    if action not in {"apply", "disable", "reactivate"}:
        raise ControllerProtocolError("local operator action is invalid")
    if operator_key is None:
        operator_key = _read_operator_key()
    current = _read_operator_state_v1(
        config, operator_key, state_path=state_path, missing_ok=True
    )
    if current is None:
        current_state = None
        generation = 1
        predecessor = None
    else:
        current_state = current[0]["payload"]["operatorState"]
        generation = int(current[0]["payload"]["generation"]) + 1
        predecessor = _sha(current[1])
    target = "active" if action in {"apply", "reactivate"} else "disabled"
    if (
        (action == "apply" and current_state is not None)
        or (action == "disable" and current_state != "active")
        or (action == "reactivate" and current_state != "disabled")
    ):
        raise ControllerProtocolError(
            "local operator transition is not the unique lifecycle successor"
        )
    plan = {
        "schemaVersion": 1,
        "action": action,
        "configEnabled": config.beads_enabled,
        "configEpoch": config.config_epoch,
        "rootSetSha256": config.root_set_sha256,
        "generation": generation,
        "predecessorStateSha256": predecessor,
        "targetState": target,
    }
    return {**plan, "planDigest": _sha(_canonical(plan))}


def apply_operator_lifecycle_v1(
    config: ControllerConfig,
    action: str,
    plan_digest: str,
    *,
    operator_key: bytes | None = None,
    state_path: Path = OPERATOR_STATE_PATH,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise ControllerProtocolError(
            "local operator lifecycle changes require the authenticated root operator"
        )
    if operator_key is None:
        operator_key = _read_operator_key()
    preview = preview_operator_lifecycle_v1(
        config, action, state_path=state_path, operator_key=operator_key
    )
    if plan_digest != preview["planDigest"]:
        raise ControllerProtocolError("local operator plan digest changed before Apply")
    if action in {"apply", "reactivate"} and not config.beads_enabled:
        raise ControllerProtocolError("Beads configuration remains disabled")
    payload = {
        "configEpoch": config.config_epoch,
        "generation": preview["generation"],
        "operatorState": preview["targetState"],
        "predecessorStateSha256": preview["predecessorStateSha256"],
        "rootSetSha256": config.root_set_sha256,
        "transition": action,
    }
    envelope = {
        "schemaVersion": 1,
        "payload": payload,
        "auth": _operator_state_auth(payload, operator_key),
    }
    raw = _canonical(envelope)
    if not state_path.is_absolute() or str(state_path) != os.path.normpath(
        str(state_path)
    ):
        raise ControllerProtocolError("local operator state path is not absolute")
    parent = os.open(
        state_path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary_leaf: str | None = None
    installed = False
    try:
        parent_info = os.fstat(parent)
        expected_parent_uid = 0 if state_path == OPERATOR_STATE_PATH else os.getuid()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != expected_parent_uid
            or stat.S_IMODE(parent_info.st_mode) & 0o022
        ):
            raise ControllerProtocolError(
                "local operator state parent is not an exact private trusted directory"
            )
        current = _read_operator_state_v1(
            config,
            operator_key,
            state_path=state_path,
            missing_ok=True,
        )
        current_raw = None if current is None else current[1]
        expected_predecessor = preview["predecessorStateSha256"]
        if (
            (current_raw is None and expected_predecessor is not None)
            or (
                current_raw is not None
                and _sha(current_raw) != expected_predecessor
            )
        ):
            raise ControllerProtocolError(
                "local operator state predecessor changed before Apply"
            )
        temporary_leaf = (
            f".{state_path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
        )
        descriptor = os.open(
            temporary_leaf,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent,
        )
        try:
            if state_path == OPERATOR_STATE_PATH:
                os.fchown(descriptor, 0, config.transport_gid)
                os.fchmod(descriptor, 0o640)
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        rebound = _read_operator_state_v1(
            config,
            operator_key,
            state_path=state_path,
            missing_ok=True,
        )
        rebound_raw = None if rebound is None else rebound[1]
        if rebound_raw != current_raw:
            raise ControllerProtocolError(
                "local operator state changed concurrently before Apply"
            )
        os.replace(
            temporary_leaf,
            state_path.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
        )
        installed = True
        os.fsync(parent)
    finally:
        if temporary_leaf is not None and not installed:
            try:
                os.unlink(temporary_leaf, dir_fd=parent)
            except FileNotFoundError:
                pass
        os.close(parent)
    return verify_operator_lifecycle_v1(
        config, operator_key, state_path=state_path
    )


def _parse_config(value: Any) -> ControllerConfig:
    data = _closed_mapping(value, _CONFIG_FIELDS, "controller configuration")
    if type(data["beadsEnabled"]) is not bool:
        raise ControllerProtocolError("beadsEnabled must be a literal boolean")
    if (
        type(data["schemaVersion"]) is not int
        or data["schemaVersion"] != 1
        or not isinstance(data["protocol"], str)
        or data["protocol"] != PROTOCOL
    ):
        raise ControllerProtocolError("controller configuration schema/protocol mismatch")
    if data["endpointPath"] != str(ENDPOINT_PATH) or data["stateRoot"] != str(STATE_ROOT) or data["controllerKeyPath"] != str(CONTROLLER_KEY_PATH):
        raise ControllerProtocolError("controller configuration changed a fixed path")
    protected = _absolute_path(data["protectedRoot"], "protectedRoot")
    record_key = _absolute_path(data["recordHmacKeyPath"], "recordHmacKeyPath")
    if (
        record_key.parent != protected
    ):
        raise ControllerProtocolError("protected root/key must be normalized absolute configured paths")
    identities = tuple(_positive_int(data[name], name) for name in ("controllerUid", "brokerUid", "workerUid"))
    if len(set(identities)) != 3:
        raise ControllerProtocolError("controller, broker, and worker UIDs must be distinct")
    operations = data["allowedOperations"]
    if not isinstance(operations, list) or tuple(operations) != ALLOWED_OPERATIONS:
        raise ControllerProtocolError("controller operation set differs from the closed production set")
    transport_gid = _positive_int(data["transportGid"], "transportGid")
    artifacts = (
        _absolute_path(data["runtimeManifestPath"], "runtimeManifestPath"),
        _absolute_path(data["modulePath"], "modulePath"),
        _absolute_path(data["schemaPath"], "schemaPath"),
        _absolute_path(
            data["nativeBoundaryManifestPath"], "nativeBoundaryManifestPath"
        ),
        _absolute_path(data["nativeModulePath"], "nativeModulePath"),
    )
    if len(set(artifacts)) != 5 or any(
        path in {CONFIG_PATH, CONTROLLER_KEY_PATH, record_key}
        or path == protected
        or protected in path.parents
        for path in artifacts
    ):
        raise ControllerProtocolError(
            "installed artifact paths must be distinct root-owned files outside protected state"
        )
    return ControllerConfig(
        beads_enabled=data["beadsEnabled"],
        protected_root=protected,
        record_hmac_key_path=record_key,
        controller_uid=identities[0],
        broker_uid=identities[1],
        worker_uid=identities[2],
        transport_gid=transport_gid,
        runtime_manifest_path=artifacts[0],
        module_path=artifacts[1],
        schema_path=artifacts[2],
        runtime_manifest_sha256=_installed_digest(data["runtimeManifestSha256"], "runtimeManifestSha256"),
        module_sha256=_installed_digest(data["moduleSha256"], "moduleSha256"),
        schema_sha256=_installed_digest(data["schemaSha256"], "schemaSha256"),
        config_epoch=_positive_int(data["configEpoch"], "configEpoch"),
        key_epoch=_positive_int(data["keyEpoch"], "keyEpoch"),
        native_boundary_manifest_path=artifacts[3],
        native_boundary_manifest_sha256=_installed_digest(
            data["nativeBoundaryManifestSha256"],
            "nativeBoundaryManifestSha256",
        ),
        native_module_path=artifacts[4],
        native_module_sha256=_installed_digest(
            data["nativeModuleSha256"], "nativeModuleSha256"
        ),
    )


def _read_root_owned(path: Path, label: str, *, max_bytes: int = MAX_MESSAGE_BYTES, executable: bool = False) -> bytes:
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ControllerProtocolError(f"{label} path is not normalized and absolute")
    parent = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for component in path.parts[1:-1]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent,
            )
            try:
                metadata = os.fstat(child)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != 0
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    raise ControllerProtocolError(
                        f"{label} ancestry must be root-owned and non-writable"
                    )
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1:
            raise ControllerProtocolError(f"{label} must be a root-owned single-link regular file")
        # Root-owned public configuration/source may be readable by the
        # dedicated controller UID, but is never group/other writable.  Secret
        # controller material has a separate controller-owned mode-0600 check.
        forbidden = 0o022
        if stat.S_IMODE(before.st_mode) & forbidden:
            raise ControllerProtocolError(f"{label} permissions are unsafe")
        if executable and not stat.S_IMODE(before.st_mode) & 0o500:
            raise ControllerProtocolError(f"{label} is not root-executable")
        fd = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_nlink, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink, before.st_size
            ):
                raise ControllerProtocolError(f"{label} changed before open")
            data = bytearray()
            while len(data) <= max_bytes:
                chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(fd)
            rebound = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            identity = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mode,
                opened.st_uid,
                opened.st_gid,
                opened.st_nlink,
            )
            if len(data) > max_bytes or identity != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mode,
                after.st_uid,
                after.st_gid,
                after.st_nlink,
            ) or identity != (
                rebound.st_dev,
                rebound.st_ino,
                rebound.st_size,
                rebound.st_mode,
                rebound.st_uid,
                rebound.st_gid,
                rebound.st_nlink,
            ):
                raise ControllerProtocolError(f"{label} is oversized or changed while read")
            return bytes(data)
        finally:
            os.close(fd)
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot read {label}: {exc}") from exc
    finally:
        os.close(parent)


def _observe_executing_module_file(
    path: Path, label: str
) -> tuple[Path, tuple[int, int, int, int, int, int, int], str]:
    """No-follow observe one live module path and bind its stable inode/bytes."""

    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ControllerProtocolError(f"{label} is not a normalized absolute path")
    if Path(os.path.realpath(path)) != path:
        raise ControllerProtocolError(f"{label} contains a symbolic link")
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ControllerProtocolError(f"{label} is not a no-follow regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            data = bytearray()
            while len(data) <= MAX_MESSAGE_BYTES:
                chunk = os.read(
                    descriptor, min(65536, MAX_MESSAGE_BYTES + 1 - len(data))
                )
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        rebound = os.lstat(path)
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot observe {label}: {exc}") from exc
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
    )
    for observed in (opened, after, rebound):
        if identity != (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mode,
            observed.st_uid,
            observed.st_gid,
            observed.st_nlink,
        ):
            raise ControllerProtocolError(f"{label} changed during observation")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ControllerProtocolError(f"{label} is oversized")
    return path, identity, _sha(bytes(data))


_EXECUTING_MODULE_PATH, _EXECUTING_MODULE_IDENTITY, _EXECUTING_MODULE_SHA256 = (
    _observe_executing_module_file(
        Path(__file__), "executing controller module at import"
    )
)
_NATIVE_MODULE_PATH, _NATIVE_MODULE_IDENTITY, _NATIVE_MODULE_SHA256 = (
    _observe_executing_module_file(
        Path(str(native_boundary_v27.__file__)),
        "executing native V27 module at import",
    )
)


def _verify_executing_module_identity(config: ControllerConfig) -> None:
    """Bind configured bytes to this exact imported module and import origin."""

    module = sys.modules.get(__name__)
    specification = getattr(module, "__spec__", None)
    origin = getattr(specification, "origin", None)
    if not isinstance(origin, str):
        raise ControllerProtocolError(
            "executing controller module specification has no file origin"
        )
    live_file = Path(__file__)
    origin_path = Path(origin)
    if live_file != config.module_path:
        raise ControllerProtocolError(
            "configured modulePath is not the executing controller module __file__"
        )
    if origin_path != config.module_path:
        raise ControllerProtocolError(
            "executing controller module specification origin differs from modulePath"
        )
    observed_path, observed_identity, observed_digest = _observe_executing_module_file(
        config.module_path, "executing controller module"
    )
    if observed_path != _EXECUTING_MODULE_PATH:
        raise ControllerProtocolError(
            "executing controller module canonical path changed since import"
        )
    if observed_identity != _EXECUTING_MODULE_IDENTITY:
        raise ControllerProtocolError(
            "executing controller module inode changed since import"
        )
    if (
        observed_digest != _EXECUTING_MODULE_SHA256
        or observed_digest != config.module_sha256
    ):
        raise ControllerProtocolError(
            "executing controller module digest differs from configured/imported bytes"
        )

    native_specification = getattr(native_boundary_v27, "__spec__", None)
    native_origin = getattr(native_specification, "origin", None)
    if (
        not isinstance(native_origin, str)
        or Path(str(native_boundary_v27.__file__)) != config.native_module_path
        or Path(native_origin) != config.native_module_path
    ):
        raise ControllerProtocolError(
            "configured nativeModulePath is not the live imported V27 module"
        )
    native_path, native_identity, native_digest = _observe_executing_module_file(
        config.native_module_path, "executing native V27 module"
    )
    if (
        native_path != _NATIVE_MODULE_PATH
        or native_identity != _NATIVE_MODULE_IDENTITY
        or native_digest != _NATIVE_MODULE_SHA256
        or native_digest != config.native_module_sha256
    ):
        raise ControllerProtocolError(
            "executing native V27 module differs from configured/imported bytes"
        )


def load_controller_config() -> ControllerConfig:
    """Load only the fixed root-owned production configuration."""

    raw = _read_root_owned(CONFIG_PATH, "Beads boundary controller configuration")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("controller configuration contains malformed JSON") from exc
    if raw not in {_canonical(value), _canonical(value) + b"\n"}:
        raise ControllerProtocolError("controller configuration is not exact canonical JSON")
    return _parse_config(value)


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"):
        raise ControllerProtocolError("SO_PEERCRED controller protocol requires Linux")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _endpoint_metadata(config: ControllerConfig) -> None:
    try:
        info = os.lstat(ENDPOINT_PATH)
    except OSError as exc:
        raise ControllerProtocolError(f"fixed controller endpoint is unavailable: {exc}") from exc
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != config.controller_uid
        or info.st_gid != config.transport_gid
        or stat.S_IMODE(info.st_mode) != 0o660
    ):
        raise ControllerProtocolError("fixed controller endpoint owner/mode/type is unsafe")


def _transport_group_members(config: ControllerConfig) -> set[int]:
    try:
        group = grp.getgrgid(config.transport_gid)
        named_members = set(group.gr_mem)
        members = {
            entry.pw_uid
            for entry in pwd.getpwall()
            if entry.pw_gid == config.transport_gid or entry.pw_name in named_members
        }
    except (KeyError, OSError) as exc:
        raise ControllerProtocolError(
            "configured Beads transport group cannot be resolved"
        ) from exc
    return members


def _validate_transport_group(config: ControllerConfig) -> None:
    members = _transport_group_members(config)
    expected = {config.controller_uid, config.broker_uid}
    if members != expected or config.worker_uid in members:
        raise ControllerProtocolError(
            "transport group must contain exactly the distinct controller and broker UIDs"
        )


def _verify_installed_artifacts(
    config: ControllerConfig,
) -> native_boundary_v27.NativeBoundaryManifestV27:
    if not config.beads_enabled:
        raise ControllerProtocolError("protected Beads boundary is disabled")
    _verify_executing_module_identity(config)
    observations = (
        (
            config.runtime_manifest_path,
            "installed protected runtime manifest",
            config.runtime_manifest_sha256,
        ),
        (config.module_path, "installed boundary controller module", config.module_sha256),
        (config.schema_path, "installed protected runtime schema", config.schema_sha256),
        (
            config.native_boundary_manifest_path,
            "installed native boundary V27 manifest",
            config.native_boundary_manifest_sha256,
        ),
        (
            config.native_module_path,
            "installed native V27 module",
            config.native_module_sha256,
        ),
    )
    native_manifest_bytes: bytes | None = None
    for path, label, expected in observations:
        installed_bytes = _read_root_owned(path, label)
        observed = _sha(installed_bytes)
        if observed != expected:
            raise ControllerProtocolError(
                f"{label} installed artifact digest does not match closed configuration"
            )
        if path == config.native_boundary_manifest_path:
            native_manifest_bytes = installed_bytes
    assert native_manifest_bytes is not None
    try:
        parsed = json.loads(native_manifest_bytes)
        if native_boundary_v27.canonical_bytes(parsed) + b"\n" != native_manifest_bytes:
            raise native_boundary_v27.NativeBoundaryV27Error(
                "native boundary manifest must be canonical JSON plus one LF"
            )
        manifest = native_boundary_v27.parse_native_boundary_manifest_v27(parsed)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_boundary_v27.NativeBoundaryV27Error,
    ) as exc:
        raise ControllerProtocolError(
            f"installed native boundary V27 manifest is invalid: {exc}"
        ) from exc
    return manifest


def _verify_native_platform_gate(
    manifest: native_boundary_v27.NativeBoundaryManifestV27,
    *,
    expected_worker_uid: int | None = None,
    run_probe: bool = True,
) -> None:
    observations = (
        (
            manifest.launcher_path,
            "installed native launcher",
            manifest.launcher_sha256,
        ),
        (
            manifest.supervisor_path,
            "installed native supervisor",
            manifest.supervisor_sha256,
        ),
        (manifest.podman_path, "installed native Podman", manifest.podman_sha256),
        (manifest.conmon_path, "installed native conmon", manifest.conmon_sha256),
        (
            manifest.oci_runtime_path,
            "installed native OCI runtime",
            manifest.oci_runtime_sha256,
        ),
    )
    for path, label, expected in observations:
        observed = _sha(_read_root_owned(path, label, executable=True))
        if observed != expected:
            raise ControllerProtocolError(
                f"{label} digest does not match the native V27 manifest"
            )
    if run_probe:
        try:
            native_boundary_v27.verify_local_platform_gate_v27(
                manifest, expected_worker_uid=expected_worker_uid
            )
        except native_boundary_v27.NativeBoundaryV27Error as exc:
            raise ControllerProtocolError(
                f"native V27 Linux/SELinux/systemd/Podman/supervisor gate failed: {exc}"
            ) from exc


def _worker_packet_v27(value: Any, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError(f"{label} is malformed") from exc
    if (
        not isinstance(parsed, dict)
        or _canonical(parsed) != value
        or len(value) > MAX_MESSAGE_BYTES
    ):
        raise ControllerProtocolError(f"{label} is not bounded canonical JSON")
    return parsed


def _recv_credentialed_packet_v27(
    channel: socket.socket,
    *,
    expected_pid: int,
    expected_uid: int,
    expected_gid: int,
    label: str,
) -> bytes:
    """Receive one record and authenticate the credentials of this send."""

    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    credential_size = struct.calcsize("3i")
    packet, ancillary, flags, _address = channel.recvmsg(
        MAX_MESSAGE_BYTES + 1,
        socket.CMSG_SPACE(credential_size),
    )
    credentials: list[tuple[int, int, int]] = []
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            if len(payload) != credential_size:
                raise ControllerProtocolError(f"{label} credentials are truncated")
            credentials.append(struct.unpack("3i", payload))
        elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            raise ControllerProtocolError(f"{label} smuggled descriptor rights")
        else:
            raise ControllerProtocolError(f"{label} has unknown ancillary data")
    if (
        flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0))
        or not packet
        or len(packet) > MAX_MESSAGE_BYTES
        or credentials != [(expected_pid, expected_uid, expected_gid)]
    ):
        raise ControllerProtocolError(f"{label} packet/credential identity is invalid")
    return packet


def _recv_worker_execute_packet_v27(
    channel: socket.socket,
    *,
    expected_pid: int,
    expected_uid: int,
    expected_gid: int,
) -> tuple[bytes, tuple[int, ...]]:
    """Receive zero, recovery-key-only, or cgroup-plus-key descriptor rights."""

    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    credential_size = struct.calcsize("3i")
    rights_size = array.array("i").itemsize * (
        len(_WORKER_CGROUP_ROLES_V27) + 1
    )
    packet, ancillary, flags, _address = channel.recvmsg(
        MAX_MESSAGE_BYTES + 1,
        socket.CMSG_SPACE(credential_size) + socket.CMSG_SPACE(rights_size),
    )
    credentials: list[tuple[int, int, int]] = []
    rights: list[tuple[int, ...]] = []
    try:
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if len(payload) != credential_size:
                    raise ControllerProtocolError(
                        "native worker request credentials are truncated"
                    )
                credentials.append(struct.unpack("3i", payload))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array("i")
                usable = len(payload) - (len(payload) % values.itemsize)
                values.frombytes(payload[:usable])
                rights.append(tuple(values))
                if len(values) not in {
                    1, len(_WORKER_CGROUP_ROLES_V27) + 1
                }:
                    raise ControllerProtocolError(
                        "native worker request descriptor rights are truncated"
                    )
            else:
                raise ControllerProtocolError(
                    "native worker request has unknown ancillary data"
                )
        if (
            flags
            & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0))
            or not packet
            or len(packet) > MAX_MESSAGE_BYTES
            or credentials != [(expected_pid, expected_uid, expected_gid)]
            or len(rights) > 1
        ):
            raise ControllerProtocolError(
                "native worker request packet/credential identity is invalid"
            )
        return packet, rights[0] if rights else ()
    except BaseException:
        for group in rights:
            for descriptor in group:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise


def _worker_result_packet_v27(
    plan_sha256: str, result: Mapping[str, Any]
) -> bytes:
    try:
        observation = native_boundary_v27._decode_native_stage_result_v27(
            result, require_discriminants=True
        )
    except native_boundary_v27.NativeBoundaryV27Error as exc:
        raise ControllerProtocolError(
            f"native worker result is invalid: {exc}"
        ) from exc
    return _canonical(
        {
            "schemaVersion": 27,
            "protocol": _WORKER_PROTOCOL,
            "status": "completed",
            "stagePlanSha256": plan_sha256,
            "nativeStageObservation": observation,
        }
    )


def _worker_result_offer_packet_v27(
    plan_sha256: str, result: Mapping[str, Any], request_key: bytes
) -> bytes:
    packet = json.loads(_worker_result_packet_v27(plan_sha256, result))
    observation = packet["nativeStageObservation"]
    observation_sha256 = _sha(_canonical(observation))
    body = {
        "schemaVersion": 27,
        "protocol": _WORKER_PROTOCOL,
        "status": "result-offer",
        "stagePlanSha256": plan_sha256,
        "nativeResultSha256": observation_sha256,
        "resultKind": observation["resultKind"],
        "resultPredecessorKind": observation["resultPredecessorKind"],
        "failureEvidenceSha256": observation["failureEvidenceSha256"],
        "placementMask": observation["placementMask"],
    }
    body["offerHmac"] = "hmac-sha256:" + hmac.new(
        request_key,
        _WORKER_RESULT_OFFER_DOMAIN_V27 + _canonical(body),
        hashlib.sha256,
    ).hexdigest()
    return _canonical(body)


def _worker_result_offer_ack_v27(
    *, plan_sha256: str, native_result_sha256: str,
    authorization_record_sha256: str, request_key: bytes,
) -> bytes:
    body = {
        "schemaVersion": 27,
        "protocol": _WORKER_PROTOCOL,
        "action": "ACK-RESULT-OFFER",
        "stagePlanSha256": plan_sha256,
        "nativeResultSha256": native_result_sha256,
        "authorizationRecordSha256": authorization_record_sha256,
    }
    body["ackHmac"] = "hmac-sha256:" + hmac.new(
        request_key,
        _WORKER_RESULT_OFFER_ACK_DOMAIN_V27 + _canonical(body),
        hashlib.sha256,
    ).hexdigest()
    return _canonical(body)


def _worker_pre_effect_failure_packet_v27(
    plan_sha256: str,
    *,
    evidence_sha256: str,
    classification: Mapping[str, Any],
    request_key: bytes,
) -> bytes:
    body = {
        "schemaVersion": 27,
        "protocol": _WORKER_PROTOCOL,
        "status": "launch-pre-effect-failed",
        "stagePlanSha256": plan_sha256,
        "evidenceSha256": evidence_sha256,
        "classification": dict(classification),
    }
    body["packetHmac"] = "hmac-sha256:" + hmac.new(
        request_key,
        _WORKER_PRE_EFFECT_FAILURE_DOMAIN_V27 + _canonical(body),
        hashlib.sha256,
    ).hexdigest()
    return _canonical(body)


def _worker_launch_unresolved_packet_v27(
    plan_sha256: str,
    recovered: Mapping[str, Any],
    request_key: bytes,
) -> bytes:
    if not native_boundary_v27._is_native_supervisor_loss_v27(recovered):
        raise ControllerProtocolError(
            "native launch unresolved packet lacks a closed loss observation"
        )
    body = {
        "schemaVersion": 27,
        "protocol": _WORKER_PROTOCOL,
        "status": "launch-unresolved",
        "stagePlanSha256": plan_sha256,
        "nativeSupervisorLoss": dict(recovered["nativeSupervisorLoss"]),
    }
    body["packetHmac"] = "hmac-sha256:" + hmac.new(
        request_key,
        _WORKER_LAUNCH_UNRESOLVED_DOMAIN_V27 + _canonical(body),
        hashlib.sha256,
    ).hexdigest()
    return _canonical(body)


def _validate_worker_launch_unresolved_v27(
    value: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    request_key: bytes,
) -> dict[str, Any]:
    fields = {
        "schemaVersion", "protocol", "status", "stagePlanSha256",
        "nativeSupervisorLoss", "packetHmac",
    }
    body = {field: value[field] for field in fields if field != "packetHmac"} if (
        isinstance(value, Mapping) and set(value) == fields
    ) else None
    recovered = (
        {"nativeSupervisorLoss": value["nativeSupervisorLoss"]}
        if body is not None
        else None
    )
    if (
        body is None
        or value["schemaVersion"] != 27
        or value["protocol"] != _WORKER_PROTOCOL
        or value["status"] != "launch-unresolved"
        or value["stagePlanSha256"] != plan["stagePlanSha256"]
        or recovered is None
        or not native_boundary_v27._is_native_supervisor_loss_v27(recovered)
        or not hmac.compare_digest(
            str(value["packetHmac"]),
            "hmac-sha256:" + hmac.new(
                request_key,
                _WORKER_LAUNCH_UNRESOLVED_DOMAIN_V27 + _canonical(body),
                hashlib.sha256,
            ).hexdigest(),
        )
    ):
        raise ControllerProtocolError(
            "native launch unresolved packet authentication changed"
        )
    return dict(recovered)


def _validate_worker_pre_effect_failure_v27(
    value: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    manifest: native_boundary_v27.NativeBoundaryManifestV27,
    request_key: bytes,
) -> dict[str, Any]:
    fields = {
        "schemaVersion", "protocol", "status", "stagePlanSha256",
        "evidenceSha256", "classification", "packetHmac",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ControllerProtocolError(
            "native launch pre-effect packet shape changed"
        )
    classification = value["classification"]
    if not isinstance(classification, Mapping) or set(classification) != {
        "classification", "setupStep", "failureKind",
        "executablePathSha256", "errno", "processCreated"
    }:
        raise ControllerProtocolError(
            "native launch pre-effect classification shape changed"
        )
    expected_path_sha256 = native_boundary_v27.sha256(
        str(manifest.launcher_path).encode("utf-8")
    )
    if (
        value["schemaVersion"] != 27
        or value["protocol"] != _WORKER_PROTOCOL
        or value["status"] != "launch-pre-effect-failed"
        or value["stagePlanSha256"] != plan["stagePlanSha256"]
        or classification["classification"]
        != "pre-popen-descriptor-preflight-failed"
        or classification["setupStep"] != "source-descriptor-preflight"
        or classification["failureKind"] != "policy-rejection"
        or classification["executablePathSha256"] != expected_path_sha256
        or classification["errno"] is not None
        or classification["processCreated"] is not False
    ):
        raise ControllerProtocolError(
            "native launch pre-effect classification changed"
        )
    expected_evidence = native_boundary_v27.sha256(
        b"startup-factory/beads/v27/launch-pre-effect-failed\0"
        + native_boundary_v27.canonical_bytes(dict(classification))
    )
    body = {field: value[field] for field in fields if field != "packetHmac"}
    expected_hmac = "hmac-sha256:" + hmac.new(
        request_key,
        _WORKER_PRE_EFFECT_FAILURE_DOMAIN_V27 + _canonical(body),
        hashlib.sha256,
    ).hexdigest()
    if (
        value["evidenceSha256"] != expected_evidence
        or not hmac.compare_digest(str(value["packetHmac"]), expected_hmac)
    ):
        raise ControllerProtocolError(
            "native launch pre-effect packet authentication changed"
        )
    return {
        "evidenceSha256": expected_evidence,
        "classification": dict(classification),
    }


def _worker_recovery_packet_v27(
    plan_sha256: str, result: Mapping[str, Any]
) -> bytes:
    if isinstance(result, Mapping) and set(result) == {
        "nativeLaunchPreEffectProof", "_controllerRetirementChain"
    }:
        return _canonical(
            {
                "schemaVersion": 27,
                "protocol": _WORKER_PROTOCOL,
                "status": "launch-pre-effect-proved",
                "stagePlanSha256": plan_sha256,
                "nativeLaunchPreEffectProof": result[
                    "nativeLaunchPreEffectProof"
                ],
                "controllerRetirementChain": result[
                    "_controllerRetirementChain"
                ],
            }
        )
    if native_boundary_v27._is_native_supervisor_loss_v27(result):
        if set(result) != {
            "nativeSupervisorLoss", "_controllerRetirementChain"
        }:
            raise ControllerProtocolError(
                "native worker loss recovery lacks the controller retirement chain"
            )
        return _canonical(
            {
                "schemaVersion": 27,
                "protocol": _WORKER_PROTOCOL,
                "status": "loss",
                "stagePlanSha256": plan_sha256,
                "nativeSupervisorLoss": result["nativeSupervisorLoss"],
                "controllerRetirementChain": result[
                    "_controllerRetirementChain"
                ],
            }
        )
    if not isinstance(result, Mapping) or set(result) not in ({
        "exitCode", "stdout", "stderr", "lifecycle", "placementMask",
        "resultKind", "resultPredecessorKind", "failureEvidenceSha256",
        "_controllerRetirementChain",
    }, {
        "exitCode", "stdout", "stderr", "lifecycle", "placementMask",
        "resultKind", "resultPredecessorKind", "failureEvidenceSha256",
        "_controllerRetirementChain", "_nativeCreatorArtifactBinding",
    }):
        raise ControllerProtocolError(
            "native worker recovery lacks exact controller envelope relays"
        )
    stage_result = {
        key: value
        for key, value in result.items()
        if key not in {
            "_controllerRetirementChain", "_nativeCreatorArtifactBinding"
        }
    }
    try:
        observation = native_boundary_v27._decode_native_stage_result_v27(
            stage_result, require_discriminants=True
        )
    except native_boundary_v27.NativeBoundaryV27Error as exc:
        raise ControllerProtocolError(
            f"native worker recovered result is invalid: {exc}"
        ) from exc
    return _canonical(
        {
            "schemaVersion": 27,
            "protocol": _WORKER_PROTOCOL,
            "status": "completed",
            "stagePlanSha256": plan_sha256,
            "nativeStageObservation": observation,
            "controllerRetirementChain": result[
                "_controllerRetirementChain"
            ],
            "nativeCreatorArtifactBinding": result.get(
                "_nativeCreatorArtifactBinding"
            ),
        }
    )


def _assert_worker_dac_isolation_v27(config: ControllerConfig) -> None:
    protected = (
        config.protected_root,
        config.record_hmac_key_path,
        CONTROLLER_KEY_PATH,
        OPERATOR_KEY_PATH,
        OPERATOR_STATE_PATH,
        STATE_ROOT,
    )
    for path in protected:
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | (getattr(os, "O_DIRECTORY", 0) if path in {config.protected_root, STATE_ROOT} else 0),
            )
        except PermissionError:
            continue
        except OSError as exc:
            raise ControllerProtocolError(
                f"worker could not prove protected asset denial for {path}: {exc}"
            ) from exc
        else:
            os.close(descriptor)
            raise ControllerProtocolError(
                f"configured worker UID can read protected controller asset {path}"
            )


def _drop_to_worker_identity_v27(config: ControllerConfig) -> None:
    try:
        account = pwd.getpwuid(config.worker_uid)
    except KeyError as exc:
        raise ControllerProtocolError("configured worker UID has no local account") from exc
    os.environ.clear()
    os.environ.update(
        {
            "HOME": account.pw_dir,
            "LANG": "C",
            "LC_ALL": "C",
            "LOGNAME": account.pw_name,
            "PATH": "/usr/bin:/bin",
            "USER": account.pw_name,
            "XDG_RUNTIME_DIR": f"/run/user/{config.worker_uid}",
        }
    )
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(config.worker_uid)
    if (
        os.geteuid() != config.worker_uid
        or os.getegid() != account.pw_gid
        or os.getgroups()
    ):
        raise ControllerProtocolError(
            "native worker did not enter the exact configured unprivileged identity"
        )
    _assert_worker_dac_isolation_v27(config)


def _validate_zero_worker_capabilities_v27(raw_status: bytes) -> None:
    try:
        status = raw_status.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ControllerProtocolError(
            "worker Linux capability state is not ASCII"
        ) from exc
    observed: dict[str, str] = {}
    for line in status.splitlines():
        match = re.fullmatch(r"(CapInh|CapPrm|CapEff|CapAmb):\s*([0-9A-Fa-f]+)", line)
        if match is None:
            continue
        name, value = match.groups()
        if name in observed:
            raise ControllerProtocolError(
                "worker Linux capability state has duplicate fields"
            )
        observed[name] = value
    required = {"CapInh", "CapPrm", "CapEff", "CapAmb"}
    if set(observed) != required:
        raise ControllerProtocolError(
            "worker Linux capability state is incomplete"
        )
    if any(int(value, 16) != 0 for value in observed.values()):
        raise ControllerProtocolError(
            "worker retained Linux capabilities after identity drop"
        )


def _assert_worker_has_no_linux_capabilities_v27() -> None:
    status_path = Path("/proc") / str(os.getpid()) / "status"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(status_path, flags)
    except OSError as exc:
        raise ControllerProtocolError(
            f"worker cannot open its Linux capability state: {exc}"
        ) from exc
    try:
        chunks: list[bytes] = []
        size = 0
        while True:
            try:
                chunk = os.read(
                    descriptor,
                    min(16_384, _WORKER_STATUS_MAX_BYTES_V27 + 1 - size),
                )
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _WORKER_STATUS_MAX_BYTES_V27:
                raise ControllerProtocolError(
                    "worker Linux capability state exceeds the byte cap"
                )
        _validate_zero_worker_capabilities_v27(b"".join(chunks))
    finally:
        os.close(descriptor)


def _verify_worker_result_root_label_v27(config: ControllerConfig) -> None:
    """Verify the actual result-root label after the irreversible UID drop."""

    result_root = (
        Path("/run/user")
        / str(config.worker_uid)
        / "startup-factory-beads-results"
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(result_root, flags)
    except OSError as exc:
        raise ControllerProtocolError(
            f"worker result root is not an accessible no-follow directory: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != config.worker_uid
            or metadata.st_gid != os.getegid()
            or metadata.st_nlink < 2
        ):
            raise ControllerProtocolError(
                "worker result root type, owner, mode, or link count changed"
            )
        try:
            raw_context = os.getxattr(descriptor, "security.selinux")
        except (AttributeError, OSError, TypeError) as exc:
            raise ControllerProtocolError(
                f"worker cannot read the actual result root SELinux label: {exc}"
            ) from exc
        if raw_context.endswith(b"\0"):
            raw_context = raw_context[:-1]
        if (
            raw_context != _WORKER_RESULT_SELINUX_CONTEXT_V27
            or b"\0" in raw_context
        ):
            raise ControllerProtocolError(
                "worker result root SELinux label differs from the pinned context"
            )
        _assert_worker_has_no_linux_capabilities_v27()
    finally:
        os.close(descriptor)


def _payload_cgroup_name_v27(plan: Mapping[str, Any]) -> str:
    operation_id = str(plan.get("operationId", ""))
    stage_location = plan.get("stageLocation")
    stage_digest = str(plan.get("stagePlanSha256", ""))
    if (
        not _OPERATION_ID.fullmatch(operation_id)
        or type(stage_location) is not int
        or not 1 <= stage_location <= 77
        or not _DIGEST.fullmatch(stage_digest)
    ):
        raise ControllerProtocolError(
            "native cgroup plan identity is invalid"
        )
    return (
        f"payload-{operation_id}-s{stage_location}-"
        f"{stage_digest.removeprefix('sha256:')[:16]}"
    )


def _process_start_time_v27(pid: int, *, proc_root: Path = Path("/proc")) -> str:
    try:
        raw = (proc_root / str(pid) / "stat").read_bytes()
    except OSError as exc:
        raise ControllerProtocolError(
            f"controller cannot read worker process identity: {exc}"
        ) from exc
    closing = raw.rfind(b")")
    if closing <= 0:
        raise ControllerProtocolError("controller worker process identity is malformed")
    fields = raw[closing + 1 :].split()
    if len(fields) < 20 or not re.fullmatch(rb"(?:0|[1-9][0-9]*)", fields[19]):
        raise ControllerProtocolError("controller worker process identity is malformed")
    return fields[19].decode("ascii")


def _process_parent_pid_v27(pid: int, *, proc_root: Path = Path("/proc")) -> int:
    try:
        raw = (proc_root / str(pid) / "stat").read_bytes()
    except OSError as exc:
        raise ControllerProtocolError(
            f"controller cannot read process parent identity: {exc}"
        ) from exc
    closing = raw.rfind(b")")
    fields = raw[closing + 1 :].split() if closing > 0 else []
    if len(fields) < 2 or not re.fullmatch(rb"[1-9][0-9]*", fields[1]):
        raise ControllerProtocolError("controller process parent identity is malformed")
    return int(fields[1])


def _assert_worker_pidfd_identity_v27(
    worker_pid: int,
    pidfd: int,
    start_time: str,
    *,
    proc_root: Path = Path("/proc"),
) -> None:
    if select.select([pidfd], [], [], 0)[0]:
        raise ControllerProtocolError("native worker pidfd is terminal")
    if _process_start_time_v27(worker_pid, proc_root=proc_root) != start_time:
        raise ControllerProtocolError("native worker PID identity changed")


def _place_persistent_worker_v27(
    process_fd: int,
    *,
    worker_pid: int,
    pidfd: int,
    start_time: str,
    expected_relative: str,
    proc_root: Path = Path("/proc"),
) -> dict[str, Any]:
    _assert_worker_pidfd_identity_v27(
        worker_pid, pidfd, start_time, proc_root=proc_root
    )
    native_boundary_v27._write_all_v27(
        process_fd, f"{worker_pid}\n".encode("ascii")
    )
    _assert_worker_pidfd_identity_v27(
        worker_pid, pidfd, start_time, proc_root=proc_root
    )
    observed = native_boundary_v27._unified_cgroup_relative_v27(
        (proc_root / str(worker_pid) / "cgroup").read_bytes()
    )
    if observed != expected_relative:
        raise ControllerProtocolError(
            "native worker did not enter the exact controller-issued cgroup"
        )
    return {
        "schemaVersion": 27,
        "workerPid": worker_pid,
        "workerStartTime": start_time,
        "cgroupRelative": expected_relative,
    }


def _validate_supervisor_process_control_v27(
    descriptor: int, *, worker_uid: int
) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid == worker_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        != os.O_WRONLY
    ):
        raise ControllerProtocolError(
            "supervisor cgroup.procs is not controller-custodied and worker-denied"
        )


def _prepare_supervisor_process_control_v27(
    supervisor_fd: int,
    *,
    controller_uid: int,
    worker_uid: int,
    worker_gid: int,
    cgroup2_observer: Any = None,
) -> int:
    """Root-delegate the common-ancestor attach control to only the controller.

    Linux checks write access to the common ancestor's ``cgroup.procs`` when
    moving a process from W to a lifecycle leaf.  Chowning S itself does not
    change this kernfs interface.  The only admitted incomplete bootstrap is
    the exact root-owned initial interface or the atomic-fchown-completed,
    chmod-pending state; every other identity is substituted evidence.
    """

    descriptor = -1
    try:
        before = os.stat(
            "cgroup.procs", dir_fd=supervisor_fd, follow_symlinks=False
        )
        descriptor = os.open(
            "cgroup.procs",
            os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=supervisor_fd,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or _cgroup_entry_identity_v27(opened)
            != _cgroup_entry_identity_v27(before)
            or opened.st_nlink != 1
        ):
            raise ControllerProtocolError(
                "supervisor cgroup.procs changed before descriptor open"
            )
        root = _prove_cgroup2_supervisor_fd_v27(
            supervisor_fd, observer=cgroup2_observer
        )
        if opened.st_dev != root["device"]:
            raise ControllerProtocolError(
                "supervisor cgroup.procs filesystem identity changed"
            )

        mode = stat.S_IMODE(opened.st_mode)
        exact_root_state = (
            opened.st_uid == 0
            and opened.st_gid in {0, worker_gid}
            and mode in {0o644, 0o600}
        )
        exact_chown_half_state = (
            opened.st_uid == controller_uid
            and opened.st_gid == worker_gid
            and mode == 0o644
        )
        exact_final_state = (
            opened.st_uid == controller_uid
            and opened.st_gid == worker_gid
            and mode == 0o600
        )
        if exact_root_state:
            if os.geteuid() != 0:
                raise ControllerProtocolError(
                    "supervisor cgroup.procs root bootstrap requires root"
                )
            os.fchown(descriptor, controller_uid, worker_gid)
            os.fchmod(descriptor, 0o600)
        elif exact_chown_half_state:
            if os.geteuid() != 0:
                raise ControllerProtocolError(
                    "supervisor cgroup.procs half-state requires root"
                )
            os.fchmod(descriptor, 0o600)
        elif not exact_final_state:
            raise ControllerProtocolError(
                "supervisor cgroup.procs has substituted owner or mode"
            )

        final = os.fstat(descriptor)
        rebound = os.stat(
            "cgroup.procs", dir_fd=supervisor_fd, follow_symlinks=False
        )
        if (
            _cgroup_entry_identity_v27(final)
            != _cgroup_entry_identity_v27(rebound)
            or final.st_uid != controller_uid
            or final.st_gid != worker_gid
            or stat.S_IMODE(final.st_mode) != 0o600
        ):
            raise ControllerProtocolError(
                "supervisor cgroup.procs delegation did not reach its exact identity"
            )
        _validate_supervisor_process_control_v27(
            descriptor, worker_uid=worker_uid
        )
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _read_cgroup_tokens_v27(descriptor: int, label: str) -> tuple[str, ...]:
    try:
        raw = os.pread(descriptor, 4096, 0)
    except OSError as exc:
        raise ControllerProtocolError(f"cannot read exact {label}: {exc}") from exc
    if len(raw) == 4096 or b"\x00" in raw:
        raise ControllerProtocolError(f"exact {label} is malformed")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ControllerProtocolError(f"exact {label} is malformed") from exc
    tokens = tuple(text.split())
    if len(tokens) != len(set(tokens)) or any(
        not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", token) for token in tokens
    ):
        raise ControllerProtocolError(f"exact {label} is malformed")
    return tokens


def _enable_exact_subtree_controllers_v27(directory_fd: int) -> None:
    """Enable the closed resource set only after proving no internal process."""

    procs = controllers = subtree = -1
    try:
        procs = os.open(
            "cgroup.procs",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        if os.pread(procs, 4096, 0).strip():
            raise ControllerProtocolError(
                "delegated cgroup has an internal process before controller enablement"
            )
        controllers = os.open(
            "cgroup.controllers",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        available = _read_cgroup_tokens_v27(controllers, "cgroup.controllers")
        if not set(_DELEGATED_CONTROLLERS_V27).issubset(available):
            raise ControllerProtocolError(
                "delegated cgroup lacks the exact required controllers"
            )
        subtree = os.open(
            "cgroup.subtree_control",
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        before = _read_cgroup_tokens_v27(subtree, "cgroup.subtree_control")
        if not set(before).issubset(_DELEGATED_CONTROLLERS_V27):
            raise ControllerProtocolError(
                "delegated cgroup has an extra enabled controller"
            )
        native_boundary_v27._write_all_v27(
            subtree,
            (" ".join("+" + item for item in _DELEGATED_CONTROLLERS_V27) + "\n").encode("ascii"),
        )
        after = _read_cgroup_tokens_v27(subtree, "cgroup.subtree_control")
        if set(after) != set(_DELEGATED_CONTROLLERS_V27):
            raise ControllerProtocolError(
                "delegated cgroup controller enablement did not reach the exact set"
            )
    except OSError as exc:
        raise ControllerProtocolError(
            f"cannot enable exact delegated cgroup controllers: {exc}"
        ) from exc
    finally:
        for descriptor in (subtree, controllers, procs):
            if descriptor >= 0:
                os.close(descriptor)


def _cgroup_descriptor_binding_v27(role: str, descriptor: int) -> dict[str, Any]:
    if role not in _WORKER_CGROUP_ROLES_V27:
        raise ControllerProtocolError("native cgroup descriptor role is invalid")
    metadata = os.fstat(descriptor)
    access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
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
        "accessMode": access_mode,
    }


@dataclasses.dataclass(slots=True)
class _ControllerCgroupCustodyV27:
    supervisor_fd: int
    supervisor_process_fd: int
    worker_fd: int
    worker_relative: str
    payload_name: str
    binding: dict[str, Any]
    owned_descriptors: tuple[int, int, int, int, int, int]
    controller_uid: int
    worker_uid: int
    worker_gid: int
    cgroup2_observer: Any = None
    cgroup_mode_observer: Any = None
    lifecycle_leaves: dict[int, tuple[int, ...]] = dataclasses.field(
        default_factory=dict
    )

    @property
    def transfer_descriptors(self) -> tuple[int, ...]:
        _payload, _procs, _threads, _subtree, events, kill = self.owned_descriptors
        return (self.worker_fd, _payload, events, kill)

    @property
    def payload_procs_fd(self) -> int:
        return self.owned_descriptors[1]

    def place_lifecycle_child(
        self,
        *,
        child_pid: int,
        child_start_time: str,
        supervisor_pid: int,
        ordinal: int,
        placement_nonce: str,
        proc_root: Path = Path("/proc"),
    ) -> dict[str, Any]:
        """Controller-only placement of one still-blocked lifecycle child."""

        if (
            type(supervisor_pid) is not int
            or supervisor_pid <= 1
            or type(ordinal) is not int
            or not 0 <= ordinal < 6
            or not re.fullmatch(r"[0-9a-f]{64}", placement_nonce)
        ):
            raise ControllerProtocolError("lifecycle child placement request is invalid")
        observed_mask = sum(1 << item for item in self.lifecycle_leaves)
        if (
            ordinal in self.lifecycle_leaves
            or not native_boundary_v27._lifecycle_placement_transition_allowed_v27(
                observed_mask, ordinal
            )
        ):
            raise ControllerProtocolError(
                "lifecycle child placement ordinal is reordered or replayed"
            )
        if not hasattr(os, "pidfd_open"):
            raise ControllerProtocolError("lifecycle child placement requires pidfd_open")
        # Reopen the common-ancestor permission proof immediately before every
        # controller-only W -> Li attach.  The worker never receives this FD.
        supervisor_process = os.fstat(self.supervisor_process_fd)
        if (
            not stat.S_ISREG(supervisor_process.st_mode)
            or supervisor_process.st_uid != self.controller_uid
            or supervisor_process.st_gid != self.worker_gid
            or stat.S_IMODE(supervisor_process.st_mode) != 0o600
            or fcntl.fcntl(self.supervisor_process_fd, fcntl.F_GETFL)
            & os.O_ACCMODE
            != os.O_WRONLY
        ):
            raise ControllerProtocolError(
                "supervisor cgroup.procs custody changed before lifecycle placement"
            )
        pidfd = os.pidfd_open(child_pid, 0)
        supervisor_pidfd = -1
        try:
            supervisor_pidfd = os.pidfd_open(supervisor_pid, 0)
            if select.select([supervisor_pidfd], [], [], 0)[0]:
                raise ControllerProtocolError("native supervisor pidfd is terminal")
            _assert_worker_pidfd_identity_v27(
                child_pid, pidfd, child_start_time, proc_root=proc_root
            )
            if (
                _process_parent_pid_v27(supervisor_pid, proc_root=proc_root)
                != self.binding["workerPid"]
                or _process_parent_pid_v27(child_pid, proc_root=proc_root)
                != supervisor_pid
            ):
                raise ControllerProtocolError(
                    "lifecycle child parent identity changed before placement"
                )
            payload_fd = self.owned_descriptors[0]
            leaf_name = f"lifecycle-{ordinal}"
            try:
                os.mkdir(leaf_name, _LIFECYCLE_CGROUP_MODE_V27, dir_fd=payload_fd)
            except OSError as exc:
                raise ControllerProtocolError(
                    f"controller cannot create exact lifecycle cgroup: {exc}"
                ) from exc
            leaf_fd = -1
            leaf_controls: list[int] = []
            try:
                leaf_fd = os.open(
                    leaf_name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=payload_fd,
                )
                os.fchmod(leaf_fd, _LIFECYCLE_CGROUP_MODE_V27)
                leaf_metadata = os.fstat(leaf_fd)
                if (
                    not stat.S_ISDIR(leaf_metadata.st_mode)
                    or leaf_metadata.st_uid != self.controller_uid
                    or leaf_metadata.st_gid != self.worker_gid
                    or stat.S_IMODE(leaf_metadata.st_mode)
                    != _LIFECYCLE_CGROUP_MODE_V27
                ):
                    raise ControllerProtocolError(
                        "controller lifecycle cgroup owner/mode/type changed"
                    )
                for control in (
                    "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"
                ):
                    descriptor = os.open(
                        control,
                        os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=leaf_fd,
                    )
                    os.fchmod(descriptor, 0o660)
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != self.controller_uid
                        or metadata.st_gid != self.worker_gid
                        or stat.S_IMODE(metadata.st_mode) != 0o660
                    ):
                        os.close(descriptor)
                        raise ControllerProtocolError(
                            f"controller lifecycle {control} identity changed"
                        )
                    leaf_controls.append(descriptor)
            except BaseException:
                for descriptor in reversed(leaf_controls):
                    os.close(descriptor)
                if leaf_fd >= 0:
                    os.close(leaf_fd)
                raise
            payload_relative = (
                self.worker_relative.rsplit("/", 1)[0]
                + "/" + self.payload_name + "/" + leaf_name
            )
            evidence = _place_persistent_worker_v27(
                leaf_controls[0],
                worker_pid=child_pid,
                pidfd=pidfd,
                start_time=child_start_time,
                expected_relative=payload_relative,
                proc_root=proc_root,
            )
            if select.select([supervisor_pidfd], [], [], 0)[0]:
                raise ControllerProtocolError(
                    "native supervisor terminated during lifecycle placement"
                )
            self.lifecycle_leaves[ordinal] = (leaf_fd, *leaf_controls)
            return {
                **evidence,
                "supervisorPid": supervisor_pid,
                "ordinal": ordinal,
                "placementNonce": placement_nonce,
            }
        finally:
            if supervisor_pidfd >= 0:
                os.close(supervisor_pidfd)
            os.close(pidfd)

    def kill_and_wait(self) -> None:
        _payload, _procs, _threads, _subtree, events, kill = self.owned_descriptors
        try:
            native_boundary_v27._write_all_v27(kill, b"1\n")
        except OSError as exc:
            raise ControllerProtocolError(
                f"controller cannot kill the exact payload cgroup: {exc}"
            ) from exc
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                observed = os.pread(events, 4096, 0)
            except InterruptedError:
                continue
            except OSError as exc:
                raise ControllerProtocolError(
                    f"controller cannot read payload cgroup.events: {exc}"
                ) from exc
            if b"populated 0\n" in observed:
                return
            time.sleep(0.02)
        raise ControllerProtocolError(
            "controller payload cgroup remained populated after cgroup.kill"
        )

    def drain(self, *, persist_intent: Any) -> dict[str, Any]:
        self.kill_and_wait()
        return _retire_lifecycle_cgroups_v27(
            self.owned_descriptors[0],
            controller_uid=self.controller_uid,
            worker_uid=self.worker_uid,
            worker_gid=self.worker_gid,
            cgroup2_observer=self.cgroup2_observer,
            cgroup_mode_observer=self.cgroup_mode_observer,
            persist_intent=persist_intent,
        )

    def close(self, *, retire: bool) -> None:
        for leaf_descriptors in reversed(tuple(self.lifecycle_leaves.values())):
            for descriptor in reversed(leaf_descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for descriptor in reversed(self.owned_descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if retire:
            try:
                os.rmdir(self.payload_name, dir_fd=self.supervisor_fd)
            except OSError as exc:
                raise ControllerProtocolError(
                    f"controller cannot retire the exact payload cgroup: {exc}"
                ) from exc


def _pre_effect_descriptor_identity_v27(
    descriptor: int, *, expected_type: str
) -> dict[str, Any]:
    metadata = os.fstat(descriptor)
    observed_type = (
        "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "file"
        if stat.S_ISREG(metadata.st_mode)
        else "unsupported"
    )
    if observed_type != expected_type or metadata.st_nlink < 1:
        raise ControllerProtocolError(
            "pre-effect cgroup descriptor type or link identity changed"
        )
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "nlink": metadata.st_nlink,
        "type": observed_type,
        "accessMode": fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE,
    }


def _controller_pre_effect_empty_observation_v27(
    custody: _ControllerCgroupCustodyV27,
) -> dict[str, Any]:
    """Prove a failed Popen left no child/effect in exact S/P/O custody."""

    if custody.lifecycle_leaves:
        raise ControllerProtocolError(
            "pre-effect failure has a controller-tracked lifecycle child"
        )
    payload_fd, payload_procs, _threads, _subtree, events_fd, _kill = (
        custody.owned_descriptors
    )
    names = tuple(sorted(os.listdir(payload_fd)))
    child_directories: list[str] = []
    for name in names:
        metadata = os.stat(name, dir_fd=payload_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child_directories.append(name)
        elif not stat.S_ISREG(metadata.st_mode):
            raise ControllerProtocolError(
                "pre-effect payload cgroup contains a symlink or special entry"
            )
    if child_directories:
        raise ControllerProtocolError(
            "pre-effect payload cgroup contains an untracked child"
        )
    procs = os.pread(payload_procs, 4096, 0)
    if len(procs) == 4096 or procs.strip():
        raise ControllerProtocolError(
            "pre-effect payload cgroup contains an internal process"
        )
    events_raw = os.pread(events_fd, 4096, 0)
    try:
        event_lines = events_raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ControllerProtocolError(
            "pre-effect payload cgroup.events is malformed"
        ) from exc
    events: dict[str, int] = {}
    for line in event_lines:
        fields = line.split(" ")
        if (
            len(fields) != 2
            or fields[0] not in {"populated", "frozen"}
            or fields[0] in events
            or fields[1] not in {"0", "1"}
        ):
            raise ControllerProtocolError(
                "pre-effect payload cgroup.events is malformed"
            )
        events[fields[0]] = int(fields[1])
    if events.get("populated") != 0 or any(events.values()):
        raise ControllerProtocolError("pre-effect payload cgroup is populated")
    stat_fd = -1
    try:
        stat_fd = os.open(
            "cgroup.stat",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=payload_fd,
        )
        stat_identity = _pre_effect_descriptor_identity_v27(
            stat_fd, expected_type="file"
        )
        cgroup_stat = _decode_cgroup_stat_bytes_v27(
            os.pread(stat_fd, 4096, 0)
        )
    except OSError as exc:
        raise ControllerProtocolError(
            f"cannot observe pre-effect payload cgroup.stat: {exc}"
        ) from exc
    finally:
        if stat_fd >= 0:
            os.close(stat_fd)
    if cgroup_stat["nr_descendants"] != 0 or any(
        value != 0
        for key, value in cgroup_stat.items()
        if key == "nr_dying_descendants" or key.startswith("nr_dying_subsys_")
    ):
        raise ControllerProtocolError(
            "pre-effect payload cgroup has visible or dying descendants"
        )
    return {
        "schemaVersion": 27,
        "knownNoChild": True,
        "S": _pre_effect_descriptor_identity_v27(
            custody.supervisor_fd, expected_type="directory"
        ),
        "P": _pre_effect_descriptor_identity_v27(
            payload_fd, expected_type="directory"
        ),
        "O": {
            "operationId": custody.binding["operationId"],
            "stageLocation": custody.binding["stageLocation"],
            "stagePlanSha256": custody.binding["stagePlanSha256"],
            "payloadName": custody.payload_name,
            "payloadProcs": _pre_effect_descriptor_identity_v27(
                payload_procs, expected_type="file"
            ),
            "cgroupStat": stat_identity,
        },
        "payloadEntries": list(names),
        "events": events,
        "cgroupStat": cgroup_stat,
        "placementMask": 0,
    }


def _cgroup2_supervisor_observation_v27(descriptor: int) -> dict[str, Any]:
    """Bind a supervisor dirfd to the Linux cgroup2 kernfs instance."""

    metadata = os.fstat(descriptor)
    buffer = (ctypes.c_byte * 256)()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fstatfs(descriptor, ctypes.byref(buffer)) != 0:
        error = ctypes.get_errno()
        raise ControllerProtocolError(
            f"controller cannot prove cgroup2 supervisor filesystem: "
            f"{os.strerror(error)}"
        )
    return {
        "schemaVersion": 27,
        "filesystemMagic": ctypes.c_long.from_buffer(buffer).value,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "type": "directory" if stat.S_ISDIR(metadata.st_mode) else "unsupported",
    }


def _prove_cgroup2_supervisor_fd_v27(
    descriptor: int,
    *,
    observer: Any = None,
) -> dict[str, Any]:
    observation = (
        _cgroup2_supervisor_observation_v27(descriptor)
        if observer is None
        else observer(descriptor)
    )
    metadata = os.fstat(descriptor)
    expected = {
        "schemaVersion": 27,
        "filesystemMagic": _CGROUP2_SUPER_MAGIC_V27,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "type": "directory",
    }
    if observation != expected:
        raise ControllerProtocolError(
            "controller supervisor descriptor is not the exact cgroup2 kernfs directory"
        )
    return dict(expected)


def _cgroup_entry_identity_v27(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
    )


def _observed_cgroup_mode_v27(descriptor: int, observer: Any = None) -> int:
    if observer is None:
        return stat.S_IMODE(os.fstat(descriptor).st_mode)
    value = observer(descriptor)
    if type(value) is not int or value < 0 or value > 0o7777:
        raise ControllerProtocolError("controller cgroup mode proof is invalid")
    return value


def _open_rebound_cgroup_interface_v27(parent_fd: int, name: str) -> None:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            getattr(os, "O_PATH", os.O_RDONLY)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or _cgroup_entry_identity_v27(after)
            != _cgroup_entry_identity_v27(before)
        ):
            raise ControllerProtocolError(
                "controller cgroup interface changed before descriptor open"
            )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _decode_cgroup_stat_bytes_v27(raw: bytes) -> dict[str, int]:
    """Decode one bounded descriptor-read modern cgroup.stat payload."""

    if len(raw) >= 4096 or not raw.endswith(b"\n"):
        raise ControllerProtocolError("controller cgroup.stat is not bounded")
    fields: dict[str, int] = {}
    for line in raw.splitlines():
        parts = line.split(b" ")
        if len(parts) != 2:
            raise ControllerProtocolError("controller cgroup.stat is malformed")
        try:
            key = parts[0].decode("ascii")
            encoded_value = parts[1].decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ControllerProtocolError(
                "controller cgroup.stat is malformed"
            ) from exc
        if not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", encoded_value):
            raise ControllerProtocolError("controller cgroup.stat is malformed")
        value = int(encoded_value, 10)
        controller_name = None
        for prefix in ("nr_subsys_", "nr_dying_subsys_"):
            if key.startswith(prefix):
                controller_name = key.removeprefix(prefix)
                break
        if (
            key in fields
            or value > (1 << 64) - 1
            or (
                key not in {"nr_descendants", "nr_dying_descendants"}
                and (
                    controller_name is None
                    or not _CGROUP_STAT_CONTROLLER_V27.fullmatch(controller_name)
                )
            )
        ):
            raise ControllerProtocolError("controller cgroup.stat is malformed")
        fields[key] = value
    if not {"nr_descendants", "nr_dying_descendants"}.issubset(fields):
        raise ControllerProtocolError("controller cgroup.stat is malformed")
    live = {
        key.removeprefix("nr_subsys_")
        for key in fields
        if key.startswith("nr_subsys_")
    }
    dying = {
        key.removeprefix("nr_dying_subsys_")
        for key in fields
        if key.startswith("nr_dying_subsys_")
    }
    if live != dying:
        raise ControllerProtocolError("controller cgroup.stat is malformed")
    return fields


def _read_cgroup_stat_v27(payload_fd: int) -> dict[str, int]:
    """Read modern cgroup-v2 counters without assuming a controller set.

    The kernel exposes zero or more per-controller counter pairs independently
    of delegation enablement at this node.  Admission therefore binds a closed
    controller-name grammar and requires every observed live counter to have
    its dying-counter peer (and conversely), rather than guessing from
    cgroup.controllers or cgroup.subtree_control.
    """

    descriptor = os.open(
        "cgroup.stat",
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=payload_fd,
    )
    try:
        raw = os.pread(descriptor, 4096, 0)
    finally:
        os.close(descriptor)
    return _decode_cgroup_stat_bytes_v27(raw)


def _cgroup_stat_matches_visible_v27(fields: Mapping[str, int], visible: int) -> bool:
    return (
        fields.get("nr_descendants") == visible
        and all(
            value == 0
            for key, value in fields.items()
            if key == "nr_dying_descendants"
            or key.startswith("nr_dying_subsys_")
        )
    )


def _split_cgroup_children_v27(
    payload_fd: int,
    *,
    cgroup2_observer: Any,
    expected_device: int,
    worker_uid: int,
    worker_gid: int,
) -> dict[str, tuple[int, tuple[int, ...]]]:
    """Open the closed Podman 5.4.1 split topology below one private P."""

    opened: dict[str, tuple[int, tuple[int, ...]]] = {}
    payload_names = 0
    try:
        for name in sorted(os.listdir(payload_fd), key=os.fsencode):
            before = os.stat(name, dir_fd=payload_fd, follow_symlinks=False)
            if stat.S_ISREG(before.st_mode):
                _open_rebound_cgroup_interface_v27(payload_fd, name)
                continue
            if not stat.S_ISDIR(before.st_mode):
                raise ControllerProtocolError(
                    "controller split cgroup contains a symlink or special entry"
                )
            if name == "runtime":
                expected_mode = _SPLIT_RUNTIME_MODE_V27
            elif _SPLIT_PAYLOAD_NAME_V27.fullmatch(name):
                payload_names += 1
                expected_mode = _SPLIT_PAYLOAD_MODE_V27
            else:
                raise ControllerProtocolError(
                    "controller split cgroup topology has an unexpected directory"
                )
            if name in opened or payload_names > 1 or len(opened) >= 2:
                raise ControllerProtocolError(
                    "controller split cgroup topology is duplicated"
                )
            descriptor = os.open(
                name,
                getattr(os, "O_PATH", os.O_RDONLY)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=payload_fd,
            )
            after = os.fstat(descriptor)
            identity = _cgroup_entry_identity_v27(before)
            if _cgroup_entry_identity_v27(after) != identity:
                os.close(descriptor)
                raise ControllerProtocolError(
                    "controller split cgroup changed before descriptor open"
                )
            proof = _prove_cgroup2_supervisor_fd_v27(
                descriptor, observer=cgroup2_observer
            )
            if (
                proof["device"] != expected_device
                or after.st_uid != worker_uid
                or after.st_gid != worker_gid
                or stat.S_IMODE(after.st_mode) != expected_mode
            ):
                os.close(descriptor)
                raise ControllerProtocolError(
                    "controller split cgroup owner/mode/filesystem changed"
                )
            opened[name] = (descriptor, identity)
        return opened
    except BaseException:
        for descriptor, _identity in opened.values():
            os.close(descriptor)
        raise


def _retire_split_cgroup_children_v27(
    payload_fd: int,
    *,
    controller_uid: int,
    worker_uid: int,
    worker_gid: int,
    cgroup2_observer: Any = None,
    monotonic_clock: Any = None,
    sleeper: Any = None,
) -> None:
    """Retire only the exact Podman split descendants after P is drained."""

    root = _prove_cgroup2_supervisor_fd_v27(
        payload_fd, observer=cgroup2_observer
    )
    root_metadata = os.fstat(payload_fd)
    if (
        root_metadata.st_uid != controller_uid
        or root_metadata.st_gid != worker_gid
        or stat.S_IMODE(root_metadata.st_mode) != _LIFECYCLE_CGROUP_MODE_V27
    ):
        raise ControllerProtocolError(
            "controller payload cgroup owner/mode changed during recovery"
        )
    opened = _split_cgroup_children_v27(
        payload_fd,
        cgroup2_observer=cgroup2_observer,
        expected_device=int(root["device"]),
        worker_uid=worker_uid,
        worker_gid=worker_gid,
    )
    initial_names = set(opened)
    try:
        initial_stat = _read_cgroup_stat_v27(payload_fd)
        if initial_stat["nr_descendants"] != len(opened):
            raise ControllerProtocolError(
                "controller split cgroup descendant count changed"
        )
        for name in sorted(opened, key=os.fsencode, reverse=True):
            descriptor, identity = opened[name]
            os.close(descriptor)
            opened[name] = (-1, identity)
            for attempt in range(_CGROUP_RETIRE_RETRIES_V27):
                try:
                    os.rmdir(name, dir_fd=payload_fd)
                    initial_names.remove(name)
                    current = _split_cgroup_children_v27(
                        payload_fd,
                        cgroup2_observer=cgroup2_observer,
                        expected_device=int(root["device"]),
                        worker_uid=worker_uid,
                        worker_gid=worker_gid,
                    )
                    try:
                        current_stat = _read_cgroup_stat_v27(payload_fd)
                        if (
                            set(current) != initial_names
                            or current_stat["nr_descendants"] != len(current)
                        ):
                            raise ControllerProtocolError(
                                "controller split cgroup changed after retirement"
                            )
                    finally:
                        for current_fd, _ in current.values():
                            os.close(current_fd)
                    break
                except OSError as exc:
                    if exc.errno not in {errno.EBUSY, errno.ENOTEMPTY}:
                        raise ControllerProtocolError(
                            f"controller cannot retire split cgroup {name}: {exc}"
                        ) from exc
                    current = _split_cgroup_children_v27(
                        payload_fd,
                        cgroup2_observer=cgroup2_observer,
                        expected_device=int(root["device"]),
                        worker_uid=worker_uid,
                        worker_gid=worker_gid,
                    )
                    try:
                        if set(current) != initial_names:
                            raise ControllerProtocolError(
                                "controller split cgroup changed during retirement"
                            )
                        if current[name][1] != identity:
                            raise ControllerProtocolError(
                                "controller split cgroup was replaced during retirement"
                            )
                        retry_stat = _read_cgroup_stat_v27(payload_fd)
                        if retry_stat["nr_descendants"] != len(current):
                            raise ControllerProtocolError(
                                "controller split cgroup descendant count changed"
                            )
                    finally:
                        for current_fd, _ in current.values():
                            os.close(current_fd)
                    if attempt + 1 == _CGROUP_RETIRE_RETRIES_V27:
                        raise ControllerProtocolError(
                            "controller split cgroup retirement timed out"
                        ) from exc
                    (sleeper or time.sleep)(0.02)
        final = _split_cgroup_children_v27(
            payload_fd,
            cgroup2_observer=cgroup2_observer,
            expected_device=int(root["device"]),
            worker_uid=worker_uid,
            worker_gid=worker_gid,
        )
        try:
            final_stat = _read_cgroup_stat_v27(payload_fd)
            if final or final_stat["nr_descendants"] != 0:
                raise ControllerProtocolError(
                    "controller split cgroup descendants remain after retirement"
                )
            # Dying CSS counters describe already-unlinked kernel objects and
            # have no bounded lifetime.  Preserve their observation for the
            # enclosing terminal receipt; correctness is instead the fresh
            # zero-visible/zero-descendant proof followed by successful P rmdir.
        finally:
            for descriptor, _ in final.values():
                os.close(descriptor)
    finally:
        for descriptor, _identity in opened.values():
            if descriptor >= 0:
                os.close(descriptor)


def _retire_lifecycle_cgroups_v27(
    payload_fd: int,
    *,
    controller_uid: int,
    worker_uid: int,
    worker_gid: int,
    cgroup2_observer: Any = None,
    cgroup_mode_observer: Any = None,
    retirement_intent: Mapping[str, Any] | None = None,
    persist_intent: Any = None,
    phase_hook: Any = None,
) -> dict[str, Any]:
    """Retire the closed Podman 5.4.1 lifecycle-leaf topology below P.

    Source contract: the init command (L1) computes its OCI payload path from
    L1 before CreateContainer moves Podman/conmon into sibling ``runtime``.
    Thus only L1 may contain the exact runtime + libpod-payload sibling pair;
    L0 and L2..L5 have no descendants.
    """

    root = _prove_cgroup2_supervisor_fd_v27(payload_fd, observer=cgroup2_observer)
    root_metadata = os.fstat(payload_fd)
    if (
        root_metadata.st_uid != controller_uid
        or root_metadata.st_gid != worker_gid
        or _observed_cgroup_mode_v27(payload_fd, cgroup_mode_observer)
        != _PAYLOAD_CGROUP_MODE_V27
    ):
        raise ControllerProtocolError(
            "controller payload cgroup owner/mode changed during recovery"
        )

    def normalize_preparation_half_state(directory_fd: int) -> bool:
        """Repair only an empty controller-created Li chmod crash prefix."""

        directory = os.fstat(directory_fd)
        mode = _observed_cgroup_mode_v27(
            directory_fd, cgroup_mode_observer
        )
        controls: list[tuple[int, int]] = []
        try:
            for name in (
                "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"
            ):
                descriptor = os.open(
                    name,
                    os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                metadata = os.fstat(descriptor)
                control_mode = stat.S_IMODE(metadata.st_mode)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != controller_uid
                    or metadata.st_gid != worker_gid
                    or metadata.st_nlink != 1
                    or control_mode not in {0o644, 0o660}
                ):
                    raise ControllerProtocolError(
                        "controller lifecycle preparation control is substituted"
                    )
                controls.append((descriptor, control_mode))
            incomplete = mode == (
                _LIFECYCLE_CGROUP_MODE_V27 | stat.S_ISGID
            ) or any(control_mode != 0o660 for _, control_mode in controls)
            if not incomplete:
                return False
            if (
                directory.st_uid != controller_uid
                or directory.st_gid != worker_gid
                or mode not in {
                    _LIFECYCLE_CGROUP_MODE_V27,
                    _LIFECYCLE_CGROUP_MODE_V27 | stat.S_ISGID,
                }
            ):
                raise ControllerProtocolError(
                    "controller lifecycle preparation directory is substituted"
                )
            for name in sorted(os.listdir(directory_fd), key=os.fsencode):
                entry = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if stat.S_ISREG(entry.st_mode):
                    _open_rebound_cgroup_interface_v27(directory_fd, name)
                    continue
                raise ControllerProtocolError(
                    "controller lifecycle preparation half-state is not empty"
                )
            if os.pread(controls[0][0], 4096, 0).strip():
                raise ControllerProtocolError(
                    "controller lifecycle preparation half-state is populated"
                )
            fields = _read_cgroup_stat_v27(directory_fd)
            if fields["nr_descendants"] != 0 or any(
                value != 0
                for key, value in fields.items()
                if key == "nr_dying_descendants"
                or key.startswith("nr_dying_subsys_")
            ):
                raise ControllerProtocolError(
                    "controller lifecycle preparation half-state has descendants"
                )
            os.fchmod(directory_fd, _LIFECYCLE_CGROUP_MODE_V27)
            for descriptor, _control_mode in controls:
                os.fchmod(descriptor, 0o660)
            if (
                _observed_cgroup_mode_v27(
                    directory_fd, cgroup_mode_observer
                ) != _LIFECYCLE_CGROUP_MODE_V27
                or any(
                    stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o660
                    for descriptor, _ in controls
                )
            ):
                raise ControllerProtocolError(
                    "controller lifecycle preparation half-state normalization failed"
                )
            return True
        finally:
            for descriptor, _mode in reversed(controls):
                os.close(descriptor)

    def directories(directory_fd: int) -> list[str]:
        result: list[str] = []
        for name in sorted(os.listdir(directory_fd), key=os.fsencode):
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISREG(before.st_mode):
                _open_rebound_cgroup_interface_v27(directory_fd, name)
                continue
            if not stat.S_ISDIR(before.st_mode):
                raise ControllerProtocolError(
                    "controller lifecycle cgroup contains a symlink or special entry"
                )
            result.append(name)
        return result

    def delegated_controls(directory_fd: int) -> tuple[str, ...]:
        opened_controls: list[int] = []
        try:
            for name in (
                "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"
            ):
                descriptor = os.open(
                    name,
                    os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                opened_controls.append(descriptor)
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != controller_uid
                    or metadata.st_gid != worker_gid
                    or stat.S_IMODE(metadata.st_mode) != 0o660
                ):
                    raise ControllerProtocolError(
                        "controller lifecycle delegated control identity changed"
                    )
            return _read_cgroup_tokens_v27(
                opened_controls[2], "lifecycle cgroup.subtree_control"
            )
        finally:
            for descriptor in reversed(opened_controls):
                os.close(descriptor)

    leaf_names = directories(payload_fd)
    ordinals: list[int] = []
    for name in leaf_names:
        match = re.fullmatch(r"lifecycle-([0-5])", name)
        if match is None:
            raise ControllerProtocolError(
                "controller lifecycle cgroup topology is reordered or unexpected"
            )
        ordinals.append(int(match.group(1)))
    mask = sum(1 << ordinal for ordinal in ordinals)
    if len(ordinals) != len(set(ordinals)) or (
        retirement_intent is None
        and mask not in native_boundary_v27._LIFECYCLE_RECOVERY_MASKS_V27
    ):
        raise ControllerProtocolError(
            "controller lifecycle cgroup topology is reordered or unexpected"
        )
    opened: list[int] = []
    removal: list[tuple[int, str, tuple[int, ...]]] = []
    expected_by_parent: dict[int, set[str]] = {payload_fd: set(leaf_names)}
    visible = len(leaf_names)
    init_controllers: tuple[str, ...] = ()
    try:
        for leaf_name, ordinal in zip(leaf_names, ordinals):
            leaf_fd = os.open(
                leaf_name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=payload_fd,
            )
            opened.append(leaf_fd)
            leaf = os.fstat(leaf_fd)
            proof = _prove_cgroup2_supervisor_fd_v27(
                leaf_fd, observer=cgroup2_observer
            )
            if (
                proof["device"] != root["device"]
                or leaf.st_uid != controller_uid
                or leaf.st_gid != worker_gid
            ):
                raise ControllerProtocolError(
                    "controller lifecycle cgroup owner/mode/filesystem changed"
                )
            normalize_preparation_half_state(leaf_fd)
            if (
                _observed_cgroup_mode_v27(leaf_fd, cgroup_mode_observer)
                != _LIFECYCLE_CGROUP_MODE_V27
            ):
                raise ControllerProtocolError(
                    "controller lifecycle cgroup owner/mode/filesystem changed"
                )
            enabled = delegated_controls(leaf_fd)
            descendants = directories(leaf_fd)
            expected_by_parent[leaf_fd] = set(descendants)
            if ordinal != 1:
                if descendants or enabled:
                    raise ControllerProtocolError(
                        "non-init lifecycle cgroup acquired split descendants"
                    )
                removal.append(
                    (
                        payload_fd,
                        leaf_name,
                        _cgroup_entry_identity_v27(
                            os.stat(leaf_name, dir_fd=payload_fd, follow_symlinks=False)
                        ),
                    )
                )
                continue
            split = _split_cgroup_children_v27(
                leaf_fd,
                cgroup2_observer=cgroup2_observer,
                expected_device=int(root["device"]),
                worker_uid=worker_uid,
                worker_gid=worker_gid,
            )
            try:
                init_controllers = tuple(enabled)
                if split and set(enabled) != set(_DELEGATED_CONTROLLERS_V27):
                    raise ControllerProtocolError(
                        "init lifecycle controllers are not the exact enabled set"
                    )
                if not split and not set(enabled).issubset(
                    _DELEGATED_CONTROLLERS_V27
                ):
                    raise ControllerProtocolError(
                        "init lifecycle controllers contain an unexpected member"
                    )
                if set(split) != set(descendants):
                    raise ControllerProtocolError(
                        "init lifecycle split topology changed during admission"
                    )
                visible += len(split)
                for name, (descriptor, _identity) in split.items():
                    if directories(descriptor):
                        raise ControllerProtocolError(
                            "controller split child has an unexpected directory"
                        )
                    removal.append(
                        (
                            leaf_fd,
                            name,
                            _cgroup_entry_identity_v27(
                                os.stat(name, dir_fd=leaf_fd, follow_symlinks=False)
                            ),
                        )
                    )
            finally:
                for descriptor, _identity in split.values():
                    os.close(descriptor)
            leaf_identity = _cgroup_entry_identity_v27(
                os.stat(leaf_name, dir_fd=payload_fd, follow_symlinks=False)
            )
            if descendants:
                leaf_identity = (
                    *leaf_identity[:-1], leaf_identity[-1] - len(descendants)
                )
            removal.append(
                (
                    payload_fd,
                    leaf_name,
                    leaf_identity,
                )
            )
        observed_stat = _read_cgroup_stat_v27(payload_fd)
        if observed_stat["nr_descendants"] != visible:
            raise ControllerProtocolError(
                "controller lifecycle cgroup descendant count changed"
            )
        parent_names = {
            payload_fd: "payload",
            **{
                descriptor: "lifecycle-1"
                for descriptor in expected_by_parent
                if descriptor != payload_fd
            },
        }
        current_plan = [
            {
                "parent": parent_names[parent_fd],
                "name": name,
                "identity": {
                    "device": identity[0],
                    "inode": identity[1],
                    "uid": identity[2],
                    "gid": identity[3],
                    "mode": f"{stat.S_IMODE(identity[4]):04o}",
                    "nlink": identity[5],
                },
            }
            for parent_fd, name, identity in removal
        ]
        payload_identity = {
            "device": root_metadata.st_dev,
            "inode": root_metadata.st_ino,
            "uid": root_metadata.st_uid,
            "gid": root_metadata.st_gid,
            "mode": f"{_observed_cgroup_mode_v27(payload_fd, cgroup_mode_observer):04o}",
        }
        if retirement_intent is None:
            intent = native_boundary_v27._decode_controller_retirement_intent_v27(
                {
                    "schemaVersion": 27,
                    "payloadIdentity": payload_identity,
                    "placementMask": mask,
                    "visibleDescendants": visible,
                    "initControllers": list(init_controllers),
                    "preRemovalCgroupStat": dict(observed_stat),
                    "removalPlan": current_plan,
                }
            )
        else:
            intent = native_boundary_v27._decode_controller_retirement_intent_v27(
                retirement_intent
            )
            if intent["payloadIdentity"] != payload_identity:
                raise ControllerProtocolError(
                    "controller retirement intent payload identity changed"
                )
            full_plan = intent["removalPlan"]
            suffixes = [
                index for index in range(len(full_plan) + 1)
                if full_plan[index:] == current_plan
            ]
            if len(suffixes) != 1:
                raise ControllerProtocolError(
                    "controller retirement state is not an exact removal suffix"
                )
        if callable(persist_intent):
            persist_intent(intent)
        if callable(phase_hook):
            phase_hook("retirement-intent-durable")
        for removal_index, (parent_fd, name, identity) in enumerate(removal):
            for attempt in range(_CGROUP_RETIRE_RETRIES_V27):
                current_names = set(directories(parent_fd))
                if current_names != expected_by_parent[parent_fd]:
                    raise ControllerProtocolError(
                        "controller lifecycle topology changed during retirement"
                    )
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _cgroup_entry_identity_v27(current) != identity:
                    raise ControllerProtocolError(
                        "controller lifecycle cgroup was replaced during retirement"
                    )
                try:
                    os.rmdir(name, dir_fd=parent_fd)
                except OSError as exc:
                    if exc.errno not in {errno.EBUSY, errno.ENOTEMPTY}:
                        raise
                    if attempt + 1 == _CGROUP_RETIRE_RETRIES_V27:
                        raise ControllerProtocolError(
                            "controller lifecycle cgroup retirement timed out"
                        ) from exc
                    time.sleep(0.02)
                    continue
                expected_by_parent[parent_fd].remove(name)
                if set(directories(parent_fd)) != expected_by_parent[parent_fd]:
                    raise ControllerProtocolError(
                        "controller lifecycle topology changed after retirement"
                    )
                if callable(phase_hook):
                    phase_hook(
                        f"retirement-remove-{removal_index}-"
                        f"{parent_names[parent_fd]}-{name}"
                    )
                break
        final_names = directories(payload_fd)
        final_stat = _read_cgroup_stat_v27(payload_fd)
        if final_names or final_stat["nr_descendants"] != 0:
            raise ControllerProtocolError(
                "controller lifecycle cgroup descendants remain after retirement"
            )
        return {
            "schemaVersion": 27,
            "visibleDescendants": intent["visibleDescendants"],
            "placementMask": intent["placementMask"],
            "initControllers": list(intent["initControllers"]),
            "preRemovalCgroupStat": dict(intent["preRemovalCgroupStat"]),
            "terminalCgroupStat": dict(final_stat),
        }
    except OSError as exc:
        raise ControllerProtocolError(
            f"controller cannot retire lifecycle cgroup topology: {exc}"
        ) from exc
    finally:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _p_only_recovery_envelope_v27(
    *, kind: str, payload_name: str, payload_identity: Mapping[str, Any],
    predecessor_sha256: str | None, body: Mapping[str, Any],
    controller_key: bytes,
) -> dict[str, Any]:
    if kind not in {"custody", "intent", "receipt"}:
        raise ControllerProtocolError("P-only recovery artifact kind changed")
    artifact = {
        "schemaVersion": 27,
        "kind": "p-only-" + kind,
        "payloadName": payload_name,
        "payloadIdentity": dict(payload_identity),
        "predecessorSha256": predecessor_sha256,
        "body": dict(body),
    }
    domain = (
        b"startup-factory/beads/v27/controller-p-only-recovery-"
        + kind.encode("ascii") + b"\0"
    )
    return {
        "artifact": artifact,
        "controllerHmac": "hmac-sha256:" + hmac.new(
            controller_key, domain + _canonical(artifact), hashlib.sha256
        ).hexdigest(),
    }


def _verify_p_only_recovery_envelope_v27(
    value: Any, *, kind: str, payload_name: str,
    payload_identity: Mapping[str, Any], predecessor_sha256: str | None,
    controller_key: bytes,
) -> tuple[dict[str, Any], str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"artifact", "controllerHmac"}
        or not isinstance(value["artifact"], Mapping)
    ):
        raise ControllerProtocolError("P-only recovery envelope changed")
    artifact = dict(value["artifact"])
    domain = (
        b"startup-factory/beads/v27/controller-p-only-recovery-"
        + kind.encode("ascii") + b"\0"
    )
    expected = "hmac-sha256:" + hmac.new(
        controller_key, domain + _canonical(artifact), hashlib.sha256
    ).hexdigest()
    if set(artifact) != {
        "schemaVersion", "kind", "payloadName", "payloadIdentity",
        "predecessorSha256", "body",
    } or (
        artifact["schemaVersion"] != 27
        or artifact["kind"] != "p-only-" + kind
        or artifact["payloadName"] != payload_name
        or artifact["payloadIdentity"] != payload_identity
        or artifact["predecessorSha256"] != predecessor_sha256
        or not hmac.compare_digest(str(value["controllerHmac"]), expected)
    ):
        raise ControllerProtocolError("P-only recovery binding changed")
    if kind == "custody":
        candidate = artifact["body"]
        if (
            not isinstance(candidate, Mapping)
            or set(candidate) != {"schemaVersion", "payloadIdentity"}
            or candidate["schemaVersion"] != 27
            or candidate["payloadIdentity"] != payload_identity
        ):
            raise ControllerProtocolError("P-only recovery custody changed")
        body = {
            "schemaVersion": 27,
            "payloadIdentity": dict(payload_identity),
        }
    elif kind == "intent":
        body = native_boundary_v27._decode_controller_retirement_intent_v27(
            artifact["body"]
        )
    else:
        candidate = artifact["body"]
        if not isinstance(candidate, Mapping):
            raise ControllerProtocolError("P-only recovery receipt changed")
        body = native_boundary_v27._decode_controller_retirement_v27(
            candidate, candidate.get("placementMask")
        )
    return body, _sha(_canonical(dict(value)))


def _recover_p_only_payload_v27(
    payload_fd: int,
    *, payload_name: str, payload_identity: Mapping[str, Any],
    controller_uid: int, worker_uid: int, worker_gid: int,
    controller_key: bytes, recovery_journal_root: Path,
    cgroup2_observer: Any = None, cgroup_mode_observer: Any = None,
    phase_hook: Any = None,
) -> dict[str, Any]:
    """Retire a pre-arena P only through a controller-authenticated journal."""

    parent_fd = os.open(
        recovery_journal_root.parent,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        try:
            os.mkdir(recovery_journal_root.name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        root_fd = os.open(
            recovery_journal_root.name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    root_metadata = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or root_metadata.st_gid != os.getegid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        os.close(root_fd)
        raise ControllerProtocolError("P-only recovery journal root changed")
    journal_fd = kill = events = -1
    try:
        try:
            os.mkdir(payload_name, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except FileExistsError:
            pass
        journal_fd = os.open(
            payload_name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        journal_metadata = os.fstat(journal_fd)
        if (
            not stat.S_ISDIR(journal_metadata.st_mode)
            or journal_metadata.st_uid != os.geteuid()
            or journal_metadata.st_gid != os.getegid()
            or stat.S_IMODE(journal_metadata.st_mode) != 0o700
        ):
            raise ControllerProtocolError("P-only recovery journal changed")

        def read(kind: str, predecessor: str | None):
            filename = {
                "custody": "controller-custody.json",
                "intent": "controller-retirement.intent.json",
                "receipt": "controller-retirement.json",
            }[kind]
            temporary_name = "." + filename + ".tmp"
            final_metadata = temporary_metadata = None
            temporary_descriptor = -1
            try:
                descriptor = os.open(
                    filename,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=journal_fd,
                )
            except FileNotFoundError:
                descriptor = -1
            try:
                temporary_descriptor = os.open(
                    temporary_name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=journal_fd,
                )
            except FileNotFoundError:
                temporary_descriptor = -1
            if descriptor < 0 and temporary_descriptor < 0:
                return None

            def inspect(
                descriptor: int, label: str, *, allow_incomplete: bool = False
            ) -> tuple[bytes, os.stat_result]:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_gid != os.getegid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink not in {1, 2}
                    or not (
                        0 <= metadata.st_size <= MAX_MESSAGE_BYTES
                        if allow_incomplete
                        else 1 <= metadata.st_size <= MAX_MESSAGE_BYTES
                    )
                ):
                    raise ControllerProtocolError(
                        f"P-only recovery {label} identity changed"
                    )
                content = os.pread(descriptor, metadata.st_size + 1, 0)
                if len(content) != metadata.st_size:
                    raise ControllerProtocolError(
                        f"P-only recovery {label} is truncated"
                    )
                return content, metadata

            try:
                if descriptor >= 0:
                    raw, final_metadata = inspect(descriptor, "artifact")
                else:
                    raw, temporary_metadata = inspect(
                        temporary_descriptor,
                        "temporary artifact",
                        allow_incomplete=True,
                    )
                if descriptor >= 0 and temporary_descriptor >= 0:
                    temporary_raw, temporary_metadata = inspect(
                        temporary_descriptor, "temporary artifact"
                    )
                    if (
                        temporary_raw != raw
                        or (temporary_metadata.st_dev, temporary_metadata.st_ino)
                        != (final_metadata.st_dev, final_metadata.st_ino)
                        or temporary_metadata.st_nlink != 2
                        or final_metadata.st_nlink != 2
                    ):
                        raise ControllerProtocolError(
                            "P-only recovery installed temporary changed"
                        )
            finally:
                for item in (temporary_descriptor, descriptor):
                    if item >= 0:
                        os.close(item)
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                if descriptor < 0 and temporary_metadata.st_nlink == 1:
                    # A crash before/full-write prefix is not authority.  Its
                    # bytes remain in place and the deterministic writer must
                    # prove they are an exact prefix of the expected envelope
                    # before any later destructive suffix can run.
                    return None
                raise ControllerProtocolError(
                    "P-only recovery artifact is malformed"
                ) from exc
            if _canonical(value) != raw:
                raise ControllerProtocolError(
                    "P-only recovery artifact is noncanonical"
                )
            verified = _verify_p_only_recovery_envelope_v27(
                value,
                kind=kind,
                payload_name=payload_name,
                payload_identity=payload_identity,
                predecessor_sha256=predecessor,
                controller_key=controller_key,
            )
            if descriptor < 0:
                try:
                    os.link(
                        temporary_name,
                        filename,
                        src_dir_fd=journal_fd,
                        dst_dir_fd=journal_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise ControllerProtocolError(
                        "P-only recovery final appeared during temp promotion"
                    ) from exc
                os.unlink(temporary_name, dir_fd=journal_fd)
                os.fsync(journal_fd)
            elif temporary_metadata is not None:
                os.unlink(temporary_name, dir_fd=journal_fd)
                os.fsync(journal_fd)
            return verified

        custody_record = read("custody", None)
        if custody_record is None:
            custody_envelope = _p_only_recovery_envelope_v27(
                kind="custody",
                payload_name=payload_name,
                payload_identity=payload_identity,
                predecessor_sha256=None,
                body={
                    "schemaVersion": 27,
                    "payloadIdentity": dict(payload_identity),
                },
                controller_key=controller_key,
            )
            native_boundary_v27._persist_atomic_retirement_artifact_v27(
                journal_fd,
                "controller-custody.json",
                _canonical(custody_envelope),
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
                phase_hook=phase_hook,
            )
            custody_record = (
                custody_envelope["artifact"]["body"],
                _sha(_canonical(custody_envelope)),
            )
        custody_sha = custody_record[1]
        intent_record = read("intent", custody_sha)
        intent = None if intent_record is None else intent_record[0]
        intent_sha = None if intent_record is None else intent_record[1]
        receipt_record = read("receipt", intent_sha)
        kill = os.open(
            "cgroup.kill", os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=payload_fd,
        )
        events = os.open(
            "cgroup.events", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=payload_fd,
        )
        native_boundary_v27._write_all_v27(kill, b"1\n")
        if b"populated 0\n" not in os.pread(events, 4096, 0):
            raise ControllerProtocolError("P-only recovery payload is populated")
        if receipt_record is not None:
            return receipt_record[0]

        persisted_intent_sha = intent_sha
        def persist_intent(value: Mapping[str, Any]) -> None:
            nonlocal persisted_intent_sha
            envelope = _p_only_recovery_envelope_v27(
                kind="intent",
                payload_name=payload_name,
                payload_identity=payload_identity,
                predecessor_sha256=custody_sha,
                body=value,
                controller_key=controller_key,
            )
            native_boundary_v27._persist_atomic_retirement_artifact_v27(
                journal_fd,
                "controller-retirement.intent.json",
                _canonical(envelope),
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
                phase_hook=phase_hook,
            )
            persisted_intent_sha = _sha(_canonical(envelope))

        retirement = _retire_lifecycle_cgroups_v27(
            payload_fd,
            controller_uid=controller_uid,
            worker_uid=worker_uid,
            worker_gid=worker_gid,
            cgroup2_observer=cgroup2_observer,
            cgroup_mode_observer=cgroup_mode_observer,
            retirement_intent=intent,
            persist_intent=persist_intent,
            phase_hook=phase_hook,
        )
        if persisted_intent_sha is None:
            raise ControllerProtocolError("P-only recovery intent was not durable")
        receipt = {
            **retirement,
            "controllerTrackedPlacementMask": retirement["placementMask"],
        }
        envelope = _p_only_recovery_envelope_v27(
            kind="receipt",
            payload_name=payload_name,
            payload_identity=payload_identity,
            predecessor_sha256=persisted_intent_sha,
            body=receipt,
            controller_key=controller_key,
        )
        native_boundary_v27._persist_atomic_retirement_artifact_v27(
            journal_fd,
            "controller-retirement.json",
            _canonical(envelope),
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            phase_hook=phase_hook,
        )
        return receipt
    finally:
        for descriptor in (events, kill, journal_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)


def _recover_controller_payload_cgroups_v27(
    supervisor_fd: int,
    *,
    controller_uid: int,
    worker_uid: int,
    worker_gid: int,
    cgroup2_observer: Any = None,
    cgroup_mode_observer: Any = None,
    result_runtime_root: Path | None = None,
    controller_key: bytes | None = None,
    recovery_journal_root: Path | None = None,
    phase_hook: Any = None,
) -> dict[str, dict[str, Any]]:
    """Drain and retire only exact stale controller-owned payload children."""

    _prove_cgroup2_supervisor_fd_v27(
        supervisor_fd,
        observer=cgroup2_observer,
    )
    if controller_key is None or not 32 <= len(controller_key) <= 4096:
        raise ControllerProtocolError(
            "cgroup recovery requires the controller-only authentication key"
        )
    try:
        names = sorted(os.listdir(supervisor_fd), key=os.fsencode)
    except OSError as exc:
        raise ControllerProtocolError(
            f"controller cannot enumerate cgroup recovery state: {exc}"
        ) from exc
    recovered: dict[str, dict[str, Any]] = {}
    for name in names:
        try:
            metadata = os.stat(name, dir_fd=supervisor_fd, follow_symlinks=False)
        except OSError as exc:
            raise ControllerProtocolError(
                f"controller cannot inspect cgroup recovery entry: {exc}"
            ) from exc
        if stat.S_ISREG(metadata.st_mode):
            interface_fd = -1
            try:
                interface_fd = os.open(
                    name,
                    getattr(os, "O_PATH", os.O_RDONLY)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=supervisor_fd,
                )
                rebound = os.fstat(interface_fd)
                if (
                    rebound.st_dev,
                    rebound.st_ino,
                    rebound.st_uid,
                    rebound.st_gid,
                    rebound.st_mode,
                    rebound.st_nlink,
                ) != (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_uid,
                    metadata.st_gid,
                    metadata.st_mode,
                    metadata.st_nlink,
                ):
                    raise ControllerProtocolError(
                        "controller cgroup interface changed before descriptor open"
                    )
            finally:
                if interface_fd >= 0:
                    os.close(interface_fd)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise ControllerProtocolError(
                "controller cgroup recovery found a symlink or special entry"
            )
        if name == "worker":
            worker_fd = _open_recover_worker_cgroup_v27(
                supervisor_fd,
                metadata,
                controller_uid=controller_uid,
                worker_gid=worker_gid,
                cgroup2_observer=cgroup2_observer,
                cgroup_mode_observer=cgroup_mode_observer,
            )
            os.close(worker_fd)
            continue
        if (
            not re.fullmatch(r"payload-[0-9a-f]{64}-s(?:[1-9]|[1-6][0-9]|7[0-7])-[0-9a-f]{16}", name)
            or metadata.st_uid != controller_uid
            or metadata.st_gid != worker_gid
        ):
            raise ControllerProtocolError(
                "controller cgroup recovery found substituted payload state"
            )
        payload_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=supervisor_fd,
        )
        kill = events = root_fd = result_fd = -1
        try:
            rebound = os.fstat(payload_fd)
            if (
                rebound.st_dev,
                rebound.st_ino,
                rebound.st_uid,
                rebound.st_gid,
                rebound.st_mode,
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_mode,
            ):
                raise ControllerProtocolError(
                    "controller cgroup recovery payload changed before open"
                )
            payload_mode = _observed_cgroup_mode_v27(
                payload_fd, cgroup_mode_observer
            )
            if payload_mode != _PAYLOAD_CGROUP_MODE_V27:
                raise ControllerProtocolError(
                    "controller cgroup recovery found substituted payload state"
                )
            payload_identity = {
                "device": rebound.st_dev,
                "gid": rebound.st_gid,
                "inode": rebound.st_ino,
                "mode": f"{payload_mode:04o}",
                "uid": rebound.st_uid,
            }
            try:
                root_fd, result_fd, stage_plan_sha256 = (
                    _open_recovered_native_result_directory_v27(
                        worker_uid=worker_uid,
                        worker_gid=worker_gid,
                        payload_name=name,
                        runtime_root=result_runtime_root,
                    )
                )
                arena, arena_record_sha256 = _read_recovered_result_arena_v27(
                    result_fd,
                    payload_name=name,
                    stage_plan_sha256=stage_plan_sha256,
                    worker_uid=worker_uid,
                    worker_gid=worker_gid,
                    controller_key=controller_key,
                )
            except ControllerProtocolError as exc:
                if recovery_journal_root is None or not any(
                    marker in str(exc)
                    for marker in (
                        "no durable native result root",
                        "no durable native result candidate",
                        "no controller-authenticated result arena",
                    )
                ):
                    raise
                for descriptor in (result_fd, root_fd):
                    if descriptor >= 0:
                        os.close(descriptor)
                result_fd = root_fd = -1
                retirement = _recover_p_only_payload_v27(
                    payload_fd,
                    payload_name=name,
                    payload_identity=payload_identity,
                    controller_uid=controller_uid,
                    worker_uid=worker_uid,
                    worker_gid=worker_gid,
                    controller_key=controller_key,
                    recovery_journal_root=recovery_journal_root,
                    cgroup2_observer=cgroup2_observer,
                    cgroup_mode_observer=cgroup_mode_observer,
                    phase_hook=phase_hook,
                )
                for descriptor in (payload_fd,):
                    if descriptor >= 0:
                        os.close(descriptor)
                payload_fd = -1
                os.rmdir(name, dir_fd=supervisor_fd)
                try:
                    os.stat(name, dir_fd=supervisor_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ControllerProtocolError(
                        "P-only recovery payload still exists after retirement"
                    )
                if callable(phase_hook):
                    phase_hook("p-only-retirement-payload-removed")
                # P-only recovery cannot make a stage result eligible; retain
                # its controller-authenticated journal solely as audit proof.
                continue
            plan_binding = arena["arena"]
            intent_record = _read_recovered_retirement_artifact_v27(
                result_fd,
                "controller-retirement.intent.json",
                "intent",
                payload_name=name,
                stage_plan_sha256=stage_plan_sha256,
                worker_uid=worker_uid,
                worker_gid=worker_gid,
                controller_key=controller_key,
                arena_record_sha256=arena_record_sha256,
                predecessor_artifact_sha256=None,
            )
            intent = None if intent_record is None else intent_record[0]
            intent_record_sha256 = (
                None if intent_record is None else intent_record[1]
            )
            receipt_record = _read_recovered_retirement_artifact_v27(
                result_fd,
                "controller-retirement.json",
                "receipt",
                payload_name=name,
                stage_plan_sha256=stage_plan_sha256,
                worker_uid=worker_uid,
                worker_gid=worker_gid,
                controller_key=controller_key,
                arena_record_sha256=arena_record_sha256,
                predecessor_artifact_sha256=intent_record_sha256,
            )
            receipt = None if receipt_record is None else receipt_record[0]
            kill = os.open(
                "cgroup.kill",
                os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=payload_fd,
            )
            events = os.open(
                "cgroup.events",
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=payload_fd,
            )
            native_boundary_v27._write_all_v27(kill, b"1\n")
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if b"populated 0\n" in os.pread(events, 4096, 0):
                    break
                time.sleep(0.02)
            else:
                raise ControllerProtocolError(
                    "controller cgroup recovery could not prove payload empty"
                )
            if receipt is not None:
                if intent is None:
                    raise ControllerProtocolError(
                        "durable retirement receipt has no predecessor intent"
                    )
                if any(
                    stat.S_ISDIR(
                        os.stat(
                            entry, dir_fd=payload_fd, follow_symlinks=False
                        ).st_mode
                    )
                    for entry in os.listdir(payload_fd)
                ) or _read_cgroup_stat_v27(payload_fd)["nr_descendants"] != 0:
                    raise ControllerProtocolError(
                        "durable retirement receipt precedes topology retirement"
                    )
                if (
                    receipt["visibleDescendants"] != intent["visibleDescendants"]
                    or receipt["placementMask"] != intent["placementMask"]
                    or receipt["controllerTrackedPlacementMask"]
                    != intent["placementMask"]
                    or receipt["initControllers"] != intent["initControllers"]
                    or receipt["preRemovalCgroupStat"]
                    != intent["preRemovalCgroupStat"]
                    or receipt["terminalCgroupStat"]["nr_descendants"] != 0
                ):
                    raise ControllerProtocolError(
                        "durable retirement receipt differs from its intent"
                    )
                retirement = receipt
            else:
                persisted_intent_envelope: dict[str, Any] | None = None
                persisted_intent_sha256 = intent_record_sha256

                def persist_intent(value: Mapping[str, Any]) -> None:
                    nonlocal persisted_intent_envelope, persisted_intent_sha256
                    envelope = _controller_retirement_envelope_v27(
                        kind="intent",
                        plan=plan_binding,
                        payload_name=name,
                        payload_identity=value["payloadIdentity"],
                        arena_record_sha256=arena_record_sha256,
                        predecessor_artifact_sha256=None,
                        body=value,
                        controller_key=controller_key,
                    )
                    _persist_recovered_retirement_artifact_v27(
                        result_fd,
                        "controller-retirement.intent.json",
                        envelope,
                        payload_name=name,
                        stage_plan_sha256=stage_plan_sha256,
                        worker_uid=worker_uid,
                        worker_gid=worker_gid,
                        phase_hook=phase_hook,
                    )
                    persisted_intent_envelope = envelope
                    persisted_intent_sha256 = _sha(_canonical(envelope))

                retirement = _retire_lifecycle_cgroups_v27(
                    payload_fd,
                    controller_uid=controller_uid,
                    worker_uid=worker_uid,
                    worker_gid=worker_gid,
                    cgroup2_observer=cgroup2_observer,
                    cgroup_mode_observer=cgroup_mode_observer,
                    retirement_intent=intent,
                    persist_intent=persist_intent,
                    phase_hook=phase_hook,
                )
                if persisted_intent_sha256 is None:
                    raise ControllerProtocolError(
                        "retirement receipt lacks a durable authenticated intent"
                    )
                receipt_body = {
                    **retirement,
                    "controllerTrackedPlacementMask": retirement["placementMask"],
                }
                receipt_envelope = _controller_retirement_envelope_v27(
                    kind="receipt",
                    plan=plan_binding,
                    payload_name=name,
                    payload_identity=persisted_intent_envelope[
                        "artifact"
                    ]["payloadIdentity"],
                    arena_record_sha256=arena_record_sha256,
                    predecessor_artifact_sha256=persisted_intent_sha256,
                    body=receipt_body,
                    controller_key=controller_key,
                )
                _persist_recovered_retirement_artifact_v27(
                    result_fd,
                    "controller-retirement.json",
                    receipt_envelope,
                    payload_name=name,
                    stage_plan_sha256=stage_plan_sha256,
                    worker_uid=worker_uid,
                    worker_gid=worker_gid,
                    phase_hook=phase_hook,
                )
                if callable(phase_hook):
                    phase_hook("retirement-receipt-durable")
                retirement = receipt_body
        finally:
            for descriptor in (kill, events, payload_fd, result_fd, root_fd):
                if descriptor >= 0:
                    os.close(descriptor)
        try:
            os.rmdir(name, dir_fd=supervisor_fd)
        except OSError as exc:
            raise ControllerProtocolError(
                f"controller cannot retire recovered payload cgroup: {exc}"
            ) from exc
        if callable(phase_hook):
            phase_hook("retirement-payload-removed")
        try:
            os.stat(name, dir_fd=supervisor_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ControllerProtocolError(
                "controller payload cgroup still exists after retirement"
            )
        recovered[name] = retirement
    return recovered


def _open_recovered_native_result_directory_v27(
    *,
    worker_uid: int,
    worker_gid: int,
    payload_name: str,
    runtime_root: Path | None = None,
) -> tuple[int, int, str]:
    """Root-open the unique worker result directory bound by the payload name."""

    match = re.fullmatch(
        r"payload-([0-9a-f]{64})-s([1-9]|[1-6][0-9]|7[0-7])-([0-9a-f]{16})",
        payload_name,
    )
    if match is None:
        raise ControllerProtocolError(
            "recovered payload name cannot bind a durable retirement receipt"
        )
    root_path = runtime_root if runtime_root is not None else (
        Path("/run/user") / str(worker_uid) / "startup-factory-beads-results"
    )
    try:
        root_fd = os.open(
            root_path,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError as exc:
        raise ControllerProtocolError(
            "recovered payload has no durable native result root"
        ) from exc
    result_fd = -1
    try:
        root = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root.st_mode)
            or root.st_uid != worker_uid
            or root.st_gid != worker_gid
            or stat.S_IMODE(root.st_mode) != 0o700
        ):
            raise ControllerProtocolError(
                "recovered native result root identity changed"
            )
        prefix = f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
        candidates = [
            name for name in os.listdir(root_fd)
            if re.fullmatch(
                re.escape(prefix) + r"[0-9a-f]{48}", name
            )
        ]
        if len(candidates) > 1:
            raise ControllerProtocolError(
                "recovered payload has multiple durable native result candidates"
            )
        if not candidates:
            raise ControllerProtocolError(
                "recovered payload has no durable native result candidate"
            )
        result_fd = os.open(
            candidates[0],
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        result = os.fstat(result_fd)
        if (
            not stat.S_ISDIR(result.st_mode)
            or result.st_uid != worker_uid
            or result.st_gid != worker_gid
            or stat.S_IMODE(result.st_mode) != 0o700
        ):
            raise ControllerProtocolError(
                "recovered native result directory identity changed"
            )
        stage_plan_sha256 = "sha256:" + candidates[0].rsplit("-", 1)[1]
        return root_fd, result_fd, stage_plan_sha256
    except BaseException:
        if result_fd >= 0:
            os.close(result_fd)
        os.close(root_fd)
        raise


def _read_recovered_result_arena_v27(
    result_fd: int,
    *,
    payload_name: str,
    stage_plan_sha256: str,
    worker_uid: int,
    worker_gid: int,
    controller_key: bytes,
) -> tuple[dict[str, Any], str]:
    descriptor = lock_fd = -1
    try:
        descriptor = os.open(
            "arena.json",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=result_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != worker_uid
            or metadata.st_gid != worker_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= MAX_MESSAGE_BYTES
        ):
            raise ControllerProtocolError(
                "controller-authenticated result arena identity changed"
            )
        raw = os.pread(descriptor, metadata.st_size + 1, 0)
        if len(raw) != metadata.st_size:
            raise ControllerProtocolError(
                "controller-authenticated result arena is truncated"
            )
        value = json.loads(raw)
        if _canonical(value) != raw:
            raise ControllerProtocolError(
                "controller-authenticated result arena is noncanonical"
            )
        verified = _verify_controller_result_arena_v27(
            value,
            controller_key,
            payload_name=payload_name,
            stage_plan_sha256=stage_plan_sha256,
        )
        arena = verified["arena"]
        result_metadata = os.fstat(result_fd)
        lock_fd = os.open(
            "operation.lock",
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=result_fd,
        )
        if (
            arena["resultDirectory"]
            != native_boundary_v27._retirement_payload_identity_v27(
                {
                    "device": result_metadata.st_dev,
                    "gid": result_metadata.st_gid,
                    "inode": result_metadata.st_ino,
                    "mode": f"{stat.S_IMODE(result_metadata.st_mode):04o}",
                    "uid": result_metadata.st_uid,
                }
            )
            or arena["operationLock"]
            != native_boundary_v27._operation_lock_projection_v27(
                os.fstat(lock_fd)
            )
        ):
            raise ControllerProtocolError(
                "controller-authenticated result arena descriptor identity changed"
            )
        return verified, _sha(raw)
    except FileNotFoundError as exc:
        raise ControllerProtocolError(
            "recovered payload has no controller-authenticated result arena"
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError(
            "controller-authenticated result arena is malformed"
        ) from exc
    finally:
        for item in (lock_fd, descriptor):
            if item >= 0:
                os.close(item)


def _read_recovered_retirement_artifact_v27(
    result_fd: int,
    filename: str,
    kind: str,
    *,
    payload_name: str,
    stage_plan_sha256: str,
    worker_uid: int,
    worker_gid: int,
    controller_key: bytes,
    arena_record_sha256: str,
    predecessor_artifact_sha256: str | None,
) -> tuple[dict[str, Any], str] | None:
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=result_fd,
            )
        except FileNotFoundError:
            return None
        metadata = os.fstat(descriptor)
        if metadata.st_nlink == 2:
            temp_fd = -1
            try:
                temp_fd = os.open(
                    "." + filename + ".tmp",
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=result_fd,
                )
                temporary = os.fstat(temp_fd)
                if (
                    temporary.st_dev,
                    temporary.st_ino,
                    temporary.st_nlink,
                ) != (metadata.st_dev, metadata.st_ino, 2):
                    raise ControllerProtocolError(
                        "durable controller retirement install hardlink changed"
                    )
            finally:
                if temp_fd >= 0:
                    os.close(temp_fd)
            os.unlink("." + filename + ".tmp", dir_fd=result_fd)
            os.fsync(result_fd)
            metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != worker_uid
            or metadata.st_gid != worker_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= MAX_MESSAGE_BYTES
        ):
            raise ControllerProtocolError(
                "durable controller retirement artifact identity changed"
            )
        raw = os.pread(descriptor, metadata.st_size + 1, 0)
        if len(raw) != metadata.st_size:
            raise ControllerProtocolError(
                "durable controller retirement artifact is truncated"
            )
        value = json.loads(raw)
        if _canonical(value) != raw:
            raise ControllerProtocolError(
                "durable controller retirement artifact is noncanonical"
            )
        return _verify_controller_retirement_envelope_v27(
            value,
            kind=kind,
            controller_key=controller_key,
            payload_name=payload_name,
            stage_plan_sha256=stage_plan_sha256,
            arena_record_sha256=arena_record_sha256,
            predecessor_artifact_sha256=predecessor_artifact_sha256,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError(
            "durable controller retirement artifact is malformed"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _persist_recovered_retirement_artifact_v27(
    result_fd: int,
    filename: str,
    raw_envelope: Mapping[str, Any],
    *,
    payload_name: str,
    stage_plan_sha256: str,
    worker_uid: int,
    worker_gid: int,
    phase_hook: Any = None,
) -> None:
    raw = _canonical(dict(raw_envelope))
    try:
        native_boundary_v27._persist_atomic_retirement_artifact_v27(
            result_fd,
            filename,
            raw,
            owner_uid=worker_uid,
            owner_gid=worker_gid,
            phase_hook=phase_hook,
        )
    except native_boundary_v27.NativeBoundaryV27Error as exc:
        raise ControllerProtocolError(str(exc)) from exc


def _normalize_worker_cgroup_owner_v27(
    descriptor: int,
    metadata: os.stat_result,
    *,
    controller_uid: int,
    worker_gid: int,
    cgroup_mode_observer: Any = None,
) -> os.stat_result:
    """Complete only the exact root-created W ownership crash prefix."""

    mode = _observed_cgroup_mode_v27(descriptor, cgroup_mode_observer)
    if metadata.st_gid != worker_gid or metadata.st_uid not in {0, controller_uid}:
        raise ControllerProtocolError(
            "controller cgroup recovery found substituted worker state"
        )
    if metadata.st_uid == 0:
        if mode not in {
            _WORKER_CGROUP_MODE_V27,
            _WORKER_CGROUP_MODE_V27 | stat.S_ISGID,
        } or os.geteuid() != 0:
            raise ControllerProtocolError(
                "controller root-created worker cgroup half-state is unsafe"
            )
        os.fchown(descriptor, controller_uid, worker_gid)
        os.fchmod(descriptor, _WORKER_CGROUP_MODE_V27)
    elif mode == _WORKER_CGROUP_MODE_V27 | stat.S_ISGID:
        os.fchmod(descriptor, _WORKER_CGROUP_MODE_V27)
    elif mode != _WORKER_CGROUP_MODE_V27:
        raise ControllerProtocolError(
            "controller cgroup recovery found substituted worker state"
        )
    final = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(final.st_mode)
        or final.st_uid != controller_uid
        or final.st_gid != worker_gid
        or _observed_cgroup_mode_v27(descriptor, cgroup_mode_observer)
        != _WORKER_CGROUP_MODE_V27
    ):
        raise ControllerProtocolError(
            "controller worker cgroup ownership normalization failed"
        )
    return final


def _open_recover_worker_cgroup_v27(
    supervisor_fd: int,
    before: os.stat_result,
    *,
    controller_uid: int,
    worker_gid: int,
    cgroup2_observer: Any = None,
    cgroup_mode_observer: Any = None,
) -> int:
    """Open, empty-proof, and normalize the fixed W leaf without following."""

    descriptor = -1
    procs = -1
    try:
        if not stat.S_ISDIR(before.st_mode):
            raise ControllerProtocolError(
                "controller cgroup recovery found substituted worker state"
            )
        descriptor = os.open(
            "worker",
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=supervisor_fd,
        )
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode),
        ) != (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
        ):
            raise ControllerProtocolError(
                "controller worker cgroup changed before descriptor open"
            )
        root = _prove_cgroup2_supervisor_fd_v27(
            supervisor_fd, observer=cgroup2_observer
        )
        worker = _prove_cgroup2_supervisor_fd_v27(
            descriptor, observer=cgroup2_observer
        )
        if worker["device"] != root["device"]:
            raise ControllerProtocolError(
                "controller worker cgroup filesystem changed"
            )
        for name in sorted(os.listdir(descriptor), key=os.fsencode):
            entry = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISREG(entry.st_mode):
                _open_rebound_cgroup_interface_v27(descriptor, name)
                continue
            raise ControllerProtocolError(
                "controller worker cgroup contains a child or special entry"
            )
        procs = os.open(
            "cgroup.procs",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        if os.pread(procs, 4096, 0).strip():
            raise ControllerProtocolError(
                "controller worker cgroup half-state is populated"
            )
        fields = _read_cgroup_stat_v27(descriptor)
        if fields["nr_descendants"] != 0 or any(
            value != 0
            for name, value in fields.items()
            if name == "nr_dying_descendants"
            or name.startswith("nr_dying_subsys_")
        ):
            raise ControllerProtocolError(
                "controller worker cgroup half-state has descendants"
            )
        final = _normalize_worker_cgroup_owner_v27(
            descriptor,
            opened,
            controller_uid=controller_uid,
            worker_gid=worker_gid,
            cgroup_mode_observer=cgroup_mode_observer,
        )
        rebound = os.stat("worker", dir_fd=supervisor_fd, follow_symlinks=False)
        if (
            rebound.st_dev,
            rebound.st_ino,
            rebound.st_uid,
            rebound.st_gid,
            stat.S_IMODE(rebound.st_mode),
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_uid,
            final.st_gid,
            stat.S_IMODE(final.st_mode),
        ):
            raise ControllerProtocolError(
                "controller worker cgroup changed during ownership normalization"
            )
        os.close(procs)
        procs = -1
        return descriptor
    except BaseException:
        if procs >= 0:
            os.close(procs)
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _create_controller_cgroup_custody_v27(
    supervisor_fd: int,
    supervisor_process_fd: int,
    worker_fd: int,
    worker_relative: str,
    plan: Mapping[str, Any],
    *,
    controller_uid: int,
    worker_uid: int,
    worker_gid: int,
    worker_pid: int,
    worker_session_nonce: str,
    cgroup_mode_observer: Any = None,
) -> _ControllerCgroupCustodyV27:
    """Create one controller-owned payload cgroup and pin all control files."""

    name = _payload_cgroup_name_v27(plan)
    supervisor_metadata = os.fstat(supervisor_fd)
    if (
        not stat.S_ISDIR(supervisor_metadata.st_mode)
        or supervisor_metadata.st_uid != controller_uid
        or supervisor_metadata.st_gid != worker_gid
        or _observed_cgroup_mode_v27(supervisor_fd, cgroup_mode_observer)
        != _SUPERVISOR_CGROUP_MODE_V27
    ):
        raise ControllerProtocolError(
            "controller supervisor cgroup owner/mode/type changed"
        )
    try:
        # The setgid half-state is intentional write-ahead evidence: a crash
        # after mkdir but before the final fchmod is recoverable only while the
        # cgroup is still provably empty and has no descendants.
        os.mkdir(name, _PAYLOAD_CGROUP_MODE_V27 | stat.S_ISGID, dir_fd=supervisor_fd)
        payload_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=supervisor_fd,
        )
    except OSError as exc:
        raise ControllerProtocolError(
            f"controller cannot create the exact payload cgroup: {exc}"
        ) from exc
    descriptors: list[int] = [payload_fd]
    try:
        payload_metadata = os.fstat(payload_fd)
        os.fchmod(payload_fd, _PAYLOAD_CGROUP_MODE_V27)
        payload_metadata = os.fstat(payload_fd)
        if (
            not stat.S_ISDIR(payload_metadata.st_mode)
            or payload_metadata.st_uid != controller_uid
            or payload_metadata.st_gid != worker_gid
            or _observed_cgroup_mode_v27(payload_fd, cgroup_mode_observer)
            != _PAYLOAD_CGROUP_MODE_V27
            or payload_metadata.st_nlink < 2
        ):
            raise ControllerProtocolError(
                "controller payload cgroup owner/mode/type changed"
            )
        _enable_exact_subtree_controllers_v27(payload_fd)
        for control, flags, expected_mode in (
            ("cgroup.procs", os.O_RDWR, 0o600),
            ("cgroup.threads", os.O_RDONLY, 0o400),
            ("cgroup.subtree_control", os.O_RDONLY, 0o400),
            ("cgroup.events", os.O_RDONLY, 0o400),
            ("cgroup.kill", os.O_WRONLY, 0o200),
        ):
            descriptor = os.open(
                control,
                flags
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=payload_fd,
            )
            os.fchmod(descriptor, expected_mode)
            control_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(control_metadata.st_mode)
                or control_metadata.st_uid != controller_uid
                or control_metadata.st_gid != worker_gid
                or stat.S_IMODE(control_metadata.st_mode) != expected_mode
                or control_metadata.st_nlink != 1
            ):
                os.close(descriptor)
                raise ControllerProtocolError(
                    f"controller payload {control} identity changed"
                )
            descriptors.append(descriptor)
        transfer = (worker_fd, descriptors[0], descriptors[4], descriptors[5])
        bindings = [
            _cgroup_descriptor_binding_v27(role, descriptor)
            for role, descriptor in zip(_WORKER_CGROUP_ROLES_V27, transfer)
        ]
        if [item["type"] for item in bindings] != [
            "directory", "directory", "file", "file"
        ] or len({(item["device"], item["inode"]) for item in bindings}) != 4:
            raise ControllerProtocolError(
                "controller payload cgroup descriptor topology changed"
            )
        binding = {
            "schemaVersion": 27,
            "workerSessionNonce": worker_session_nonce,
            "workerPid": worker_pid,
            "operationId": plan["operationId"],
            "stageLocation": plan["stageLocation"],
            "stagePlanSha256": plan["stagePlanSha256"],
            "payloadName": name,
            "transferNonce": secrets.token_hex(32),
            "workerCgroupRelative": worker_relative,
            "descriptors": bindings,
        }
        return _ControllerCgroupCustodyV27(
            supervisor_fd,
            supervisor_process_fd,
            worker_fd,
            worker_relative,
            name,
            binding,
            (
                descriptors[0], descriptors[1], descriptors[2],
                descriptors[3], descriptors[4], descriptors[5],
            ),
            controller_uid,
            worker_uid,
            worker_gid,
            None,
            cgroup_mode_observer,
        )
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.rmdir(name, dir_fd=supervisor_fd)
        except OSError:
            pass
        raise


def _validate_worker_cgroup_transfer_v27(
    binding: Any,
    descriptors: tuple[int, ...],
    plan: Mapping[str, Any],
    *,
    worker_session_nonce: str,
    consumed_nonces: set[str],
    process_cgroup_reader: Any = None,
    process_start_time_reader: Any = None,
) -> dict[str, Any]:
    fields = {
        "schemaVersion", "workerSessionNonce", "workerPid", "operationId",
        "stageLocation", "stagePlanSha256", "payloadName", "transferNonce",
        "workerCgroupRelative", "descriptors",
    }
    if not isinstance(binding, dict) or set(binding) != fields:
        raise ControllerProtocolError("native cgroup transfer binding is not closed")
    if (
        binding["schemaVersion"] != 27
        or binding["workerSessionNonce"] != worker_session_nonce
        or binding["workerPid"] != os.getpid()
        or binding["operationId"] != plan["operationId"]
        or binding["stageLocation"] != plan["stageLocation"]
        or binding["stagePlanSha256"] != plan["stagePlanSha256"]
        or binding["payloadName"] != _payload_cgroup_name_v27(plan)
        or not isinstance(binding["workerCgroupRelative"], str)
        or Path(binding["workerCgroupRelative"]).name != "worker"
        or not isinstance(binding["transferNonce"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", binding["transferNonce"])
        or binding["transferNonce"] in consumed_nonces
        or len(descriptors) != len(_WORKER_CGROUP_ROLES_V27)
        or not isinstance(binding["descriptors"], list)
        or len(binding["descriptors"]) != len(descriptors)
    ):
        raise ControllerProtocolError("native cgroup transfer identity changed")
    observed = [
        _cgroup_descriptor_binding_v27(role, descriptor)
        for role, descriptor in zip(_WORKER_CGROUP_ROLES_V27, descriptors)
    ]
    if observed != binding["descriptors"] or [item["type"] for item in observed] != [
        "directory", "directory", "file", "file"
    ]:
        raise ControllerProtocolError("native cgroup transfer descriptors changed")
    reader = (
        (lambda: (Path("/proc") / str(os.getpid()) / "cgroup").read_bytes())
        if process_cgroup_reader is None
        else process_cgroup_reader
    )
    relative = native_boundary_v27._unified_cgroup_relative_v27(reader())
    if relative != binding["workerCgroupRelative"]:
        raise ControllerProtocolError(
            "native worker is outside the exact controller-issued worker cgroup"
        )
    consumed_nonces.add(binding["transferNonce"])
    return {"binding": dict(binding), "descriptors": tuple(descriptors)}


def _set_worker_parent_death_v27(parent_pid: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise ControllerProtocolError("native worker could not bind parent-death signal")
    if os.getppid() != parent_pid:
        raise ControllerProtocolError("controller died during native worker bootstrap")


def _close_worker_inherited_descriptors_v27(retained: int) -> None:
    try:
        descriptors = tuple(int(name) for name in os.listdir("/proc/self/fd"))
    except (OSError, ValueError) as exc:
        raise ControllerProtocolError(
            f"native worker cannot enumerate inherited descriptors: {exc}"
        ) from exc
    for descriptor in descriptors:
        if descriptor > 2 and descriptor != retained:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _decode_mountinfo_path_v27(value: str) -> str:
    """Decode only the kernel mountinfo octal escape grammar."""

    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            output.append(value[index])
            index += 1
            continue
        if index + 3 >= len(value) or not all(
            "0" <= item <= "7" for item in value[index + 1:index + 4]
        ):
            raise ControllerProtocolError(
                "native repository release mountinfo escape changed"
            )
        output.append(chr(int(value[index + 1:index + 4], 8)))
        index += 4
    decoded = "".join(output)
    if "\0" in decoded:
        raise ControllerProtocolError(
            "native repository release mountinfo contains NUL"
        )
    return decoded


def _parse_mountinfo_v27(raw: bytes) -> list[dict[str, Any]]:
    if not raw or len(raw) > _WORKER_STATUS_MAX_BYTES_V27 * 16:
        raise ControllerProtocolError(
            "native repository release mountinfo is empty or oversized"
        )
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ControllerProtocolError(
            "native repository release mountinfo is not UTF-8"
        ) from exc
    if not text.endswith("\n"):
        raise ControllerProtocolError(
            "native repository release mountinfo is truncated"
        )
    result: list[dict[str, Any]] = []
    for line in text[:-1].split("\n"):
        left, separator, right = line.partition(" - ")
        left_fields = left.split(" ")
        right_fields = right.split(" ")
        if (
            separator != " - "
            or len(left_fields) < 6
            or len(right_fields) != 3
            or not left_fields[0].isdigit()
            or not left_fields[1].isdigit()
            or re.fullmatch(r"[0-9]+:[0-9]+", left_fields[2]) is None
        ):
            raise ControllerProtocolError(
                "native repository release mountinfo grammar changed"
            )
        result.append(
            {
                "mountId": int(left_fields[0]),
                "parentId": int(left_fields[1]),
                "majorMinor": left_fields[2],
                "root": _decode_mountinfo_path_v27(left_fields[3]),
                "mountPoint": _decode_mountinfo_path_v27(left_fields[4]),
                "mountOptions": left_fields[5],
                "optionalFields": left_fields[6:],
                "fsType": right_fields[0],
                "mountSource": _decode_mountinfo_path_v27(right_fields[1]),
                "superOptions": right_fields[2],
            }
        )
        if len(result) > 8192:
            raise ControllerProtocolError(
                "native repository release mountinfo exceeds the fixed bound"
            )
    return result


def _path_within_v27(candidate: str, root: str) -> bool:
    if not candidate.startswith("/") or os.path.normpath(candidate) != candidate:
        return False
    try:
        return os.path.commonpath((candidate, root)) == root
    except ValueError:
        return False


def _worker_repository_release_probe_v27(
    plan: Mapping[str, Any],
    request_key: bytes,
    *,
    worker_session_nonce: str,
    probe_nonce: str,
    post_manifest: Mapping[str, Any],
    consumed_nonces: set[str] | None = None,
    descriptor_names: Any = None,
    descriptor_stat: Any = None,
    descriptor_target: Any = None,
    mountinfo_reader: Any = None,
) -> dict[str, Any]:
    custody = native_boundary_v27.validate_repository_custody_binding_v27(
        plan.get("repositoryCustody"),
        repository_path=str(plan.get("repositoryPath")),
    )
    if (
        not isinstance(worker_session_nonce, str)
        or re.fullmatch(r"[0-9a-f]{64}", worker_session_nonce) is None
        or not isinstance(probe_nonce, str)
        or re.fullmatch(r"[0-9a-f]{64}", probe_nonce) is None
        or len(request_key) != 32
    ):
        raise ControllerProtocolError(
            "native repository release probe identity changed"
        )
    if consumed_nonces is not None:
        if probe_nonce in consumed_nonces:
            raise ControllerProtocolError(
                "native repository release probe nonce was replayed"
            )
        consumed_nonces.add(probe_nonce)
    post_candidate = dict(custody)
    post_candidate["manifest"] = dict(post_manifest)
    post_candidate["manifestSha256"] = post_manifest.get("manifestSha256")
    post_candidate["bindingSha256"] = native_boundary_v27.sha256(
        native_boundary_v27._REPOSITORY_CUSTODY_BINDING_DOMAIN_V27
        + native_boundary_v27.canonical_bytes(
            {
                key: item
                for key, item in post_candidate.items()
                if key != "bindingSha256"
            }
        )
    )
    post = native_boundary_v27.validate_repository_custody_binding_v27(
        post_candidate, repository_path=str(plan.get("repositoryPath"))
    )
    names_reader = (
        (lambda: os.listdir("/proc/self/fd"))
        if descriptor_names is None
        else descriptor_names
    )
    stat_reader = os.fstat if descriptor_stat is None else descriptor_stat
    target_reader = (
        (lambda descriptor: os.readlink(f"/proc/self/fd/{descriptor}"))
        if descriptor_target is None
        else descriptor_target
    )
    identities: dict[tuple[int, int], list[str]] = {}
    for source, manifest in (
        ("pre", custody["manifest"]), ("post", post["manifest"])
    ):
        for item in manifest["entries"]:
            identities.setdefault(
                (int(item["device"]), int(item["inode"])), []
            ).append(f"{source}:{item['relativePath']}")
    inventory: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    for name in sorted(names_reader(), key=lambda item: int(item)):
        if not isinstance(name, str) or not name.isdigit():
            raise ControllerProtocolError(
                "native repository release fd inventory changed"
            )
        descriptor = int(name)
        try:
            observed = stat_reader(descriptor)
            target = target_reader(descriptor)
        except FileNotFoundError:
            continue
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise ControllerProtocolError(
                f"native repository release fd inspection failed: {exc}"
            ) from exc
        item = {
            "fd": descriptor,
            "device": observed.st_dev,
            "inode": observed.st_ino,
            "fileType": stat.S_IFMT(observed.st_mode),
            "target": target,
        }
        inventory.append(item)
        relative_paths = identities.get((observed.st_dev, observed.st_ino), [])
        if relative_paths:
            matches.append({**item, "relativePaths": relative_paths})
    mount_reader = (
        (lambda: Path("/proc/self/mountinfo").read_bytes())
        if mountinfo_reader is None
        else mountinfo_reader
    )
    mounts = _parse_mountinfo_v27(mount_reader())
    leaf_path = str(custody["leafPath"])
    mount_matches = [
        item
        for item in mounts
        if any(
            _path_within_v27(str(item[field]), leaf_path)
            for field in ("root", "mountPoint", "mountSource")
        )
    ]
    body = {
        "schemaVersion": 27,
        "operationId": plan["operationId"],
        "stageLocation": plan["stageLocation"],
        "stagePlanSha256": plan["stagePlanSha256"],
        "workerSessionNonce": worker_session_nonce,
        "grantWorkerSessionNonce": custody["workerSessionNonce"],
        "probeNonce": probe_nonce,
        "repositoryBindingSha256": custody["bindingSha256"],
        "repositoryManifestSha256": custody["manifestSha256"],
        "postRepositoryManifestSha256": post["manifestSha256"],
        "descriptorCount": len(inventory),
        "descriptorInventorySha256": _sha(_canonical(inventory)),
        "descriptorMatches": matches,
        "mountCount": len(mounts),
        "mountInfoSha256": _sha(_canonical(mounts)),
        "mountMatches": mount_matches,
    }
    body["releaseHmac"] = "hmac-sha256:" + hmac.new(
        request_key,
        _REPOSITORY_CUSTODY_RELEASE_DOMAIN_V27 + _canonical(body),
        hashlib.sha256,
    ).hexdigest()
    return body


def _worker_main_v27(
    channel: socket.socket,
    config: ControllerConfig,
    manifest: native_boundary_v27.NativeBoundaryManifestV27,
    parent_pid: int,
    worker_session_nonce: str,
) -> None:
    os.setsid()
    _close_worker_inherited_descriptors_v27(channel.fileno())
    _drop_to_worker_identity_v27(config)
    # setuid clears PR_SET_PDEATHSIG.  Bind it only after final credentials,
    # then close the parent-race by checking getppid immediately.
    _set_worker_parent_death_v27(parent_pid)
    _verify_worker_result_root_label_v27(config)
    _verify_native_platform_gate(
        manifest, expected_worker_uid=config.worker_uid
    )
    channel.sendall(
        _canonical(
            {
                "schemaVersion": 27,
                "protocol": _WORKER_PROTOCOL,
                "status": "ready",
                "workerPid": os.getpid(),
                "workerUid": os.geteuid(),
                "workerSessionNonce": worker_session_nonce,
            }
        )
    )
    consumed_cgroup_nonces: set[str] = set()
    consumed_repository_probe_nonces: set[str] = set()
    while True:
        packet, received_descriptors = _recv_worker_execute_packet_v27(
            channel,
            expected_pid=parent_pid,
            expected_uid=config.controller_uid,
            expected_gid=config.transport_gid,
        )
        try:
            request = _worker_packet_v27(packet, "native worker request")
            if set(request) != {
                "schemaVersion", "protocol", "action", "plan", "cgroupBinding",
                "retirementArtifact",
            } or (request["schemaVersion"], request["protocol"]) != (
                27, _WORKER_PROTOCOL
            ):
                raise ControllerProtocolError(
                    "native worker request shape is invalid"
                )
            if (
                request["action"] == "STOP"
                and request["plan"] is None
                and request["cgroupBinding"] is None
                and request["retirementArtifact"] is None
                and not received_descriptors
            ):
                return
            if request["action"] != "EXECUTE":
                if request["action"] not in {
                    "PREPARE", "ACK-ARENA", "RECOVER", "PERSIST-RETIREMENT",
                    "PROBE-REPOSITORY-RELEASE",
                }:
                    raise ControllerProtocolError("native worker action is invalid")
            _assert_worker_dac_isolation_v27(config)
            _verify_worker_result_root_label_v27(config)
            _verify_native_platform_gate(
                manifest, expected_worker_uid=config.worker_uid
            )
            plan = native_boundary_v27.validate_native_stage_action_plan_v27(
                request["plan"], manifest
            )
            if request["action"] == "PROBE-REPOSITORY-RELEASE":
                artifact = request["retirementArtifact"]
                probe_nonce = (
                    artifact.get("value", {}).get("probeNonce")
                    if isinstance(artifact, Mapping)
                    and isinstance(artifact.get("value"), Mapping)
                    else None
                )
                if (
                    request["cgroupBinding"] is not None
                    or len(received_descriptors) != 1
                    or not isinstance(artifact, Mapping)
                    or set(artifact) != {"kind", "value"}
                    or artifact["kind"] != "repository-release-probe"
                    or not isinstance(artifact["value"], Mapping)
                    or set(artifact["value"]) != {"probeNonce", "postManifest"}
                    or not isinstance(artifact["value"].get("postManifest"), Mapping)
                    or probe_nonce in consumed_repository_probe_nonces
                ):
                    raise ControllerProtocolError(
                        "native repository release probe custody changed"
                    )
                request_key = (
                    native_boundary_v27.consume_sealed_request_key_descriptor_v27(
                        received_descriptors[0], plan["requestKeyId"]
                    )
                )
                receipt = _worker_repository_release_probe_v27(
                    plan,
                    request_key,
                    worker_session_nonce=worker_session_nonce,
                    probe_nonce=str(artifact["value"]["probeNonce"]),
                    post_manifest=artifact["value"]["postManifest"],
                    consumed_nonces=consumed_repository_probe_nonces,
                )
                channel.sendall(
                    _canonical(
                        {
                            "schemaVersion": 27,
                            "protocol": _WORKER_PROTOCOL,
                            "status": "repository-release-proved",
                            "stagePlanSha256": plan["stagePlanSha256"],
                            "releaseReceipt": receipt,
                        }
                    )
                )
                continue
            if request["action"] == "PREPARE":
                if (
                    request["cgroupBinding"] is not None
                    or request["retirementArtifact"] is not None
                    or len(received_descriptors) != 1
                ):
                    raise ControllerProtocolError(
                        "native result-arena preparation custody changed"
                    )
                request_key = native_boundary_v27.consume_sealed_request_key_descriptor_v27(
                    received_descriptors[0], plan["requestKeyId"]
                )
                preparation = native_boundary_v27.prepare_native_stage_result_arena_v27(
                    manifest, plan, request_key
                )
                channel.sendall(
                    _canonical(
                        {
                            "schemaVersion": 27,
                            "protocol": _WORKER_PROTOCOL,
                            "status": "result-arena-prepared",
                            "stagePlanSha256": plan["stagePlanSha256"],
                            "arenaPreparation": preparation,
                        }
                    )
                )
                continue
            if request["action"] == "ACK-ARENA":
                if (
                    request["cgroupBinding"] is not None
                    or len(received_descriptors) != 0
                    or not isinstance(request["retirementArtifact"], Mapping)
                    or set(request["retirementArtifact"]) != {"kind", "value"}
                    or request["retirementArtifact"]["kind"] != "arena"
                ):
                    raise ControllerProtocolError(
                        "native result-arena ACK custody changed"
                    )
                arena_sha256 = native_boundary_v27.persist_controller_result_arena_v27(
                    manifest, plan, request["retirementArtifact"]["value"]
                )
                channel.sendall(
                    _canonical(
                        {
                            "schemaVersion": 27,
                            "protocol": _WORKER_PROTOCOL,
                            "status": "result-arena-durable",
                            "stagePlanSha256": plan["stagePlanSha256"],
                            "arenaRecordSha256": arena_sha256,
                        }
                    )
                )
                continue
            if request["action"] == "PERSIST-RETIREMENT":
                if request["cgroupBinding"] is not None or received_descriptors:
                    raise ControllerProtocolError(
                        "native retirement persistence descriptor custody changed"
                    )
                artifact = request["retirementArtifact"]
                if not isinstance(artifact, Mapping) or set(artifact) != {
                    "kind", "value"
                }:
                    raise ControllerProtocolError(
                        "native retirement artifact request changed"
                    )
                native_boundary_v27.persist_controller_retirement_artifact_v27(
                    manifest, plan, artifact["kind"], artifact["value"]
                )
                artifact_sha256 = native_boundary_v27.sha256(
                    native_boundary_v27.canonical_bytes(dict(artifact))
                )
                channel.sendall(
                    _canonical(
                        {
                            "schemaVersion": 27,
                            "protocol": _WORKER_PROTOCOL,
                            "status": "retirement-artifact-durable",
                            "stagePlanSha256": plan["stagePlanSha256"],
                            "artifactKind": artifact["kind"],
                            "artifactSha256": artifact_sha256,
                        }
                    )
                )
                continue
            if request["action"] == "RECOVER":
                if (
                    request["cgroupBinding"] is not None
                    or request["retirementArtifact"] is not None
                    or len(received_descriptors) != 1
                ):
                    raise ControllerProtocolError(
                        "native worker recovery descriptor custody changed"
                    )
                request_key = native_boundary_v27.consume_sealed_request_key_descriptor_v27(
                    received_descriptors[0], plan["requestKeyId"]
                )
                result = native_boundary_v27.recover_durable_native_stage_result_v27(
                    manifest, plan, request_key
                )
                channel.sendall(
                    _worker_recovery_packet_v27(
                        plan["stagePlanSha256"], result
                    )
                )
                continue
            if len(received_descriptors) != len(_WORKER_CGROUP_ROLES_V27) + 1:
                raise ControllerProtocolError(
                    "native worker execution descriptor custody changed"
                )
            if request["retirementArtifact"] is not None:
                raise ControllerProtocolError(
                    "native worker execution carried a retirement artifact"
                )
            request_key = native_boundary_v27.consume_sealed_request_key_descriptor_v27(
                received_descriptors[-1], plan["requestKeyId"]
            )
            custody = _validate_worker_cgroup_transfer_v27(
                request["cgroupBinding"],
                received_descriptors[:-1],
                plan,
                worker_session_nonce=worker_session_nonce,
                consumed_nonces=consumed_cgroup_nonces,
            )
            def placement_mediator(request_value: Mapping[str, Any]) -> Mapping[str, Any]:
                request_fields = {
                    "supervisorPid", "childPid", "childStartTime", "ordinal",
                    "placementNonce",
                }
                if not isinstance(request_value, Mapping) or set(request_value) != request_fields:
                    raise ControllerProtocolError(
                        "native supervisor placement request shape changed"
                    )
                packet_value = {
                    "schemaVersion": 27,
                    "protocol": _WORKER_PROTOCOL,
                    "status": "placement-request",
                    "stagePlanSha256": plan["stagePlanSha256"],
                    **dict(request_value),
                }
                encoded = _canonical(packet_value)
                if channel.send(encoded) != len(encoded):
                    raise ControllerProtocolError(
                        "native placement request forwarding was truncated"
                    )
                response_packet = _recv_credentialed_packet_v27(
                    channel,
                    expected_pid=parent_pid,
                    expected_uid=config.controller_uid,
                    expected_gid=config.transport_gid,
                    label="native lifecycle placement authorization",
                )
                response = _worker_packet_v27(
                    response_packet, "native lifecycle placement authorization"
                )
                if set(response) != {
                    "schemaVersion", "protocol", "status", "stagePlanSha256",
                    "placement",
                } or (
                    response["schemaVersion"], response["protocol"],
                    response["status"], response["stagePlanSha256"],
                ) != (
                    27, _WORKER_PROTOCOL, "placement-authorized",
                    plan["stagePlanSha256"],
                ) or not isinstance(response["placement"], Mapping):
                    raise ControllerProtocolError(
                        "native lifecycle placement authorization identity changed"
                    )
                return response["placement"]
            native_result_offer: dict[str, Any] | None = None

            def result_offer_mediator(
                request_value: Mapping[str, Any]
            ) -> Mapping[str, Any]:
                nonlocal native_result_offer
                fields = {
                    "schemaVersion", "protocol", "status",
                    "stagePlanSha256", "nativeResultSha256", "resultKind",
                    "resultPredecessorKind", "failureEvidenceSha256",
                    "placementMask",
                }
                if (
                    native_result_offer is not None
                    or not isinstance(request_value, Mapping)
                    or set(request_value) != fields
                    or request_value.get("schemaVersion") != 27
                    or request_value.get("protocol") != _WORKER_PROTOCOL
                    or request_value.get("status") != "result-offer"
                    or request_value.get("stagePlanSha256")
                    != plan["stagePlanSha256"]
                ):
                    raise ControllerProtocolError(
                        "native result offer request identity changed"
                    )
                packet_value = dict(request_value)
                packet_value["offerHmac"] = "hmac-sha256:" + hmac.new(
                    request_key,
                    _WORKER_RESULT_OFFER_DOMAIN_V27
                    + _canonical(dict(request_value)),
                    hashlib.sha256,
                ).hexdigest()
                encoded = _canonical(packet_value)
                if channel.send(encoded) != len(encoded):
                    raise ControllerProtocolError(
                        "native result offer forwarding was truncated"
                    )
                response = _worker_packet_v27(
                    _recv_credentialed_packet_v27(
                        channel,
                        expected_pid=parent_pid,
                        expected_uid=config.controller_uid,
                        expected_gid=config.transport_gid,
                        label="native result-offer authorization",
                    ),
                    "native result-offer authorization",
                )
                expected_fields = {
                    "schemaVersion", "protocol", "action", "stagePlanSha256",
                    "nativeResultSha256", "authorizationRecordSha256", "ackHmac",
                }
                ack_body = {
                    key: response.get(key)
                    for key in expected_fields
                    if key != "ackHmac"
                }
                expected_ack = "hmac-sha256:" + hmac.new(
                    request_key,
                    _WORKER_RESULT_OFFER_ACK_DOMAIN_V27 + _canonical(ack_body),
                    hashlib.sha256,
                ).hexdigest()
                if (
                    set(response) != expected_fields
                    or response.get("schemaVersion") != 27
                    or response.get("protocol") != _WORKER_PROTOCOL
                    or response.get("action") != "ACK-RESULT-OFFER"
                    or response.get("stagePlanSha256")
                    != plan["stagePlanSha256"]
                    or response.get("nativeResultSha256")
                    != request_value["nativeResultSha256"]
                    or not isinstance(
                        response.get("authorizationRecordSha256"), str
                    )
                    or not _DIGEST.fullmatch(
                        response["authorizationRecordSha256"]
                    )
                    or not hmac.compare_digest(
                        str(response.get("ackHmac")), expected_ack
                    )
                ):
                    raise ControllerProtocolError(
                        "native result offer authorization changed"
                    )
                native_result_offer = dict(request_value)
                return response

            def event_mediator(request_value: Mapping[str, Any]) -> Mapping[str, Any]:
                event_fields = {
                    "schemaVersion", "stagePlanSha256", "sequence", "event",
                    "phase", "eventObservation", "eventEvidenceSha256",
                }
                if (
                    not isinstance(request_value, Mapping)
                    or set(request_value) != event_fields
                    or request_value.get("schemaVersion") != 27
                    or request_value.get("stagePlanSha256")
                    != plan["stagePlanSha256"]
                ):
                    raise ControllerProtocolError(
                        "native supervisor event request shape changed"
                    )
                try:
                    event_observation = (
                        native_boundary_v27._validate_native_event_observation_v27(
                            request_value["event"],
                            request_value["phase"],
                            request_value["eventObservation"],
                        )
                    )
                except native_boundary_v27.NativeBoundaryV27Error as exc:
                    raise ControllerProtocolError(str(exc)) from exc
                if request_value["eventEvidenceSha256"] != (
                    native_boundary_v27._native_event_evidence_v27(
                        stage_plan_sha256=plan["stagePlanSha256"],
                        sequence=request_value["sequence"],
                        event=request_value["event"],
                        phase=request_value["phase"],
                        observation=event_observation,
                    )
                ):
                    raise ControllerProtocolError(
                        "native event evidence does not bind its closed observation"
                    )
                event_body = dict(request_value)
                packet_value = {
                    **event_body,
                    "protocol": _WORKER_PROTOCOL,
                    "status": "native-event",
                    "eventHmac": native_boundary_v27._native_event_hmac_v27(
                        request_key, event_body
                    ),
                }
                encoded = _canonical(packet_value)
                if channel.send(encoded) != len(encoded):
                    raise ControllerProtocolError(
                        "native event forwarding was truncated"
                    )
                response_packet = _recv_credentialed_packet_v27(
                    channel,
                    expected_pid=parent_pid,
                    expected_uid=config.controller_uid,
                    expected_gid=config.transport_gid,
                    label="native event authorization",
                )
                response = _worker_packet_v27(
                    response_packet, "native event authorization"
                )
                response_fields = {
                    "schemaVersion", "protocol", "status",
                    "stagePlanSha256", "sequence", "event", "phase",
                    "authorityRecordSha256", "controlAction",
                    "controlAuthorityRecordSha256", "creatorCaptureBinding",
                    "ackHmac",
                }
                if set(response) != response_fields or (
                    response["schemaVersion"], response["protocol"],
                    response["status"], response["stagePlanSha256"],
                    response["sequence"], response["event"],
                    response["phase"],
                ) != (
                    27, _WORKER_PROTOCOL, "native-event-authorized",
                    plan["stagePlanSha256"], event_body["sequence"],
                    event_body["event"], event_body["phase"],
                ):
                    raise ControllerProtocolError(
                        "native event authorization identity changed"
                    )
                ack_body = {
                    key: response[key]
                    for key in (
                        "schemaVersion", "stagePlanSha256", "sequence",
                        "event", "phase", "authorityRecordSha256",
                        "controlAction", "controlAuthorityRecordSha256",
                        "creatorCaptureBinding",
                    )
                }
                capture_binding = response["creatorCaptureBinding"]
                expected_capture_binding = (
                    request_value["event"] == "creator-return-ready"
                    and request_value["phase"] == "before"
                )
                if expected_capture_binding:
                    if (
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
                    ):
                        raise ControllerProtocolError(
                            "native creator capture authority changed"
                        )
                elif capture_binding is not None:
                    raise ControllerProtocolError(
                        "native event carried unexpected creator capture authority"
                    )
                if (
                    response["controlAction"] not in {"continue", "revoke"}
                    or (
                        response["controlAction"] == "continue"
                        and response["controlAuthorityRecordSha256"] is not None
                    )
                    or (
                        response["controlAction"] == "revoke"
                        and (
                            not isinstance(
                                response["controlAuthorityRecordSha256"], str
                            )
                            or not native_boundary_v27._DIGEST.fullmatch(
                                response["controlAuthorityRecordSha256"]
                            )
                        )
                    )
                ):
                    raise ControllerProtocolError(
                        "native event control authorization changed"
                    )
                if not hmac.compare_digest(
                    response["ackHmac"],
                    native_boundary_v27._native_event_ack_hmac_v27(
                        request_key, ack_body
                    ),
                ):
                    raise ControllerProtocolError(
                        "native event authorization HMAC changed"
                    )
                return response
            token = native_boundary_v27._NATIVE_REQUEST_KEY_V27.set(request_key)
            try:
                try:
                    result = native_boundary_v27.run_native_stage_action_v27(
                        manifest,
                        plan,
                        cgroup_custody=custody,
                        placement_mediator=placement_mediator,
                        event_mediator=event_mediator,
                        result_offer_mediator=result_offer_mediator,
                    )
                except native_boundary_v27._NativeLaunchPreEffectFailedV27 as exc:
                    if exc.classification is None:
                        raise ControllerProtocolError(
                            "native launch pre-effect failure lacks Popen classification"
                        ) from exc
                    channel.sendall(
                        _worker_pre_effect_failure_packet_v27(
                            plan["stagePlanSha256"],
                            evidence_sha256=exc.evidence_sha256,
                            classification=exc.classification,
                            request_key=request_key,
                        )
                    )
                    continue
                except native_boundary_v27._NativeLaunchUnresolvedV27 as exc:
                    channel.sendall(
                        _worker_launch_unresolved_packet_v27(
                            plan["stagePlanSha256"],
                            exc.recovered,
                            request_key,
                        )
                    )
                    continue
            finally:
                native_boundary_v27._NATIVE_REQUEST_KEY_V27.reset(token)
            observation = native_boundary_v27._decode_native_stage_result_v27(
                result, require_discriminants=True
            )
            if (
                native_result_offer is None
                or _sha(_canonical(observation))
                != native_result_offer["nativeResultSha256"]
                or result["resultKind"] != native_result_offer["resultKind"]
                or result["resultPredecessorKind"]
                != native_result_offer["resultPredecessorKind"]
                or result["failureEvidenceSha256"]
                != native_result_offer["failureEvidenceSha256"]
                or result["placementMask"]
                != native_result_offer["placementMask"]
            ):
                raise ControllerProtocolError(
                    "native result differs from its supervisor-authorized offer"
                )
            channel.sendall(
                _worker_result_packet_v27(plan["stagePlanSha256"], result)
            )
        finally:
            for descriptor in received_descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _mediate_native_event_authority_v27(
    candidate: Mapping[str, Any],
    plan: Mapping[str, Any],
    event_handler: Any,
    *,
    revocation_observation: Mapping[str, Any] | None,
    revoke_delivered: bool,
) -> tuple[str, str, str | None, bool]:
    """Authorize one genuine supervisor event and an optional pre-effect revoke.

    A disable may branch only after the creator-created receipt or in place of
    the release-consumed `before` event.  The RevokeDecision CAS is therefore
    installed before the authenticated command reaches the supervisor.  Once
    the signal-attempt gate is reached, no verified-no-effect result is legal.
    """

    if not callable(event_handler):
        raise ControllerProtocolError(
            "native event arrived without a current authority handler"
        )
    event = candidate["event"]
    phase = candidate["phase"]
    denied_pre_release = (
        revocation_observation is not None
        and not revoke_delivered
        and phase == "before"
        and event == "release-consumed-current"
    )
    if (
        revocation_observation is not None
        and not revoke_delivered
        and event in {
            "signal-attempt-consumed",
            "release-issued",
            "release-known-live",
            "release-terminal",
            "creator-return-ready",
            "creator-lifetime-closed",
        }
    ):
        raise ControllerProtocolError(
            "operator disable crossed the no-effect revoke cutoff"
        )
    authority_record = None if denied_pre_release else event_handler(
        event,
        phase,
        candidate["eventEvidenceSha256"],
        candidate["eventObservation"],
    )
    control_action = "continue"
    control_authority = None
    completed_creator_gate = (
        event == "native-creator-created" and phase == "after"
    )
    if (
        revocation_observation is not None
        and not revoke_delivered
        and (completed_creator_gate or denied_pre_release)
    ):
        revoke_evidence = native_boundary_v27.sha256(
            b"startup-factory/beads/v27/operator-revoke-decision\0"
            + native_boundary_v27.canonical_bytes(
                {
                    "stagePlanSha256": plan["stagePlanSha256"],
                    "triggerSequence": candidate["sequence"],
                    "triggerEvent": event,
                    "triggerPhase": phase,
                    "triggerAuthorityRecordSha256": authority_record,
                    "operatorLifecycle": dict(revocation_observation),
                }
            )
        )
        control_authority = event_handler(
            "revoke-decision",
            "before",
            revoke_evidence,
            {"revokeAuthorized": True, "releaseNotIssued": True},
        )
        control_action = "revoke"
        revoke_delivered = True
        if authority_record is None:
            authority_record = control_authority
    if not isinstance(authority_record, str) or not _DIGEST.fullmatch(
        authority_record
    ):
        raise ControllerProtocolError(
            "native event has no exact current authority"
        )
    if control_authority is not None and not _DIGEST.fullmatch(
        control_authority
    ):
        raise ControllerProtocolError(
            "native revoke command has no exact current authority"
        )
    return authority_record, control_action, control_authority, revoke_delivered


@dataclasses.dataclass(slots=True)
class _WorkerChannelV27:
    channel: socket.socket
    pid: int
    pidfd: int
    worker_uid: int
    worker_gid: int
    controller_uid: int
    cgroup_worker_gid: int
    supervisor_cgroup_fd: int
    supervisor_procs_fd: int
    worker_cgroup_fd: int
    worker_procs_fd: int
    worker_cgroup_relative: str
    worker_start_time: str
    worker_session_nonce: str
    retirement_receipts: dict[str, dict[str, Any]] = dataclasses.field(
        default_factory=dict
    )
    arena_records: dict[str, str] = dataclasses.field(default_factory=dict)
    retirement_intents: dict[str, tuple[dict[str, Any], str]] = (
        dataclasses.field(default_factory=dict)
    )
    repository_release_receipts: dict[str, dict[str, Any]] = (
        dataclasses.field(default_factory=dict)
    )

    def _assert_peer(self) -> None:
        readable, _, _ = select.select([self.pidfd], [], [], 0)
        if readable:
            raise ControllerProtocolError("native worker pidfd is terminal")

    def await_ready(self) -> None:
        self.channel.settimeout(CONNECTION_DEADLINE_SECONDS * 6)
        self._assert_peer()
        packet = _recv_credentialed_packet_v27(
            self.channel,
            expected_pid=self.pid,
            expected_uid=self.worker_uid,
            expected_gid=self.worker_gid,
            label="native worker readiness",
        )
        value = _worker_packet_v27(packet, "native worker readiness")
        if set(value) != {
            "schemaVersion",
            "protocol",
            "status",
            "workerPid",
            "workerUid",
            "workerSessionNonce",
        } or (
            value["schemaVersion"],
            value["protocol"],
            value["status"],
            value["workerPid"],
            value["workerUid"],
            value["workerSessionNonce"],
        ) != (
            27,
            _WORKER_PROTOCOL,
            "ready",
            self.pid,
            self.worker_uid,
            self.worker_session_nonce,
        ):
            raise ControllerProtocolError("native worker readiness identity is invalid")
        self.channel.settimeout(None)

    def execute(
        self,
        manifest: native_boundary_v27.NativeBoundaryManifestV27,
        value: Any,
        *,
        lifecycle_check: Any,
        controller_key: bytes,
        event_handler: Any = None,
    ) -> dict[str, Any]:
        def lifecycle_observation(*, require_active: bool) -> Mapping[str, Any] | None:
            observed = lifecycle_check()
            if observed is None:
                return None
            if not isinstance(observed, Mapping):
                raise ControllerProtocolError(
                    "native execution lifecycle observation changed"
                )
            state = observed.get("operatorState")
            if state not in {"active", "disabled"} or type(
                observed.get("generation")
            ) is not int:
                raise ControllerProtocolError(
                    "native execution lifecycle observation is malformed"
                )
            if require_active and state != "active":
                raise ControllerProtocolError(
                    "local operator state is not active"
                )
            return dict(observed)

        lifecycle_observation(require_active=True)
        plan = native_boundary_v27.validate_native_stage_action_plan_v27(
            value, manifest
        )
        request_key = native_boundary_v27._NATIVE_REQUEST_KEY_V27.get()
        if request_key is None or native_boundary_v27.sha256(request_key) != plan["requestKeyId"]:
            raise ControllerProtocolError(
                "native worker execution lacks the exact derived request key"
            )
        self._assert_peer()
        arena_record_sha256 = self._prepare_result_arena(
            manifest,
            plan,
            request_key=request_key,
            controller_key=controller_key,
            lifecycle_check=lambda: lifecycle_observation(require_active=True),
        )
        lifecycle_observation(require_active=True)
        custody = _create_controller_cgroup_custody_v27(
            self.supervisor_cgroup_fd,
            self.supervisor_procs_fd,
            self.worker_cgroup_fd,
            self.worker_cgroup_relative,
            plan,
            controller_uid=self.controller_uid,
            worker_uid=self.worker_uid,
            worker_gid=self.cgroup_worker_gid,
            worker_pid=self.pid,
            worker_session_nonce=self.worker_session_nonce,
        )
        retirement_done = False
        completed_result: dict[str, Any] | None = None
        completed_retirement: dict[str, Any] | None = None
        request_key_fd = -1
        try:
            request_key_fd, request_key_copy = (
                native_boundary_v27._sealed_request_key_descriptor_v27(request_key)
            )
            for index in range(len(request_key_copy)):
                request_key_copy[index] = 0
            request = _canonical(
                {
                    "schemaVersion": 27,
                    "protocol": _WORKER_PROTOCOL,
                    "action": "EXECUTE",
                    "plan": plan,
                    "cgroupBinding": custody.binding,
                    "retirementArtifact": None,
                }
            )
            rights = array.array(
                "i", (*custody.transfer_descriptors, request_key_fd)
            )
            try:
                sent = self.channel.sendmsg(
                    [request],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                )
            finally:
                os.close(request_key_fd)
                request_key_fd = -1
            if sent != len(request):
                raise ControllerProtocolError(
                    "native worker cgroup transfer packet was truncated"
                )
            deadline = time.monotonic() + _WORKER_WAIT_SECONDS
            packet = b""
            expected_native_event_sequence = 1
            revocation_observation: Mapping[str, Any] | None = None
            revoke_delivered = False
            pending_result_offer: dict[str, Any] | None = None
            while True:
                while True:
                    observed_lifecycle = lifecycle_observation(
                        require_active=False
                    )
                    if (
                        observed_lifecycle is not None
                        and observed_lifecycle["operatorState"] == "disabled"
                    ):
                        revocation_observation = observed_lifecycle
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self.terminate()
                        raise ControllerProtocolError(
                            "native worker timed out and its payload cgroup was drained"
                        )
                    readable, _, _ = select.select(
                        [self.channel], [], [], min(0.25, remaining)
                    )
                    if readable:
                        break
                packet = _recv_credentialed_packet_v27(
                    self.channel,
                    expected_pid=self.pid,
                    expected_uid=self.worker_uid,
                    expected_gid=self.worker_gid,
                    label="native worker result or placement request",
                )
                candidate = _worker_packet_v27(
                    packet, "native worker result or placement request"
                )
                if candidate.get("status") == "result-offer":
                    fields = {
                        "schemaVersion", "protocol", "status",
                        "stagePlanSha256", "nativeResultSha256", "resultKind",
                        "resultPredecessorKind", "failureEvidenceSha256",
                        "placementMask", "offerHmac",
                    }
                    offer_body = {
                        key: candidate.get(key)
                        for key in fields
                        if key != "offerHmac"
                    }
                    expected_offer_hmac = "hmac-sha256:" + hmac.new(
                        request_key,
                        _WORKER_RESULT_OFFER_DOMAIN_V27
                        + _canonical(offer_body),
                        hashlib.sha256,
                    ).hexdigest()
                    if (
                        pending_result_offer is not None
                        or set(candidate) != fields
                        or candidate.get("schemaVersion") != 27
                        or candidate.get("protocol") != _WORKER_PROTOCOL
                        or candidate.get("stagePlanSha256")
                        != plan["stagePlanSha256"]
                        or not isinstance(candidate.get("nativeResultSha256"), str)
                        or not _DIGEST.fullmatch(candidate["nativeResultSha256"])
                        or not hmac.compare_digest(
                            str(candidate.get("offerHmac")), expected_offer_hmac
                        )
                        or not callable(
                            getattr(event_handler, "authorize_result_offer", None)
                        )
                    ):
                        raise ControllerProtocolError(
                            "native result offer authentication changed"
                        )
                    native_boundary_v27.validate_result_envelope_v4(
                        {
                            "resultKind": candidate["resultKind"],
                            "predecessorKind": candidate[
                                "resultPredecessorKind"
                            ],
                            "failureEvidenceSha256": candidate[
                                "failureEvidenceSha256"
                            ],
                        }
                    )
                    if not native_boundary_v27._placement_mask_matches_result_v27(
                        candidate["placementMask"], candidate["resultKind"]
                    ):
                        raise ControllerProtocolError(
                            "native result offer placement mask changed"
                        )
                    authorization_record = event_handler.authorize_result_offer(
                        candidate
                    )
                    acknowledgement = _worker_result_offer_ack_v27(
                        plan_sha256=plan["stagePlanSha256"],
                        native_result_sha256=candidate["nativeResultSha256"],
                        authorization_record_sha256=authorization_record,
                        request_key=request_key,
                    )
                    if self.channel.send(acknowledgement) != len(acknowledgement):
                        raise ControllerProtocolError(
                            "native result-offer authorization was truncated"
                        )
                    pending_result_offer = dict(candidate)
                    continue
                if candidate.get("status") == "native-event":
                    if not callable(event_handler):
                        raise ControllerProtocolError(
                            "native event arrived without a current authority handler"
                        )
                    required_event = {
                        "schemaVersion", "protocol", "status",
                        "stagePlanSha256", "sequence", "event", "phase",
                        "eventObservation", "eventEvidenceSha256", "eventHmac",
                    }
                    if set(candidate) != required_event or (
                        candidate["schemaVersion"],
                        candidate["protocol"],
                        candidate["stagePlanSha256"],
                    ) != (27, _WORKER_PROTOCOL, plan["stagePlanSha256"]):
                        raise ControllerProtocolError(
                            "native event identity changed"
                        )
                    if candidate["sequence"] != expected_native_event_sequence:
                        raise ControllerProtocolError(
                            "native event sequence was skipped, replayed, or reordered"
                        )
                    try:
                        event_observation = (
                            native_boundary_v27._validate_native_event_observation_v27(
                                candidate["event"],
                                candidate["phase"],
                                candidate["eventObservation"],
                            )
                        )
                    except native_boundary_v27.NativeBoundaryV27Error as exc:
                        raise ControllerProtocolError(str(exc)) from exc
                    event_body = {
                        key: candidate[key]
                        for key in (
                            "schemaVersion", "stagePlanSha256", "sequence",
                            "event", "phase", "eventObservation",
                            "eventEvidenceSha256",
                        )
                    }
                    expected_event_hmac = native_boundary_v27._native_event_hmac_v27(
                        request_key, event_body
                    )
                    if not hmac.compare_digest(
                        candidate["eventHmac"], expected_event_hmac
                    ):
                        raise ControllerProtocolError(
                            "native event authentication changed"
                        )
                    if candidate["eventEvidenceSha256"] != (
                        native_boundary_v27._native_event_evidence_v27(
                            stage_plan_sha256=plan["stagePlanSha256"],
                            sequence=candidate["sequence"],
                            event=candidate["event"],
                            phase=candidate["phase"],
                            observation=event_observation,
                        )
                    ):
                        raise ControllerProtocolError(
                            "native event observation digest changed"
                        )
                    observed_lifecycle = lifecycle_observation(
                        require_active=False
                    )
                    if (
                        observed_lifecycle is not None
                        and observed_lifecycle["operatorState"] == "disabled"
                    ):
                        revocation_observation = observed_lifecycle
                    try:
                        (
                            authority_record,
                            control_action,
                            control_authority,
                            revoke_delivered,
                        ) = _mediate_native_event_authority_v27(
                            candidate,
                            plan,
                            event_handler,
                            revocation_observation=revocation_observation,
                            revoke_delivered=revoke_delivered,
                        )
                    except ControllerProtocolError as exc:
                        if "crossed the no-effect revoke cutoff" in str(exc):
                            self.terminate()
                            raise ControllerProtocolError(
                                f"{exc}; the worker was fenced for "
                                "authenticated loss recovery"
                            ) from exc
                        raise
                    acknowledgement = {
                        "schemaVersion": 27,
                        "protocol": _WORKER_PROTOCOL,
                        "status": "native-event-authorized",
                        "stagePlanSha256": plan["stagePlanSha256"],
                        "sequence": candidate["sequence"],
                        "event": candidate["event"],
                        "phase": candidate["phase"],
                        "authorityRecordSha256": authority_record,
                        "controlAction": control_action,
                        "controlAuthorityRecordSha256": control_authority,
                        "creatorCaptureBinding": (
                            event_handler.creator_capture_binding_v27()
                            if (
                                candidate["event"] == "creator-return-ready"
                                and candidate["phase"] == "before"
                                and callable(getattr(
                                    event_handler,
                                    "creator_capture_binding_v27",
                                    None,
                                ))
                            )
                            else None
                        ),
                    }
                    acknowledgement["ackHmac"] = (
                        native_boundary_v27._native_event_ack_hmac_v27(
                            request_key,
                            {
                                key: acknowledgement[key]
                                for key in (
                                    "schemaVersion", "stagePlanSha256",
                                    "sequence", "event", "phase",
                                    "authorityRecordSha256", "controlAction",
                                    "controlAuthorityRecordSha256",
                                    "creatorCaptureBinding",
                                )
                            },
                        )
                    )
                    encoded_ack = _canonical(acknowledgement)
                    if self.channel.send(encoded_ack) != len(encoded_ack):
                        raise ControllerProtocolError(
                            "native event authorization was truncated"
                        )
                    expected_native_event_sequence += 1
                    continue
                if candidate.get("status") == "launch-unresolved":
                    recovered = _validate_worker_launch_unresolved_v27(
                        candidate,
                        plan=plan,
                        request_key=request_key,
                    )
                    retirement = custody.drain(
                        persist_intent=lambda intent: self._persist_retirement_artifact(
                            manifest,
                            plan,
                            "intent",
                            intent,
                            arena_record_sha256=arena_record_sha256,
                            controller_key=controller_key,
                            lifecycle_check=lambda: lifecycle_observation(
                                require_active=False
                            ),
                        )
                    )
                    retirement_receipt = {
                        **retirement,
                        "controllerTrackedPlacementMask": retirement[
                            "placementMask"
                        ],
                    }
                    self._persist_retirement_artifact(
                        manifest,
                        plan,
                        "receipt",
                        retirement_receipt,
                        arena_record_sha256=arena_record_sha256,
                        controller_key=controller_key,
                        lifecycle_check=lambda: lifecycle_observation(
                            require_active=False
                        ),
                    )
                    retirement_done = True
                    recovered["controllerRetirement"] = retirement_receipt
                    raise native_boundary_v27._NativeLaunchUnresolvedV27(
                        recovered
                    )
                if candidate.get("status") == "launch-pre-effect-failed":
                    failure = _validate_worker_pre_effect_failure_v27(
                        candidate,
                        plan=plan,
                        manifest=manifest,
                        request_key=request_key,
                    )
                    proof_error: ControllerProtocolError | None = None
                    first_empty: dict[str, Any] | None = None
                    second_empty: dict[str, Any] | None = None
                    try:
                        if (
                            expected_native_event_sequence != 1
                            or pending_result_offer is not None
                        ):
                            raise ControllerProtocolError(
                                "pre-effect failure crossed native authority"
                            )
                        first_empty = _controller_pre_effect_empty_observation_v27(
                            custody
                        )
                        second_empty = _controller_pre_effect_empty_observation_v27(
                            custody
                        )
                        if first_empty != second_empty:
                            raise ControllerProtocolError(
                                "pre-effect S/P/O empty observations changed"
                            )
                    except ControllerProtocolError as exc:
                        proof_error = exc
                    retirement = custody.drain(
                        persist_intent=lambda intent: self._persist_retirement_artifact(
                            manifest,
                            plan,
                            "intent",
                            intent,
                            arena_record_sha256=arena_record_sha256,
                            controller_key=controller_key,
                            lifecycle_check=lambda: lifecycle_observation(
                                require_active=False
                            ),
                        )
                    )
                    retirement_receipt = {
                        **retirement,
                        "controllerTrackedPlacementMask": 0,
                    }
                    if retirement.get("placementMask") != 0:
                        raise ControllerProtocolError(
                            "pre-effect retirement observed a lifecycle child"
                        )
                    self._persist_retirement_artifact(
                        manifest,
                        plan,
                        "receipt",
                        retirement_receipt,
                        arena_record_sha256=arena_record_sha256,
                        controller_key=controller_key,
                        lifecycle_check=lambda: lifecycle_observation(
                            require_active=False
                        ),
                    )
                    retirement_done = True
                    if proof_error is not None:
                        unresolved_evidence = native_boundary_v27.sha256(
                            b"startup-factory/beads/v27/pre-effect-proof-unresolved\0"
                            + _canonical(
                                {
                                    "stagePlanSha256": plan["stagePlanSha256"],
                                    "workerFailureEvidenceSha256": failure[
                                        "evidenceSha256"
                                    ],
                                    "retirement": retirement_receipt,
                                }
                            )
                        )
                        recovered = native_boundary_v27._native_supervisor_loss_v27(
                            reason="dead-holder-without-terminal",
                            evidence_sha256=unresolved_evidence,
                        )
                        recovered["controllerRetirement"] = retirement_receipt
                        raise native_boundary_v27._NativeLaunchUnresolvedV27(
                            recovered
                        ) from proof_error
                    assert first_empty is not None and second_empty is not None
                    consumed_current = getattr(event_handler, "current", None)
                    if (
                        not isinstance(consumed_current, Mapping)
                        or consumed_current.get("kind")
                        != "SupervisorLaunchSlotConsumedCurrentV1"
                        or not _DIGEST.fullmatch(
                            str(consumed_current.get("recordSha256"))
                        )
                    ):
                        raise ControllerProtocolError(
                            "pre-effect proof lost its consumed-current identity"
                        )
                    proof_envelope = _controller_pre_effect_proof_envelope_v27(
                        plan=plan,
                        payload_name=custody.payload_name,
                        arena_record_sha256=arena_record_sha256,
                        consumed_current_record_sha256=str(
                            consumed_current["recordSha256"]
                        ),
                        worker_failure=failure,
                        first_empty_observation=first_empty,
                        second_empty_observation=second_empty,
                        controller_retirement=retirement_receipt,
                        controller_key=controller_key,
                    )
                    self._persist_retirement_artifact(
                        manifest,
                        plan,
                        "pre-effect-proof",
                        proof_envelope,
                        arena_record_sha256=arena_record_sha256,
                        controller_key=controller_key,
                        lifecycle_check=lambda: lifecycle_observation(
                            require_active=False
                        ),
                    )
                    proved_evidence = _sha(_canonical(proof_envelope))
                    raise native_boundary_v27._NativeLaunchPreEffectFailedV27(
                        proved_evidence,
                        failure["classification"],
                        proof_envelope,
                    )
                if candidate.get("status") != "placement-request":
                    break
                required = {
                    "schemaVersion", "protocol", "status", "stagePlanSha256",
                    "supervisorPid", "childPid", "childStartTime", "ordinal",
                    "placementNonce",
                }
                if set(candidate) != required or (
                    candidate["schemaVersion"],
                    candidate["protocol"],
                    candidate["stagePlanSha256"],
                ) != (27, _WORKER_PROTOCOL, plan["stagePlanSha256"]):
                    raise ControllerProtocolError(
                        "native lifecycle placement request identity changed"
                    )
                placement = custody.place_lifecycle_child(
                    child_pid=candidate["childPid"],
                    child_start_time=candidate["childStartTime"],
                    supervisor_pid=candidate["supervisorPid"],
                    ordinal=candidate["ordinal"],
                    placement_nonce=candidate["placementNonce"],
                )
                response = _canonical(
                    {
                        "schemaVersion": 27,
                        "protocol": _WORKER_PROTOCOL,
                        "status": "placement-authorized",
                        "stagePlanSha256": plan["stagePlanSha256"],
                        "placement": placement,
                    }
                )
                if self.channel.send(response) != len(response):
                    raise ControllerProtocolError(
                        "native lifecycle placement authorization was truncated"
                    )
            terminal_lifecycle = lifecycle_observation(require_active=False)
            response = _worker_packet_v27(packet, "native worker result")
            expected_fields = {
                "schemaVersion",
                "protocol",
                "status",
                "stagePlanSha256",
                "nativeStageObservation",
            }
            if set(response) != expected_fields or (
                response["schemaVersion"],
                response["protocol"],
                response["status"],
                response["stagePlanSha256"],
            ) != (27, _WORKER_PROTOCOL, "completed", plan["stagePlanSha256"]):
                raise ControllerProtocolError(
                    "native worker result identity is invalid"
                )
            observation = response["nativeStageObservation"]
            if not isinstance(observation, dict):
                raise ControllerProtocolError(
                    "native worker stage observation is invalid"
                )
            try:
                result = {
                    "exitCode": observation["exitCode"],
                    "placementMask": observation["placementMask"],
                    "stdout": base64.b64decode(
                        observation["stdoutBase64"], validate=True
                    ),
                    "stderr": base64.b64decode(
                        observation["stderrBase64"], validate=True
                    ),
                    "lifecycle": observation["lifecycle"],
                    "resultKind": observation["resultKind"],
                    "resultPredecessorKind": observation[
                        "resultPredecessorKind"
                    ],
                    "failureEvidenceSha256": observation[
                        "failureEvidenceSha256"
                    ],
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise ControllerProtocolError(
                    "native worker stage observation encoding is invalid"
                ) from exc
            native_boundary_v27._decode_native_stage_result_v27(
                result, require_discriminants=True
            )
            if (
                pending_result_offer is None
                or _sha(_canonical(observation))
                != pending_result_offer["nativeResultSha256"]
                or result["resultKind"] != pending_result_offer["resultKind"]
                or result["resultPredecessorKind"]
                != pending_result_offer["resultPredecessorKind"]
                or result["failureEvidenceSha256"]
                != pending_result_offer["failureEvidenceSha256"]
                or result["placementMask"]
                != pending_result_offer["placementMask"]
                or not callable(
                    getattr(event_handler, "receipt_result_handoff", None)
                )
            ):
                raise ControllerProtocolError(
                    "native result handoff differs from its authorized offer"
                )
            event_handler.receipt_result_handoff(observation)
            if (
                terminal_lifecycle is not None
                and terminal_lifecycle["operatorState"] == "disabled"
                and result["resultKind"] == "success"
            ):
                raise ControllerProtocolError(
                    "operator disable fenced a native success result"
                )
            native_mask = result["placementMask"]
            tracked_mask = sum(1 << ordinal for ordinal in custody.lifecycle_leaves)
            if native_mask != tracked_mask:
                raise ControllerProtocolError(
                    "native and controller-tracked placement masks differ"
                )
            retirement = custody.drain(
                persist_intent=lambda intent: self._persist_retirement_artifact(
                    manifest,
                    plan,
                    "intent",
                    intent,
                    arena_record_sha256=arena_record_sha256,
                    controller_key=controller_key,
                    lifecycle_check=lambda: lifecycle_observation(
                        require_active=False
                    ),
                )
            )
            retirement_receipt = {
                **retirement,
                "controllerTrackedPlacementMask": tracked_mask,
            }
            if retirement.get("placementMask") != tracked_mask:
                raise ControllerProtocolError(
                    "controller-tracked and retirement placement masks differ"
                )
            self._persist_retirement_artifact(
                manifest,
                plan,
                "receipt",
                retirement_receipt,
                arena_record_sha256=arena_record_sha256,
                controller_key=controller_key,
                lifecycle_check=lambda: lifecycle_observation(
                    require_active=False
                ),
            )
            retirement_done = True
            result["controllerRetirement"] = retirement_receipt
            if not callable(
                getattr(event_handler, "terminalize_result_handoff", None)
            ):
                raise ControllerProtocolError(
                    "native result handoff lacks terminal receipt authority"
                )
            event_handler.terminalize_result_handoff(retirement_receipt)
            native_boundary_v27._decode_native_stage_result_v27(
                result, require_discriminants=True
            )
            completed_result = result
            completed_retirement = dict(retirement)
        finally:
            try:
                if not retirement_done:
                    custody.kill_and_wait()
            finally:
                try:
                    if request_key_fd >= 0:
                        os.close(request_key_fd)
                finally:
                    custody.close(retire=retirement_done)
            if plan.get("repositoryCustody") is not None:
                try:
                    os.stat(
                        custody.payload_name,
                        dir_fd=self.supervisor_cgroup_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    self.repository_release_receipts[
                        plan["stagePlanSha256"]
                    ] = self._probe_repository_release(
                        manifest,
                        plan,
                        request_key=request_key,
                        lifecycle_check=lambda: lifecycle_observation(
                            require_active=False
                        ),
                    )
        if completed_result is None or completed_retirement is None:
            raise ControllerProtocolError(
                "native worker completed without a retirement result"
            )
        try:
            os.stat(
                custody.payload_name,
                dir_fd=self.supervisor_cgroup_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise ControllerProtocolError(
                "native worker success preceded payload cgroup removal"
            )
        self.retirement_receipts[custody.payload_name] = completed_retirement
        return completed_result

    def _probe_repository_release(
        self,
        manifest: native_boundary_v27.NativeBoundaryManifestV27,
        plan: Mapping[str, Any],
        *,
        request_key: bytes,
        lifecycle_check: Any,
    ) -> dict[str, Any]:
        """Ask the persistent UID993 worker to prove it retained no custody."""

        del manifest  # The worker revalidates the protected installed manifest.
        self._assert_peer()
        probe_nonce = secrets.token_hex(32)
        custody = native_boundary_v27.validate_repository_custody_binding_v27(
            plan.get("repositoryCustody"),
            repository_path=str(plan["repositoryPath"]),
        )
        post_manifest = native_boundary_v27._repository_custody_manifest_v27(
            Path(str(plan["repositoryPath"])),
            controller_uid=self.controller_uid,
            worker_gid=self.cgroup_worker_gid,
            directory_mode=(
                0o550 if custody["accessMode"] == "read-only" else 0o770
            ),
            file_mode=(
                0o440 if custody["accessMode"] == "read-only" else 0o660
            ),
        )
        request_key_fd, key_copy = (
            native_boundary_v27._sealed_request_key_descriptor_v27(request_key)
        )
        for index in range(len(key_copy)):
            key_copy[index] = 0
        request = _canonical(
            {
                "schemaVersion": 27,
                "protocol": _WORKER_PROTOCOL,
                "action": "PROBE-REPOSITORY-RELEASE",
                "plan": dict(plan),
                "cgroupBinding": None,
                "retirementArtifact": {
                    "kind": "repository-release-probe",
                    "value": {
                        "probeNonce": probe_nonce,
                        "postManifest": post_manifest,
                    },
                },
            }
        )
        try:
            rights = array.array("i", (request_key_fd,))
            if self.channel.sendmsg(
                [request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
            ) != len(request):
                raise ControllerProtocolError(
                    "native repository release probe packet was truncated"
                )
        finally:
            os.close(request_key_fd)
        lifecycle_check()
        self._assert_peer()
        response = _worker_packet_v27(
            _recv_credentialed_packet_v27(
                self.channel,
                expected_pid=self.pid,
                expected_uid=self.worker_uid,
                expected_gid=self.worker_gid,
                label="native repository release probe",
            ),
            "native repository release probe",
        )
        if set(response) != {
            "schemaVersion", "protocol", "status", "stagePlanSha256",
            "releaseReceipt",
        } or (
            response["schemaVersion"],
            response["protocol"],
            response["status"],
            response["stagePlanSha256"],
        ) != (
            27,
            _WORKER_PROTOCOL,
            "repository-release-proved",
            plan["stagePlanSha256"],
        ):
            raise ControllerProtocolError(
                "native repository release probe identity changed"
            )
        receipt = response["releaseReceipt"]
        if not isinstance(receipt, Mapping):
            raise ControllerProtocolError(
                "native repository release receipt is malformed"
            )
        fields = {
            "schemaVersion", "operationId", "stageLocation",
            "stagePlanSha256", "workerSessionNonce", "grantWorkerSessionNonce", "probeNonce",
            "repositoryBindingSha256", "repositoryManifestSha256",
            "postRepositoryManifestSha256",
            "descriptorCount", "descriptorInventorySha256",
            "descriptorMatches", "mountCount", "mountInfoSha256",
            "mountMatches", "releaseHmac",
        }
        body = {key: receipt.get(key) for key in fields if key != "releaseHmac"}
        expected_hmac = "hmac-sha256:" + hmac.new(
            request_key,
            _REPOSITORY_CUSTODY_RELEASE_DOMAIN_V27 + _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        if (
            set(receipt) != fields
            or receipt.get("schemaVersion") != 27
            or receipt.get("operationId") != plan["operationId"]
            or receipt.get("stageLocation") != plan["stageLocation"]
            or receipt.get("stagePlanSha256") != plan["stagePlanSha256"]
            or receipt.get("workerSessionNonce") != self.worker_session_nonce
            or receipt.get("grantWorkerSessionNonce")
            != custody["workerSessionNonce"]
            or receipt.get("probeNonce") != probe_nonce
            or receipt.get("repositoryBindingSha256")
            != custody["bindingSha256"]
            or receipt.get("repositoryManifestSha256")
            != custody["manifestSha256"]
            or receipt.get("postRepositoryManifestSha256")
            != post_manifest["manifestSha256"]
            or receipt.get("descriptorMatches") != []
            or receipt.get("mountMatches") != []
            or type(receipt.get("descriptorCount")) is not int
            or type(receipt.get("mountCount")) is not int
            or not hmac.compare_digest(
                str(receipt.get("releaseHmac")), expected_hmac
            )
        ):
            raise ControllerProtocolError(
                "native repository release receipt changed or retained access"
            )
        return dict(receipt)

    def _persist_retirement_artifact(
        self,
        manifest: native_boundary_v27.NativeBoundaryManifestV27,
        plan: Mapping[str, Any],
        artifact_kind: str,
        value: Mapping[str, Any],
        *,
        arena_record_sha256: str,
        controller_key: bytes,
        lifecycle_check: Any,
    ) -> None:
        self._assert_peer()
        payload_name = _payload_cgroup_name_v27(plan)
        if artifact_kind == "intent":
            decoded = native_boundary_v27._decode_controller_retirement_intent_v27(
                value
            )
            payload_identity = decoded["payloadIdentity"]
            predecessor = None
        elif artifact_kind == "receipt":
            decoded = native_boundary_v27._decode_controller_retirement_v27(
                value, value.get("placementMask")
            )
            prior = self.retirement_intents.get(payload_name)
            if prior is None:
                raise ControllerProtocolError(
                    "native retirement receipt lacks its authenticated intent"
                )
            payload_identity = prior[0]["payloadIdentity"]
            predecessor = prior[1]
        elif artifact_kind == "pre-effect-proof":
            if (
                not isinstance(value, Mapping)
                or set(value) != {"proof", "controllerHmac"}
            ):
                raise ControllerProtocolError(
                    "native pre-effect proof persistence envelope changed"
                )
            decoded = dict(value)
            envelope = dict(value)
            payload_identity = {}
            predecessor = None
        else:
            raise ControllerProtocolError(
                "native retirement artifact kind changed"
            )
        if artifact_kind != "pre-effect-proof":
            envelope = _controller_retirement_envelope_v27(
                kind=artifact_kind,
                plan=plan,
                payload_name=payload_name,
                payload_identity=payload_identity,
                arena_record_sha256=arena_record_sha256,
                predecessor_artifact_sha256=predecessor,
                body=decoded,
                controller_key=controller_key,
            )
        artifact = {"kind": artifact_kind, "value": envelope}
        artifact_sha256 = native_boundary_v27.sha256(
            native_boundary_v27.canonical_bytes(artifact)
        )
        request = _canonical(
            {
                "schemaVersion": 27,
                "protocol": _WORKER_PROTOCOL,
                "action": "PERSIST-RETIREMENT",
                "plan": dict(plan),
                "cgroupBinding": None,
                "retirementArtifact": artifact,
            }
        )
        if self.channel.send(request) != len(request):
            raise ControllerProtocolError(
                "native retirement persistence packet was truncated"
            )
        lifecycle_check()
        self._assert_peer()
        packet = _recv_credentialed_packet_v27(
            self.channel,
            expected_pid=self.pid,
            expected_uid=self.worker_uid,
            expected_gid=self.worker_gid,
            label="native retirement persistence acknowledgement",
        )
        response = _worker_packet_v27(
            packet, "native retirement persistence acknowledgement"
        )
        if set(response) != {
            "schemaVersion", "protocol", "status", "stagePlanSha256",
            "artifactKind", "artifactSha256",
        } or (
            response["schemaVersion"], response["protocol"],
            response["status"], response["stagePlanSha256"],
            response["artifactKind"], response["artifactSha256"],
        ) != (
            27, _WORKER_PROTOCOL, "retirement-artifact-durable",
            plan["stagePlanSha256"], artifact_kind, artifact_sha256,
        ):
            raise ControllerProtocolError(
                "native retirement persistence acknowledgement changed"
            )
        envelope_sha256 = _sha(_canonical(envelope))
        if artifact_kind == "intent":
            self.retirement_intents[payload_name] = (
                dict(decoded), envelope_sha256
            )

    def _prepare_result_arena(
        self,
        manifest: native_boundary_v27.NativeBoundaryManifestV27,
        plan: Mapping[str, Any],
        *,
        request_key: bytes,
        controller_key: bytes,
        lifecycle_check: Any,
    ) -> str:
        """Complete worker PREPARE and controller-authenticated durable ACK."""

        request_key_fd, request_key_copy = (
            native_boundary_v27._sealed_request_key_descriptor_v27(request_key)
        )
        for index in range(len(request_key_copy)):
            request_key_copy[index] = 0
        request = _canonical(
            {
                "schemaVersion": 27,
                "protocol": _WORKER_PROTOCOL,
                "action": "PREPARE",
                "plan": dict(plan),
                "cgroupBinding": None,
                "retirementArtifact": None,
            }
        )
        try:
            rights = array.array("i", (request_key_fd,))
            if self.channel.sendmsg(
                [request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
            ) != len(request):
                raise ControllerProtocolError(
                    "native result-arena PREPARE packet was truncated"
                )
        finally:
            os.close(request_key_fd)
        lifecycle_check()
        self._assert_peer()
        prepared = _worker_packet_v27(
            _recv_credentialed_packet_v27(
                self.channel,
                expected_pid=self.pid,
                expected_uid=self.worker_uid,
                expected_gid=self.worker_gid,
                label="native result-arena PREPARE acknowledgement",
            ),
            "native result-arena PREPARE acknowledgement",
        )
        if set(prepared) != {
            "schemaVersion", "protocol", "status", "stagePlanSha256",
            "arenaPreparation",
        } or (
            prepared["schemaVersion"], prepared["protocol"],
            prepared["status"], prepared["stagePlanSha256"],
        ) != (
            27, _WORKER_PROTOCOL, "result-arena-prepared",
            plan["stagePlanSha256"],
        ):
            raise ControllerProtocolError(
                "native result-arena PREPARE acknowledgement changed"
            )
        envelope = _controller_result_arena_envelope_v27(
            prepared["arenaPreparation"], plan, request_key, controller_key
        )
        ack = _canonical(
            {
                "schemaVersion": 27,
                "protocol": _WORKER_PROTOCOL,
                "action": "ACK-ARENA",
                "plan": dict(plan),
                "cgroupBinding": None,
                "retirementArtifact": {"kind": "arena", "value": envelope},
            }
        )
        if self.channel.send(ack) != len(ack):
            raise ControllerProtocolError(
                "native result-arena ACK packet was truncated"
            )
        lifecycle_check()
        self._assert_peer()
        durable = _worker_packet_v27(
            _recv_credentialed_packet_v27(
                self.channel,
                expected_pid=self.pid,
                expected_uid=self.worker_uid,
                expected_gid=self.worker_gid,
                label="native result-arena durable acknowledgement",
            ),
            "native result-arena durable acknowledgement",
        )
        expected_sha256 = _sha(_canonical(envelope))
        if set(durable) != {
            "schemaVersion", "protocol", "status", "stagePlanSha256",
            "arenaRecordSha256",
        } or (
            durable["schemaVersion"], durable["protocol"], durable["status"],
            durable["stagePlanSha256"], durable["arenaRecordSha256"],
        ) != (
            27, _WORKER_PROTOCOL, "result-arena-durable",
            plan["stagePlanSha256"], expected_sha256,
        ):
            raise ControllerProtocolError(
                "native result-arena durable acknowledgement changed"
            )
        self.arena_records[_payload_cgroup_name_v27(plan)] = expected_sha256
        return expected_sha256

    def recover(
        self,
        manifest: native_boundary_v27.NativeBoundaryManifestV27,
        value: Any,
        *,
        lifecycle_check: Any,
    ) -> dict[str, Any]:
        """Recover a durable FD10 result through the worker; never relaunch."""

        plan = native_boundary_v27.validate_native_stage_action_plan_v27(
            value, manifest
        )
        self._assert_peer()
        payload_name = _payload_cgroup_name_v27(plan)
        try:
            os.stat(
                payload_name,
                dir_fd=self.supervisor_cgroup_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise ControllerProtocolError(
                "native result is ineligible while its payload cgroup exists"
            )
        request_key = native_boundary_v27._NATIVE_REQUEST_KEY_V27.get()
        if request_key is None or native_boundary_v27.sha256(request_key) != plan["requestKeyId"]:
            raise ControllerProtocolError(
                "native worker recovery lacks the exact derived request key"
            )
        request_key_fd, request_key_copy = (
            native_boundary_v27._sealed_request_key_descriptor_v27(request_key)
        )
        for index in range(len(request_key_copy)):
            request_key_copy[index] = 0
        request = _canonical(
            {
                "schemaVersion": 27,
                "protocol": _WORKER_PROTOCOL,
                "action": "RECOVER",
                "plan": plan,
                "cgroupBinding": None,
                "retirementArtifact": None,
            }
        )
        try:
            rights = array.array("i", (request_key_fd,))
            if self.channel.sendmsg(
                [request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
            ) != len(request):
                raise ControllerProtocolError(
                    "native worker recovery packet was truncated"
                )
        finally:
            os.close(request_key_fd)
        lifecycle_check()
        self._assert_peer()
        packet = _recv_credentialed_packet_v27(
            self.channel,
            expected_pid=self.pid,
            expected_uid=self.worker_uid,
            expected_gid=self.worker_gid,
            label="native worker recovered result",
        )
        response = _worker_packet_v27(packet, "native worker recovered result")
        if set(response) == {
            "schemaVersion", "protocol", "status", "stagePlanSha256",
            "nativeLaunchPreEffectProof", "controllerRetirementChain",
        } and (
            response["schemaVersion"], response["protocol"],
            response["status"], response["stagePlanSha256"],
        ) == (
            27, _WORKER_PROTOCOL, "launch-pre-effect-proved",
            plan["stagePlanSha256"],
        ):
            return {
                "nativeLaunchPreEffectProof": response[
                    "nativeLaunchPreEffectProof"
                ],
                "_controllerRetirementChain": response[
                    "controllerRetirementChain"
                ],
            }
        if set(response) == {
            "schemaVersion", "protocol", "status", "stagePlanSha256",
            "nativeSupervisorLoss", "controllerRetirementChain",
        } and (
            response["schemaVersion"], response["protocol"],
            response["status"], response["stagePlanSha256"],
        ) == (27, _WORKER_PROTOCOL, "loss", plan["stagePlanSha256"]):
            loss = {
                "nativeSupervisorLoss": response["nativeSupervisorLoss"],
                "_controllerRetirementChain": response[
                    "controllerRetirementChain"
                ],
            }
            if not native_boundary_v27._is_native_supervisor_loss_v27(loss):
                raise ControllerProtocolError(
                    "native worker recovered loss binding changed"
                )
            return loss
        if set(response) != {
            "schemaVersion", "protocol", "status", "stagePlanSha256",
            "nativeStageObservation", "controllerRetirementChain",
            "nativeCreatorArtifactBinding",
        } or (
            response["schemaVersion"], response["protocol"], response["status"],
            response["stagePlanSha256"],
        ) != (27, _WORKER_PROTOCOL, "completed", plan["stagePlanSha256"]):
            raise ControllerProtocolError(
                "native worker recovered result identity changed"
            )
        observation = response["nativeStageObservation"]
        try:
            result = {
                "exitCode": observation["exitCode"],
                "placementMask": observation["placementMask"],
                "stdout": base64.b64decode(observation["stdoutBase64"], validate=True),
                "stderr": base64.b64decode(observation["stderrBase64"], validate=True),
                "lifecycle": observation["lifecycle"],
                "resultKind": observation["resultKind"],
                "resultPredecessorKind": observation[
                    "resultPredecessorKind"
                ],
                "failureEvidenceSha256": observation[
                    "failureEvidenceSha256"
                ],
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise ControllerProtocolError(
                "native worker recovered result encoding changed"
            ) from exc
        native_boundary_v27._decode_native_stage_result_v27(result)
        result["_controllerRetirementChain"] = response[
            "controllerRetirementChain"
        ]
        if response["nativeCreatorArtifactBinding"] is not None:
            result["_nativeCreatorArtifactBinding"] = response[
                "nativeCreatorArtifactBinding"
            ]
        return result

    def terminate(self) -> None:
        try:
            if hasattr(signal, "pidfd_send_signal"):
                signal.pidfd_send_signal(self.pidfd, signal.SIGKILL, None, 0)
            else:
                os.kill(self.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass

    def close(self) -> None:
        try:
            self.channel.sendall(
                _canonical(
                    {
                        "schemaVersion": 27,
                        "protocol": _WORKER_PROTOCOL,
                        "action": "STOP",
                        "plan": None,
                        "cgroupBinding": None,
                        "retirementArtifact": None,
                    }
                )
            )
        except OSError:
            pass
        self.channel.close()
        try:
            waited, _status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            waited = self.pid
        try:
            if waited == 0:
                self.terminate()
        finally:
            try:
                os.close(self.pidfd)
            except OSError:
                pass
            try:
                os.close(self.supervisor_cgroup_fd)
            except OSError:
                pass
            try:
                os.close(self.supervisor_procs_fd)
            except OSError:
                pass
            try:
                os.close(self.worker_procs_fd)
            except OSError:
                pass
            try:
                os.close(self.worker_cgroup_fd)
            except OSError:
                pass


@dataclasses.dataclass(slots=True)
class _WorkerStageRunnerV27:
    worker: _WorkerChannelV27
    lifecycle_check: Any
    controller_key: bytes

    def repository_custody_profile_v27(
        self, _plan: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "rootPath": str(REPOSITORY_HANDOFF_ROOT_V27),
            "controllerUid": self.worker.controller_uid,
            "workerGid": self.worker.cgroup_worker_gid,
            "workerSessionNonce": self.worker.worker_session_nonce,
        }

    def repository_custody_release_receipt_v27(
        self, plan: Mapping[str, Any]
    ) -> dict[str, Any]:
        receipt = self.worker.repository_release_receipts.pop(
            str(plan["stagePlanSha256"]), None
        )
        if receipt is None:
            raise ControllerProtocolError(
                "native repository custody was not proved released"
            )
        return receipt

    def __call__(
        self,
        manifest: native_boundary_v27.NativeBoundaryManifestV27,
        plan: Any,
    ) -> dict[str, Any]:
        validated_plan = native_boundary_v27.validate_native_stage_action_plan_v27(
            plan, manifest
        )
        event_handler = native_boundary_v27._NATIVE_OUTER_EVENT_HANDLER_V27.get()
        if not callable(getattr(
            event_handler, "bind_native_stage_authority_v27", None
        )):
            raise ControllerProtocolError(
                "native stage execution lacks outer-current authority"
            )
        event_handler.bind_native_stage_authority_v27(validated_plan)
        return self.worker.execute(
            manifest,
            validated_plan,
            lifecycle_check=self.lifecycle_check,
            controller_key=self.controller_key,
            event_handler=event_handler,
        )

    def recover(
        self,
        manifest: native_boundary_v27.NativeBoundaryManifestV27,
        plan: Any,
    ) -> dict[str, Any]:
        result = self.worker.recover(
            manifest, plan, lifecycle_check=self.lifecycle_check
        )
        validated_plan = native_boundary_v27.validate_native_stage_action_plan_v27(
            plan, manifest
        )
        event_handler = native_boundary_v27._NATIVE_OUTER_EVENT_HANDLER_V27.get()
        if callable(getattr(
            event_handler, "bind_native_stage_authority_v27", None
        )):
            event_handler.bind_native_stage_authority_v27(validated_plan)
        request_key = native_boundary_v27._NATIVE_REQUEST_KEY_V27.get()
        if (
            request_key is None
            or native_boundary_v27.sha256(request_key)
            != validated_plan["requestKeyId"]
        ):
            raise ControllerProtocolError(
                "native result recovery lacks the exact derived request key"
            )
        if isinstance(result, Mapping) and set(result) == {
            "nativeLaunchPreEffectProof", "_controllerRetirementChain"
        }:
            retirement = _verify_controller_retirement_chain_v27(
                result["_controllerRetirementChain"],
                plan=validated_plan,
                request_key=request_key,
                controller_key=self.controller_key,
                expected_placement_mask=0,
            )
            try:
                proof = _verify_controller_pre_effect_proof_v27(
                    result["nativeLaunchPreEffectProof"],
                    plan=validated_plan,
                    controller_key=self.controller_key,
                    arena_record_sha256=_sha(
                        _canonical(result["_controllerRetirementChain"]["arena"])
                    ),
                    retirement=retirement,
                )
            except ControllerProtocolError:
                # Worker-readable proof bytes are relay data only.  Once the
                # consumed holder is dead, an absent, forged, rebound, or
                # swapped controller proof cannot establish never-created.
                # The controller's verified arena/retirement custody turns
                # that ambiguity into the closed non-public loss branch.
                return {
                    "nativeSupervisorLoss": (
                        native_boundary_v27._native_supervisor_loss_v27(
                            reason="dead-holder-without-terminal",
                            evidence_sha256=native_boundary_v27.sha256(
                                b"startup-factory/beads/v27/invalid-pre-effect-proof\0"
                                + _canonical(
                                    {
                                        "operationId": validated_plan["operationId"],
                                        "stageLocation": validated_plan["stageLocation"],
                                        "stagePlanSha256": validated_plan[
                                            "stagePlanSha256"
                                        ],
                                        "arenaRecordSha256": _sha(
                                            _canonical(
                                                result[
                                                    "_controllerRetirementChain"
                                                ]["arena"]
                                            )
                                        ),
                                        "proofRelaySha256": _sha(
                                            _canonical(
                                                result[
                                                    "nativeLaunchPreEffectProof"
                                                ]
                                            )
                                        ),
                                    }
                                ),
                            ),
                        )["nativeSupervisorLoss"]
                    ),
                    "controllerRetirement": retirement,
                }
            raise native_boundary_v27._NativeLaunchPreEffectFailedV27(
                _sha(_canonical(result["nativeLaunchPreEffectProof"])),
                proof["workerFailure"]["classification"],
                result["nativeLaunchPreEffectProof"],
            )
        if native_boundary_v27._is_native_supervisor_loss_v27(result):
            if set(result) != {
                "nativeSupervisorLoss", "_controllerRetirementChain"
            }:
                raise ControllerProtocolError(
                    "native loss recovery lacks the full retirement chain"
                )
            retirement = _verify_controller_retirement_chain_v27(
                result["_controllerRetirementChain"],
                plan=validated_plan,
                request_key=request_key,
                controller_key=self.controller_key,
                expected_placement_mask=None,
            )
            return {
                "nativeSupervisorLoss": dict(result["nativeSupervisorLoss"]),
                "controllerRetirement": retirement,
            }
        if not isinstance(result, Mapping) or set(result) not in ({
            "exitCode", "placementMask", "stdout", "stderr", "lifecycle",
            "resultKind", "resultPredecessorKind", "failureEvidenceSha256",
            "_controllerRetirementChain",
        }, {
            "exitCode", "placementMask", "stdout", "stderr", "lifecycle",
            "resultKind", "resultPredecessorKind", "failureEvidenceSha256",
            "_controllerRetirementChain", "_nativeCreatorArtifactBinding",
        }):
            raise ControllerProtocolError(
                "native result recovery lacks the full retirement chain"
            )
        retirement = _verify_controller_retirement_chain_v27(
            result["_controllerRetirementChain"],
            plan=validated_plan,
            request_key=request_key,
            controller_key=self.controller_key,
            expected_placement_mask=result["placementMask"],
        )
        recovered = {
            key: value
            for key, value in result.items()
            if key not in {
                "_controllerRetirementChain", "_nativeCreatorArtifactBinding"
            }
        }
        artifact_binding = result.get("_nativeCreatorArtifactBinding")
        if recovered["resultKind"] in {
            "success", "revoke-verified-no-effect"
        }:
            if not callable(getattr(
                event_handler, "verify_creator_artifact_binding_v27", None
            )):
                raise ControllerProtocolError(
                    "native creator artifact recovery lacks controller authority"
                )
            event_handler.verify_creator_artifact_binding_v27(
                artifact_binding, recovered["resultKind"]
            )
        elif artifact_binding is not None:
            raise ControllerProtocolError(
                "non-creator result carried a creator artifact binding"
            )
        recovered["controllerRetirement"] = retirement
        native_boundary_v27._decode_native_stage_result_v27(recovered)
        cached = self.worker.retirement_receipts.get(
            _payload_cgroup_name_v27(validated_plan)
        )
        if cached is not None and {
            **cached,
            "controllerTrackedPlacementMask": cached.get("placementMask"),
        } != retirement:
            raise ControllerProtocolError(
                "cached and authenticated retirement receipts differ"
            )
        return recovered


def _move_worker_to_supervisor_cgroup_v27(
    worker_pid: int,
    *,
    worker_pidfd: int,
    worker_start_time: str,
    controller_uid: int,
    worker_uid: int,
    worker_gid: int,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_root: Path = Path("/proc"),
    cgroup2_observer: Any = None,
    cgroup_mode_observer: Any = None,
) -> tuple[int, int, int, int, str, dict[str, dict[str, Any]]]:
    """Place a paused worker in W, leaving S empty for controller enablement."""

    if type(worker_pid) is not int or worker_pid <= 1:
        raise ControllerProtocolError("native worker PID is invalid")
    try:
        relative = native_boundary_v27._unified_cgroup_relative_v27(
            (proc_root / "self/cgroup").read_bytes()
        )
        if Path(relative).name != "controller":
            raise ControllerProtocolError(
                "controller is not in the exact delegated controller subgroup"
            )
        supervisor = native_boundary_v27._delegated_supervisor_path_v27(
            relative, cgroup_root=cgroup_root
        )
        try:
            os.mkdir(supervisor, _SUPERVISOR_CGROUP_MODE_V27)
        except FileExistsError:
            pass
        os.chown(
            supervisor,
            controller_uid,
            worker_gid,
            follow_symlinks=False,
        )
        os.chmod(
            supervisor,
            _SUPERVISOR_CGROUP_MODE_V27,
            follow_symlinks=False,
        )
        descriptor = os.open(
            supervisor,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != controller_uid
            or metadata.st_gid != worker_gid
            or _observed_cgroup_mode_v27(descriptor, cgroup_mode_observer)
            != _SUPERVISOR_CGROUP_MODE_V27
        ):
            raise ControllerProtocolError(
                "delegated supervisor cgroup owner/mode/type changed"
            )
        supervisor_process_file = _prepare_supervisor_process_control_v27(
            descriptor,
            controller_uid=controller_uid,
            worker_uid=worker_uid,
            worker_gid=worker_gid,
            cgroup2_observer=cgroup2_observer,
        )
        # Stale payloads are recovered only after the worker has forked and
        # the parent has loaded the controller-only HMAC key.  This preserves
        # the worker key-denial invariant while allowing authenticated arena
        # and retirement journals to be verified before service readiness.
        recovered_retirements: dict[str, dict[str, Any]] = {}
        try:
            os.mkdir("worker", _WORKER_CGROUP_MODE_V27, dir_fd=descriptor)
        except FileExistsError:
            pass
        worker_before = os.stat(
            "worker", dir_fd=descriptor, follow_symlinks=False
        )
        worker_descriptor = _open_recover_worker_cgroup_v27(
            descriptor,
            worker_before,
            controller_uid=controller_uid,
            worker_gid=worker_gid,
            cgroup2_observer=cgroup2_observer,
            cgroup_mode_observer=cgroup_mode_observer,
        )
        worker_metadata = os.fstat(worker_descriptor)
        if (
            not stat.S_ISDIR(worker_metadata.st_mode)
            or worker_metadata.st_uid != controller_uid
            or worker_metadata.st_gid != worker_gid
            or stat.S_IMODE(worker_metadata.st_mode) != _WORKER_CGROUP_MODE_V27
        ):
            raise ControllerProtocolError(
                "delegated worker cgroup owner/mode/type changed"
            )
        worker_process_file = os.open(
            "cgroup.procs",
            os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=worker_descriptor,
        )
        _validate_supervisor_process_control_v27(
            worker_process_file, worker_uid=worker_uid
        )
        relative_supervisor = "/" + "/".join(
            supervisor.relative_to(cgroup_root).parts
        )
        relative_worker = relative_supervisor + "/worker"
        _place_persistent_worker_v27(
            worker_process_file,
            worker_pid=worker_pid,
            pidfd=worker_pidfd,
            start_time=worker_start_time,
            expected_relative=relative_worker,
            proc_root=proc_root,
        )
        _enable_exact_subtree_controllers_v27(descriptor)
        return (
            descriptor,
            supervisor_process_file,
            worker_descriptor,
            worker_process_file,
            relative_worker,
            recovered_retirements,
        )
    except (
        OSError,
        native_boundary_v27.NativeBoundaryV27Error,
        ControllerProtocolError,
    ) as exc:
        if "descriptor" in locals():
            try:
                os.close(descriptor)
            except OSError:
                pass
        if "worker_process_file" in locals():
            try:
                os.close(worker_process_file)
            except OSError:
                pass
        if "supervisor_process_file" in locals():
            try:
                os.close(supervisor_process_file)
            except OSError:
                pass
        if "worker_descriptor" in locals():
            try:
                os.close(worker_descriptor)
            except OSError:
                pass
        if isinstance(exc, ControllerProtocolError):
            raise
        raise ControllerProtocolError(
            f"cannot place native worker in delegated supervisor cgroup: {exc}"
        ) from exc


def _spawn_worker_channel_v27(
    config: ControllerConfig,
    manifest: native_boundary_v27.NativeBoundaryManifestV27,
) -> _WorkerChannelV27:
    parent, child = socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
    )
    parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    try:
        worker_gid = pwd.getpwuid(config.worker_uid).pw_gid
    except KeyError as exc:
        parent.close()
        child.close()
        raise ControllerProtocolError("configured worker UID has no local account") from exc
    parent_pid = os.getpid()
    worker_session_nonce = secrets.token_hex(32)
    release_read, release_write = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        parent.close()
        os.close(release_write)
        try:
            if os.read(release_read, 1) != b"R":
                raise ControllerProtocolError(
                    "native worker cgroup release gate was not satisfied"
                )
            os.close(release_read)
            _worker_main_v27(
                child,
                config,
                manifest,
                parent_pid,
                worker_session_nonce,
            )
        except BaseException:
            os._exit(125)
        os._exit(0)
    child.close()
    os.close(release_read)
    if not hasattr(os, "pidfd_open"):
        parent.close()
        os.close(release_write)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise ControllerProtocolError("native worker custody requires pidfd_open")
    try:
        pidfd = os.pidfd_open(pid, 0)
        worker_start_time = _process_start_time_v27(pid)
        (
            supervisor_cgroup_fd,
            supervisor_procs_fd,
            worker_cgroup_fd,
            worker_procs_fd,
            worker_cgroup_relative,
            recovered_retirements,
        ) = _move_worker_to_supervisor_cgroup_v27(
            pid,
            worker_pidfd=pidfd,
            worker_start_time=worker_start_time,
            controller_uid=config.controller_uid,
            worker_uid=config.worker_uid,
            worker_gid=worker_gid,
        )
        native_boundary_v27._write_all_v27(release_write, b"R")
        os.close(release_write)
        return _WorkerChannelV27(
            parent,
            pid,
            pidfd,
            config.worker_uid,
            worker_gid,
            config.controller_uid,
            worker_gid,
            supervisor_cgroup_fd,
            supervisor_procs_fd,
            worker_cgroup_fd,
            worker_procs_fd,
            worker_cgroup_relative,
            worker_start_time,
            worker_session_nonce,
            recovered_retirements,
        )
    except Exception:
        os.close(release_write)
        parent.close()
        try:
            if "pidfd" in locals() and hasattr(signal, "pidfd_send_signal"):
                signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            else:
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
        if "pidfd" in locals():
            os.close(pidfd)
        if "supervisor_cgroup_fd" in locals():
            os.close(supervisor_cgroup_fd)
        if "supervisor_procs_fd" in locals():
            os.close(supervisor_procs_fd)
        if "worker_procs_fd" in locals():
            os.close(worker_procs_fd)
        if "worker_cgroup_fd" in locals():
            os.close(worker_cgroup_fd)
        raise


def _validate_endpoint_parent(config: ControllerConfig) -> None:
    path = ENDPOINT_PATH.parent
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ControllerProtocolError("controller endpoint parent is not normalized")
    descriptor = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != config.transport_gid
            or stat.S_IMODE(metadata.st_mode) != 0o750
        ):
            raise ControllerProtocolError(
                "controller endpoint parent must be root:transport mode 0750"
            )
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(
            f"cannot open fixed controller endpoint parent: {exc}"
        ) from exc
    finally:
        os.close(descriptor)


def _validate_controller_directory(path: Path, config: ControllerConfig, label: str) -> None:
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ControllerProtocolError(f"{label} path is not normalized and absolute")
    descriptor = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != config.controller_uid
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ControllerProtocolError(
                f"{label} must be a controller-owned private directory"
            )
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot open fixed {label}: {exc}") from exc
    finally:
        os.close(descriptor)


def _request(action: str, request: Mapping[str, Any], config: ControllerConfig) -> dict[str, Any]:
    if not config.beads_enabled:
        raise ControllerProtocolError("protected Beads boundary is disabled")
    if action not in {"OPEN", "STEP", "VALIDATE", "RECOVER", "EXECUTE"}:
        raise ControllerProtocolError("client requested an unknown controller action")
    if not sys.platform.startswith("linux"):
        raise ControllerProtocolError("fixed Beads boundary controller requires Linux")
    if os.geteuid() != config.broker_uid:
        raise ControllerProtocolError(
            "client process is not the distinct configured broker UID"
        )
    _validate_transport_group(config)
    _validate_endpoint_parent(config)
    _endpoint_metadata(config)
    packet = {"schemaVersion": 1, "protocol": PROTOCOL, "action": action, "request": dict(request)}
    encoded = _canonical(packet)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        connection.settimeout(5.0)
        connection.connect(str(ENDPOINT_PATH))
        _, peer_uid, _ = _peer_credentials(connection)
        if peer_uid != config.controller_uid or peer_uid in {config.broker_uid, config.worker_uid}:
            raise ControllerProtocolError("controller peer credential does not match the distinct configured controller UID")
        connection.sendall(encoded)
        response = connection.recv(MAX_MESSAGE_BYTES + 1)
        if not response or len(response) > MAX_MESSAGE_BYTES:
            raise ControllerProtocolError("controller response is empty or oversized")
        extra = connection.recv(1)
        if extra:
            raise ControllerProtocolError("controller sent more than one response packet")
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"fixed controller exchange failed: {exc}") from exc
    finally:
        connection.close()
    try:
        value = json.loads(response)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("controller returned malformed JSON") from exc
    expected_response_fields = set(_RESPONSE_FIELDS)
    if action == "RECOVER":
        expected_response_fields |= _RECOVERY_RESPONSE_EXTRA_FIELDS
    elif action == "EXECUTE":
        expected_response_fields |= _EXECUTE_RESPONSE_EXTRA_FIELDS
    if not isinstance(value, dict) or set(value) != expected_response_fields or _canonical(value) != response:
        raise ControllerProtocolError("controller response is not a canonical closed object")
    if value.get("schemaVersion") != 1 or value.get("protocol") != PROTOCOL or value.get("action") != action or value.get("requestSha256") != _sha(encoded):
        raise ControllerProtocolError("controller response does not bind the exact request")
    if value.get("provenanceDomain") != PRODUCTION_PROVENANCE or value.get("status") not in {"accepted", "completed", "validated", "recovered", "executed"}:
        raise ControllerProtocolError("controller response is not live production provenance")
    _digest(value.get("receiptSha256"), "receiptSha256")
    if not isinstance(value.get("controllerHmac"), str) or not _HMAC.fullmatch(value["controllerHmac"]):
        raise ControllerProtocolError("controller response lacks controller-only HMAC evidence")
    receipt_material = dict(value)
    receipt_sha256 = receipt_material.pop("receiptSha256")
    if receipt_sha256 != _sha(_canonical(receipt_material)):
        raise ControllerProtocolError("controller response receipt digest is invalid")
    _operation_id(value.get("operationId"), "controller response operationId")
    _nonce(value.get("sessionNonce"), "controller response session nonce")
    _digest(value.get("resultSha256"), "resultSha256", nullable=True)
    if value.get("state") not in _STATES:
        raise ControllerProtocolError("controller response state is invalid")
    if action == "RECOVER":
        _digest(
            value.get("effectAuthorizationReceiptSha256"),
            "effectAuthorizationReceiptSha256",
        )
        _positive_int(value.get("operationExpiresAtUnix"), "operationExpiresAtUnix")
        _digest(
            value.get("recoveryPublicationIntentSha256"),
            "recoveryPublicationIntentSha256",
            nullable=True,
        )
    elif action == "EXECUTE":
        native_result = value.get("nativeResult")
        if (
            not isinstance(native_result, dict)
            or _sha(_canonical(native_result)) != value.get("resultSha256")
        ):
            raise ControllerProtocolError(
                "EXECUTE response native result digest is invalid"
            )
    return value


def open_operation(operation: str, binding: Mapping[str, Any]) -> tuple[ControllerConfig, dict[str, Any]]:
    config = load_controller_config()
    if operation not in ALLOWED_OPERATIONS:
        raise ControllerProtocolError("operation is outside the fixed controller set")
    now = int(time.time())
    request = {
        "operationId": hashlib.sha256(_canonical({"operation": operation, "binding": dict(binding)})).hexdigest(),
        "clientNonce": secrets.token_hex(32),
        "operation": operation,
        "repositoryLocatorSha256": binding["repositoryLocatorSha256"],
        "rootSetSha256": config.root_set_sha256,
        "requestSha256": binding["requestSha256"],
        "runtimeManifestSha256": config.runtime_manifest_sha256,
        "moduleSha256": config.module_sha256,
        "schemaSha256": config.schema_sha256,
        "configEpoch": config.config_epoch,
        "keyEpoch": config.key_epoch,
        "issuedAtUnix": now,
        "expiresAtUnix": now + MAX_OPERATION_SECONDS,
    }
    response = _request("OPEN", request, config)
    if (
        response.get("operationId") != request["operationId"]
        or response.get("state") not in {"accepted", "completed"}
        or response.get("status") != (
            "completed" if response.get("state") == "completed" else "accepted"
        )
    ):
        raise ControllerProtocolError("OPEN response changed the exact operation state")
    return config, response


def step_operation(config: ControllerConfig, session: Mapping[str, Any], target_state: str, *, transaction_intent_sha256: str | None, result_sha256: str | None) -> dict[str, Any]:
    if target_state not in _STATES[1:]:
        raise ControllerProtocolError("invalid controller STEP target")
    request = {
        "operationId": session["operationId"],
        "sessionNonce": session["sessionNonce"],
        "stepNonce": secrets.token_hex(32),
        "predecessorReceiptSha256": session["receiptSha256"],
        "targetState": target_state,
        "transactionIntentSha256": transaction_intent_sha256,
        "resultSha256": result_sha256,
    }
    response = _request("STEP", request, config)
    if (
        response.get("operationId") != session.get("operationId")
        or response.get("sessionNonce") != session.get("sessionNonce")
        or response.get("state") != target_state
        or response.get("status")
        != ("completed" if target_state == "completed" else "accepted")
        or response.get("resultSha256") != result_sha256
    ):
        raise ControllerProtocolError("STEP response changed the exact requested successor")
    return response


def execute_native_effect_v27(
    config: ControllerConfig,
    session: Mapping[str, Any],
    authorization_record_sha256: str,
) -> dict[str, Any]:
    request = {
        "operationId": session["operationId"],
        "sessionNonce": session["sessionNonce"],
        "executionNonce": secrets.token_hex(32),
        "predecessorReceiptSha256": session["receiptSha256"],
        "authorizationRecordSha256": authorization_record_sha256,
    }
    response = _request("EXECUTE", request, config)
    if (
        response.get("operationId") != session.get("operationId")
        or response.get("sessionNonce") != session.get("sessionNonce")
        or response.get("state") != "effect-authorized"
        or response.get("status") != "executed"
        or not isinstance(response.get("nativeResult"), dict)
    ):
        raise ControllerProtocolError(
            "EXECUTE response changed the exact native effect lineage"
        )
    return dict(response["nativeResult"])


def validate_stored_receipt(config: ControllerConfig, *, operation_id: str, stored_receipt_sha256: str, expected_state: str, expected_result_sha256: str | None) -> dict[str, Any]:
    request = {
        "operationId": operation_id,
        "validationNonce": secrets.token_hex(32),
        "storedReceiptSha256": stored_receipt_sha256,
        "expectedState": expected_state,
        "expectedResultSha256": expected_result_sha256,
    }
    response = _request("VALIDATE", request, config)
    if (
        response.get("operationId") != operation_id
        or response.get("state") != expected_state
        or response.get("status") != "validated"
        or response.get("resultSha256") != expected_result_sha256
    ):
        raise ControllerProtocolError(
            "VALIDATE response changed the exact stored controller result"
        )
    return response


def recover_publication_operation(
    config: ControllerConfig,
    operation: str,
    binding: Mapping[str, Any],
    *,
    phase: str,
    prior: Mapping[str, Any] | None = None,
    publication_intent_sha256: str | None = None,
    recovery_result_sha256: str | None = None,
) -> dict[str, Any]:
    """Inspect/authorize/complete only an exact publication suffix recovery."""

    if operation not in ALLOWED_OPERATIONS:
        raise ControllerProtocolError("recovery operation is outside the fixed set")
    if phase not in {"inspect", "authorize-publication", "complete-publication"}:
        raise ControllerProtocolError("unknown publication recovery phase")
    request_digest = _digest(binding.get("requestSha256"), "recovery requestSha256")
    repository = _digest(
        binding.get("repositoryLocatorSha256"),
        "recovery repositoryLocatorSha256",
    )
    assert request_digest is not None and repository is not None
    operation_id = hashlib.sha256(
        _canonical(
            {
                "operation": operation,
                "binding": {
                    "repositoryLocatorSha256": repository,
                    "requestSha256": request_digest,
                },
            }
        )
    ).hexdigest()
    request = {
        "operationId": operation_id,
        "recoveryNonce": secrets.token_hex(32),
        "recoveryPhase": phase,
        "operation": operation,
        "repositoryLocatorSha256": repository,
        "rootSetSha256": config.root_set_sha256,
        "requestSha256": request_digest,
        "transactionIntentSha256": request_digest,
        "runtimeManifestSha256": config.runtime_manifest_sha256,
        "moduleSha256": config.module_sha256,
        "schemaSha256": config.schema_sha256,
        "configEpoch": config.config_epoch,
        "keyEpoch": config.key_epoch,
        "sessionNonce": None if prior is None else prior.get("sessionNonce"),
        "predecessorReceiptSha256": (
            None if prior is None else prior.get("receiptSha256")
        ),
        "effectAuthorizationReceiptSha256": (
            None
            if prior is None
            else prior.get("effectAuthorizationReceiptSha256")
        ),
        "publicationIntentSha256": publication_intent_sha256,
        "recoveryResultSha256": recovery_result_sha256,
    }
    response = _request("RECOVER", request, config)
    if (
        response.get("operationId") != operation_id
        or response.get("sessionNonce") is None
        or response.get("effectAuthorizationReceiptSha256") is None
    ):
        raise ControllerProtocolError("RECOVER response changed operation authority")
    expected_state = {
        "inspect": {
            "effect-authorized",
            "publication-recovery-authorized",
            "publication-recovered",
        },
        "authorize-publication": {"publication-recovery-authorized"},
        "complete-publication": {"publication-recovered"},
    }[phase]
    if response.get("state") not in expected_state:
        raise ControllerProtocolError("RECOVER response changed the requested recovery state")
    return response


# Controller implementation.  It deliberately shares no client override path.
def _sign_response(key: bytes, action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    body = {**dict(payload), "schemaVersion": 1, "protocol": PROTOCOL, "action": action, "provenanceDomain": PRODUCTION_PROVENANCE}
    material = _canonical(body)
    auth = "hmac-sha256:" + hmac.new(key, (PROTOCOL + "/" + action + "\0").encode() + material, hashlib.sha256).hexdigest()
    result = {**body, "controllerHmac": auth}
    result["receiptSha256"] = _sha(_canonical(result))
    return result


def _state_file(operation_id: str) -> Path:
    if not _OPERATION_ID.fullmatch(operation_id):
        raise ControllerProtocolError("invalid operationId")
    return STATE_ROOT / f"{operation_id}.json"


def _read_state_bytes(path: Path, *, missing_ok: bool = False) -> bytes | None:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ControllerProtocolError("controller operation state does not exist")
    except OSError as exc:
        raise ControllerProtocolError(f"cannot inspect controller state: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o077
        or before.st_size > MAX_MESSAGE_BYTES
    ):
        raise ControllerProtocolError("controller operation state metadata is unsafe")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_mode, before.st_size
            ):
                raise ControllerProtocolError("controller state changed before open")
            data = os.read(descriptor, MAX_MESSAGE_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot read controller state: {exc}") from exc
    if (
        len(data) > MAX_MESSAGE_BYTES
        or (after.st_dev, after.st_ino, after.st_mode, after.st_size)
        != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size)
    ):
        raise ControllerProtocolError("controller state changed during read")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("controller state contains malformed JSON") from exc
    if not isinstance(value, dict) or _canonical(value) != data:
        raise ControllerProtocolError("controller state is not exact canonical JSON")
    return data


def _load_state(
    path: Path,
    key: bytes,
    *,
    missing_ok: bool = False,
) -> tuple[bytes, dict[str, Any]] | None:
    raw = _read_state_bytes(path, missing_ok=missing_ok)
    if raw is None:
        return None
    value = json.loads(raw)
    state = value.get("state")
    fields = {
        "openBindingSha256",
        "expiresAtUnix",
        "operation",
        "repositoryLocatorSha256",
        "requestSha256",
        "operatorGeneration",
        "state",
        "usedNonces",
        "response",
    }
    if state != "accepted":
        fields.add("transactionIntentSha256")
    if state in {
        "effect-authorized",
        "result-stored",
        "completed",
        "publication-recovery-authorized",
        "publication-recovered",
    }:
        fields.add("effectAuthorizationReceiptSha256")
        fields.update(
            {
                "nativeEffectAuthorizationRecordSha256",
                "nativeEffectPlanSha256",
                "nativeEffectOperatorGeneration",
                "nativeEffectResultSha256",
                "nativeEffectResult",
            }
        )
    if state in _RECOVERY_STATES:
        fields.add("recoveryPublicationIntentSha256")
    data = _closed_mapping(value, fields, "controller durable state")
    _digest(data["openBindingSha256"], "state openBindingSha256")
    if data["operation"] not in ALLOWED_OPERATIONS:
        raise ControllerProtocolError("controller durable operation is invalid")
    _digest(data["repositoryLocatorSha256"], "state repositoryLocatorSha256")
    _digest(data["requestSha256"], "state requestSha256")
    if type(data["operatorGeneration"]) is not int or data["operatorGeneration"] < 0:
        raise ControllerProtocolError("controller durable operator generation is invalid")
    _positive_int(data["expiresAtUnix"], "state expiresAtUnix")
    if state not in _STATES:
        raise ControllerProtocolError("controller durable state has an unknown state")
    if state != "accepted":
        _digest(data["transactionIntentSha256"], "state transactionIntentSha256")
    if "effectAuthorizationReceiptSha256" in fields:
        _digest(
            data["effectAuthorizationReceiptSha256"],
            "state effectAuthorizationReceiptSha256",
        )
        _digest(
            data["nativeEffectAuthorizationRecordSha256"],
            "state nativeEffectAuthorizationRecordSha256",
            nullable=True,
        )
        _digest(
            data["nativeEffectPlanSha256"],
            "state nativeEffectPlanSha256",
            nullable=True,
        )
        _digest(
            data["nativeEffectResultSha256"],
            "state nativeEffectResultSha256",
            nullable=True,
        )
        native_generation = data["nativeEffectOperatorGeneration"]
        if native_generation is not None and (
            type(native_generation) is not int or native_generation < 0
        ):
            raise ControllerProtocolError("native effect operator generation is invalid")
        if (data["nativeEffectPlanSha256"] is None) != (
            data["nativeEffectAuthorizationRecordSha256"] is None
        ) or (data["nativeEffectPlanSha256"] is None) != (
            native_generation is None
        ):
            raise ControllerProtocolError(
                "controller native effect authorization binding is incomplete"
            )
        native_result = data["nativeEffectResult"]
        if (native_result is None) != (data["nativeEffectResultSha256"] is None):
            raise ControllerProtocolError("controller native effect result binding is incomplete")
        if native_result is not None and (
            not isinstance(native_result, dict)
            or _sha(_canonical(native_result)) != data["nativeEffectResultSha256"]
        ):
            raise ControllerProtocolError("controller native effect result digest changed")
    if state in _RECOVERY_STATES:
        _digest(
            data["recoveryPublicationIntentSha256"],
            "state recoveryPublicationIntentSha256",
        )
    nonces = data["usedNonces"]
    if (
        not isinstance(nonces, list)
        or not nonces
        or len(nonces) > 4096
        or len(nonces) != len(set(nonces))
        or any(not isinstance(nonce, str) or not _NONCE.fullmatch(nonce) for nonce in nonces)
    ):
        raise ControllerProtocolError("controller durable state has an invalid nonce set")
    response_value = data["response"]
    response_action = (
        response_value.get("action") if isinstance(response_value, dict) else None
    )
    response_fields = (
        _RESPONSE_FIELDS | _RECOVERY_RESPONSE_EXTRA_FIELDS
        if response_action == "RECOVER"
        else _RESPONSE_FIELDS
    )
    response = _closed_mapping(
        response_value, response_fields, "stored controller response"
    )
    if (
        response["schemaVersion"] != 1
        or response["protocol"] != PROTOCOL
        or response["provenanceDomain"] != PRODUCTION_PROVENANCE
        or response["action"] not in {"OPEN", "STEP", "RECOVER"}
        or response["state"] != state
        or response["operationId"] != path.stem
        or not isinstance(response["sessionNonce"], str)
        or not _NONCE.fullmatch(response["sessionNonce"])
        or not isinstance(response["controllerHmac"], str)
        or not _HMAC.fullmatch(response["controllerHmac"])
    ):
        raise ControllerProtocolError("stored controller response identity is invalid")
    _digest(response["requestSha256"], "stored response requestSha256")
    _digest(response["receiptSha256"], "stored response receiptSha256")
    _digest(response["resultSha256"], "stored response resultSha256", nullable=True)
    expected_status = (
        "completed"
        if state == "completed"
        else "recovered"
        if state == "publication-recovered"
        else "accepted"
    )
    if response["status"] != expected_status:
        raise ControllerProtocolError("stored controller response status is invalid")
    if (state in {
        "accepted",
        "intent-bound",
        "effect-authorized",
        "publication-recovery-authorized",
    }) != (
        response["resultSha256"] is None
    ):
        raise ControllerProtocolError("stored controller result/state relation is invalid")
    if response["action"] == "RECOVER":
        if (
            response["effectAuthorizationReceiptSha256"]
            != data.get("effectAuthorizationReceiptSha256")
            or response["operationExpiresAtUnix"] != data["expiresAtUnix"]
            or response["recoveryPublicationIntentSha256"]
            != data.get("recoveryPublicationIntentSha256")
        ):
            raise ControllerProtocolError(
                "stored recovery response does not bind durable recovery authority"
            )
    receipt_material = dict(response)
    receipt_sha256 = receipt_material.pop("receiptSha256")
    if receipt_sha256 != _sha(_canonical(receipt_material)):
        raise ControllerProtocolError("stored controller response receipt is invalid")
    hmac_material = dict(receipt_material)
    observed_hmac = hmac_material.pop("controllerHmac")
    expected_hmac = "hmac-sha256:" + hmac.new(
        key,
        (PROTOCOL + "/" + response["action"] + "\0").encode()
        + _canonical(hmac_material),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(observed_hmac, expected_hmac):
        raise ControllerProtocolError("stored controller response HMAC is invalid")
    return raw, data


def _write_state(path: Path, value: Mapping[str, Any], expected: bytes | None) -> None:
    current = _read_state_bytes(path, missing_ok=True)
    if current != expected:
        raise ControllerProtocolError("controller durable state predecessor changed")
    encoded = _canonical(dict(value))
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory = os.open(STATE_ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _protected_record_v27(
    config: ControllerConfig,
    repository_locator_sha256: str,
    relative: tuple[str, ...],
    *,
    kind: str,
    expected_record_sha256: str | None = None,
) -> dict[str, Any]:
    """Reopen and authenticate one broker-published protected record.

    This is controller-side validation, not caller attestation.  The worker
    never receives the protected root or record HMAC key.
    """

    repository = _digest(repository_locator_sha256, "protected repository")
    key = _read_root_owned(
        config.record_hmac_key_path,
        "protected runtime record HMAC key",
        max_bytes=4096,
    )
    if not 32 <= len(key) <= 4096:
        raise ControllerProtocolError("protected runtime record HMAC key is invalid")
    if any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", item) is None for item in relative):
        raise ControllerProtocolError("protected record path component is invalid")
    path = (
        config.protected_root
        / "beads-authority-v1"
        / repository.removeprefix("sha256:")
    ).joinpath(*relative)
    raw = _read_root_owned(
        path,
        f"protected {kind} record",
        max_bytes=MAX_MESSAGE_BYTES,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError(f"protected {kind} record is malformed") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"payload", "auth"}
        or not isinstance(value["payload"], dict)
        or _canonical(value) != raw
    ):
        raise ControllerProtocolError(f"protected {kind} record is not canonical")
    body = value["payload"]
    if body.get("kind") != kind or body.get("schemaVersion") != 1:
        raise ControllerProtocolError(f"protected {kind} record kind changed")
    body_raw = _canonical(body)
    record_sha256 = _sha(body_raw)
    if expected_record_sha256 is not None and record_sha256 != expected_record_sha256:
        raise ControllerProtocolError(f"protected {kind} record digest changed")
    expected_auth = "hmac-sha256:" + hmac.new(
        key,
        f"startup-factory/{kind}/v1\0".encode("ascii") + body_raw,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(value["auth"]), expected_auth):
        raise ControllerProtocolError(f"protected {kind} record authentication failed")
    if body.get("repositoryLocatorSha256") != repository:
        raise ControllerProtocolError(f"protected {kind} repository binding changed")
    return {"payload": body, "recordSha256": record_sha256, "rawSha256": _sha(raw)}


def _closed_effect_text_v27(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ControllerProtocolError(f"protected {label} is not a safe fixed argv value")
    return value


def _prepared_expected_bindings_v27(evidence: Mapping[str, Any]) -> Any:
    """Decode the separately authenticated typed expected-binding evidence.

    The candidate prepared payload is deliberately not an input.  In
    particular, ``payload_sha256`` must already be present in the protected
    finish evidence and cannot be minted by hashing the candidate here.
    """

    try:
        from bin.beads_contract import PreparedBeadsStoreExpectedBindingsV1

        return PreparedBeadsStoreExpectedBindingsV1(
            **dict(evidence),
        )
    except (ImportError, KeyError, TypeError, ValueError) as exc:
        raise ControllerProtocolError(
            "protected typed prepared expected bindings are invalid"
        ) from exc


def _derive_protected_read_back_plan_v27(
    config: ControllerConfig,
    repository: str,
    candidate: Mapping[str, Any],
    target_id: str,
) -> dict[str, Any]:
    pointer_digest = _digest(
        candidate.get("preparationPointerRecordSha256"),
        "protected preparation pointer",
    )
    pointer = _protected_record_v27(
        config,
        repository,
        (
            "preparation-current",
            "history",
            pointer_digest.removeprefix("sha256:") + ".json",
        ),
        kind="beads-preparation-current",
        expected_record_sha256=pointer_digest,
    )
    result_digest = _digest(
        pointer["payload"].get("resultRecordSha256"),
        "protected preparation result",
    )
    result = _protected_record_v27(
        config,
        repository,
        (
            "preparation-results",
            "history",
            result_digest.removeprefix("sha256:") + ".json",
        ),
        kind="beads-preparation-result",
        expected_record_sha256=result_digest,
    )
    if pointer["payload"].get("leaseRecordSha256") != result["payload"].get(
        "leaseRecordSha256"
    ):
        raise ControllerProtocolError("protected preparation pointer/result lease changed")
    lease_digest = _digest(
        result["payload"].get("leaseRecordSha256"), "protected preparation lease"
    )
    lease = _protected_record_v27(
        config,
        repository,
        (
            "preparation-leases",
            "history",
            lease_digest.removeprefix("sha256:") + ".json",
        ),
        kind="beads-preparation-lease",
        expected_record_sha256=lease_digest,
    )
    canonical_text = result["payload"].get("preparedPayloadCanonicalJson")
    if not isinstance(canonical_text, str):
        raise ControllerProtocolError("protected prepared payload text is absent")
    canonical = canonical_text.encode("utf-8")
    if (
        _sha(canonical)
        != result["payload"].get("preparedPayloadCanonicalSha256")
    ):
        raise ControllerProtocolError("protected prepared payload raw digest changed")
    try:
        payload = json.loads(canonical)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("protected prepared payload is malformed") from exc
    if not isinstance(payload, dict) or _canonical(payload) != canonical:
        raise ControllerProtocolError("protected prepared payload is noncanonical")
    if (
        payload.get("repositoryLocatorSha256") != repository
        or payload.get("databaseName") != candidate.get("databaseName")
        or payload.get("preparationMode") != lease["payload"].get("preparationMode")
        or payload.get("executable", {}).get("sha256")
        != lease["payload"].get("executableSha256")
    ):
        raise ControllerProtocolError(
            "protected prepared payload differs from authority/lease bindings"
        )
    expected_text = result["payload"].get(
        "preparedExpectedBindingsCanonicalJson"
    )
    expected_raw_digest = result["payload"].get(
        "preparedExpectedBindingsCanonicalSha256"
    )
    if not isinstance(expected_text, str):
        raise ControllerProtocolError(
            "protected typed prepared expected bindings are absent"
        )
    expected_raw = expected_text.encode("utf-8")
    if _sha(expected_raw) != expected_raw_digest:
        raise ControllerProtocolError(
            "protected typed prepared expected-binding bytes changed"
        )
    try:
        expected_value = json.loads(expected_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError(
            "protected typed prepared expected bindings are malformed"
        ) from exc
    if not isinstance(expected_value, dict) or _canonical(expected_value) != expected_raw:
        raise ControllerProtocolError(
            "protected typed prepared expected bindings are noncanonical"
        )
    expected = _prepared_expected_bindings_v27(expected_value)
    try:
        verified = native_boundary_v27.verify_protected_read_back_candidate_v27(
            canonical,
            protected_raw_sha256=str(
                result["payload"]["preparedPayloadCanonicalSha256"]
            ),
            protected_expected_bindings=expected,
        )
    except native_boundary_v27.NativeBoundaryV27Error as exc:
        raise ControllerProtocolError(
            f"protected read-back candidate verification failed: {exc}"
        ) from exc
    executable_path = Path(
        _closed_effect_text_v27(lease["payload"].get("executablePath"), "executable path")
    )
    repository_path = Path(
        _closed_effect_text_v27(candidate.get("repositoryPath"), "repository path")
    )
    database_relative = payload.get("databaseRootRelative")
    if not isinstance(database_relative, str) or Path(database_relative).is_absolute():
        raise ControllerProtocolError("protected database relative path is invalid")
    database_path = repository_path / database_relative
    target_path = STATE_ROOT / f".read-back-target-{os.getpid()}-{secrets.token_hex(8)}"
    descriptors: list[int] = []
    try:
        descriptors.append(
            os.open(executable_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        )
        descriptors.append(
            os.open(
                database_path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        )
        target_fd = os.open(
            target_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        descriptors.append(target_fd)
        native_boundary_v27._write_all_v27(target_fd, (target_id + "\n").encode())
        os.fsync(target_fd)
        os.lseek(target_fd, 0, os.SEEK_SET)
        derived = native_boundary_v27.derive_descriptor_pinned_read_back_plan_v27(
            verified,
            binary_fd=descriptors[0],
            database_fd=descriptors[1],
            target_id_fd=target_fd,
        )
        return native_boundary_v27.descriptor_pinned_read_back_plan_payload_v27(
            derived
        )
    except (OSError, native_boundary_v27.NativeBoundaryV27Error) as exc:
        raise ControllerProtocolError(
            f"cannot derive descriptor-pinned protected read-back plan: {exc}"
        ) from exc
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.unlink(target_path)
        except FileNotFoundError:
            pass


def _derive_protected_effect_authority_v27(
    config: ControllerConfig,
    prior: Mapping[str, Any],
    authorization_record_sha256: str,
    manifest: native_boundary_v27.NativeBoundaryManifestV27,
    operation_id: str,
    *,
    controller_key: bytes | None = None,
    operator_generation: int = 0,
) -> tuple[dict[str, Any], int, int | None]:
    """Derive the only native plan from authenticated protected current state."""

    authorization_digest = _digest(
        authorization_record_sha256, "EXECUTE authorizationRecordSha256"
    )
    repository = _digest(
        prior.get("repositoryLocatorSha256"), "controller repository binding"
    )
    operation = prior.get("operation")
    authority = _protected_record_v27(
        config,
        repository,
        ("authority", "current.json"),
        kind="beads-authority-epoch-state",
    )
    authority_body = authority["payload"]
    candidate = authority_body.get("candidate")

    operation_class: str
    argv: list[str]
    repository_path: str
    read_back_target_id: str | None = None
    preparation_commands: list[list[str]] | None = None
    stage_start = 1
    stage_end: int | None = None
    if operation in {"advance_atomic_claim_v1", "record_atomic_claim_receipt_v1"}:
        if not isinstance(candidate, dict):
            raise ControllerProtocolError("protected authority has no repository candidate")
        lease = _protected_record_v27(
            config,
            repository,
            (
                "claims",
                "history",
                authorization_digest.removeprefix("sha256:") + ".json",
            ),
            kind="atomic-claim-lease",
            expected_record_sha256=authorization_digest,
        )["payload"]
        if lease.get("activeAuthorityRecordSha256") != authority["recordSha256"]:
            raise ControllerProtocolError("claim authority is not the authenticated current")
        if authority_body.get("authorityState") != "active":
            raise ControllerProtocolError("claim authority is not active")
        task_id = _closed_effect_text_v27(lease.get("taskId"), "task id")
        read_back_target_id = task_id
        repository_path = _closed_effect_text_v27(
            candidate.get("repositoryPath"), "repository path"
        )
        if operation == "advance_atomic_claim_v1":
            if lease.get("claimState") != "prepared":
                raise ControllerProtocolError("claim CAS requires a prepared lease")
            expected_revision = _closed_effect_text_v27(
                lease.get("expectedRevision"), "expected revision"
            )
            operation_class = "claim-cas"
            argv = [
                "/usr/local/bin/bd",
                "update",
                task_id,
                "--claim",
                "--expected-revision",
                expected_revision,
                "--json",
            ]
        else:
            if lease.get("claimState") != "claimed":
                raise ControllerProtocolError("claim receipt comment requires a claimed lease")
            receipt_body = _canonical(
                {
                    "claimLeaseRecordSha256": authorization_digest,
                    "taskId": task_id,
                }
            ).decode("utf-8")
            operation_class = "receipt-comment"
            argv = [
                "/usr/local/bin/bd",
                "comments",
                "add",
                task_id,
                "--body",
                receipt_body,
                "--json",
            ]
    elif operation in {"finish_beads_mutation_v1", "advance_beads_preparation_v1"}:
        intent = _protected_record_v27(
            config,
            repository,
            (
                "mutation-intents",
                "history",
                authorization_digest.removeprefix("sha256:") + ".json",
            ),
            kind="beads-mutation-intent",
            expected_record_sha256=authorization_digest,
        )["payload"]
        raw_argv = intent.get("argv")
        if (
            not isinstance(raw_argv, list)
            or not raw_argv
            or any(not isinstance(item, str) for item in raw_argv)
        ):
            raise ControllerProtocolError("protected mutation intent argv is invalid")
        argv = ["/usr/local/bin/bd", *[
            _closed_effect_text_v27(item, "mutation argv") for item in raw_argv[1:]
        ]]
        if intent.get("mutationClass") == "ordinary":
            if not isinstance(candidate, dict):
                raise ControllerProtocolError(
                    "protected authority has no repository candidate"
                )
            if (
                authority_body.get("authorityState") != "active"
                or intent.get("activeAuthorityRecordSha256")
                != authority["recordSha256"]
            ):
                raise ControllerProtocolError("ordinary mutation authority is stale")
            operation_class = "ordinary"
            repository_path = _closed_effect_text_v27(
                candidate.get("repositoryPath"), "repository path"
            )
            if len(argv) >= 3 and argv[1] == "update":
                read_back_target_id = _closed_effect_text_v27(
                    argv[2], "ordinary mutation target id"
                )
            elif len(argv) >= 4 and argv[1:3] == ["comments", "add"]:
                read_back_target_id = _closed_effect_text_v27(
                    argv[3], "ordinary mutation target id"
                )
            else:
                raise ControllerProtocolError(
                    "ordinary mutation has no pre-authorized exact read-back target"
                )
        elif intent.get("mutationClass") == "preparation":
            lease_digest = _digest(
                intent.get("preparationLeaseRecordSha256"),
                "preparation lease record",
            )
            lease = _protected_record_v27(
                config,
                repository,
                (
                    "preparation-leases",
                    "history",
                    lease_digest.removeprefix("sha256:") + ".json",
                ),
                kind="beads-preparation-lease",
                expected_record_sha256=lease_digest,
            )["payload"]
            if authority_body.get("authorityState") != "revoked":
                raise ControllerProtocolError("preparation requires revoked authority")
            if controller_key is None or not 32 <= len(controller_key) <= 4096:
                raise ControllerProtocolError(
                    "preparation sequence operation requires the controller HMAC key"
                )
            command_digest = _digest(
                intent.get("preparationCommandIntentRecordSha256"),
                "preparation command intent",
            )
            command = _protected_record_v27(
                config,
                repository,
                (
                    "preparation-commands",
                    "history",
                    command_digest.removeprefix("sha256:") + ".json",
                ),
                kind="beads-preparation-command-intent",
                expected_record_sha256=command_digest,
            )["payload"]
            if command.get("leaseRecordSha256") != lease_digest:
                raise ControllerProtocolError(
                    "preparation command does not bind its exact lease"
                )
            sequence_fields = {
                "repositoryLocatorSha256": repository,
                "preparationSequenceSha256": _digest(
                    lease.get("preparationSequenceSha256"),
                    "preparation sequence",
                ),
                "authorizationRecordSha256": _digest(
                    lease.get("authorizationRecordSha256"),
                    "preparation authorization",
                ),
                "leaseTransactionIntentSha256": _digest(
                    lease.get("transactionIntentSha256"),
                    "preparation lease transaction",
                ),
                "revokedAuthorityRecordSha256": _digest(
                    lease.get("revokedAuthorityRecordSha256"),
                    "preparation revoked current",
                ),
                "operatorGeneration": operator_generation,
            }
            operation_id = hmac.new(
                controller_key,
                b"startup-factory/beads/v27/preparation-sequence-operation\0"
                + _canonical(sequence_fields),
                hashlib.sha256,
            ).hexdigest()
            mode = lease.get("preparationMode")
            if mode == "create":
                operation_class = "create-preparation"
                stage_path = Path(
                    _closed_effect_text_v27(
                        lease.get("createStageDatabasePath"), "create-stage path"
                    )
                )
                repository_path = str(stage_path.parent)
                database = f"/workspace/{stage_path.name}"
                config_value = _closed_effect_text_v27(
                    lease.get("statusConfigValue"), "status config value"
                )
                executable = _closed_effect_text_v27(
                    lease.get("executablePath"), "preparation executable path"
                )
                protected_commands = [
                    [executable, "version", "--json"],
                    [executable, "--db", str(stage_path), "--json", "--sandbox", "init"],
                    [
                        executable, "--db", str(stage_path), "--json", "--sandbox",
                        "config", "set", "status.custom", config_value,
                    ],
                    [
                        executable, "--db", str(stage_path), "--json", "--sandbox",
                        "config", "list",
                    ],
                ]
                preparation_commands = [
                    ["/usr/local/bin/bd", "version", "--json"],
                    [
                        "/usr/local/bin/bd", "--db", database, "--json",
                        "--sandbox", "init",
                    ],
                    [
                        "/usr/local/bin/bd", "--db", database, "--json",
                        "--sandbox", "config", "set", "status.custom",
                        config_value,
                    ],
                    [
                        "/usr/local/bin/bd", "--db", database, "--json",
                        "--sandbox", "config", "list",
                    ],
                ]
                ordinal = command.get("commandOrdinal")
                if type(ordinal) is not int or not 0 <= ordinal <= 3:
                    raise ControllerProtocolError(
                        "create preparation command ordinal is invalid"
                    )
                stage_start = ordinal * 13 + 1
                stage_end = stage_start + 12
                expected_kind = (
                    "binary-proof", "initialize", "status-config-write",
                    "status-config-readback",
                )[ordinal]
            elif mode == "reattest":
                operation_class = "reattest-preparation"
                repository_path = _closed_effect_text_v27(
                    lease.get("repositoryPath"), "repository path"
                )
                selector = Path(
                    _closed_effect_text_v27(
                        lease.get("installedSelectorPath"), "installed selector"
                    )
                )
                try:
                    relative_selector = selector.relative_to(Path(repository_path))
                except ValueError as exc:
                    raise ControllerProtocolError(
                        "reattest selector is outside its protected repository"
                    ) from exc
                preparation_commands = [[
                    "/usr/local/bin/bd", "--db",
                    "/workspace/" + relative_selector.as_posix(), "--json",
                    "--sandbox", "config", "list",
                ]]
                protected_commands = [[
                    _closed_effect_text_v27(
                        lease.get("executablePath"), "preparation executable path"
                    ),
                    "--db", str(selector), "--json", "--sandbox", "config", "list",
                ]]
                if command.get("commandOrdinal") != 0:
                    raise ControllerProtocolError(
                        "reattest preparation command ordinal is invalid"
                    )
                stage_start, stage_end = 1, 13
                expected_kind = "status-config-readback"
            else:
                raise ControllerProtocolError("preparation mode is invalid")
            ordinal = int(command["commandOrdinal"])
            command_argv = command.get("argv")
            if (
                command.get("commandKind") != expected_kind
                or command_argv != protected_commands[ordinal]
                or intent.get("argv") != command_argv
                or command.get("argvSha256") != _sha(_canonical(command_argv))
                or intent.get("argvSha256") != command.get("argvSha256")
            ):
                raise ControllerProtocolError(
                    "preparation command differs from its exact protected sequence row"
                )
            argv = list(preparation_commands[0])
        else:
            raise ControllerProtocolError("protected mutation class is invalid")
    elif operation == "finish_beads_preparation_v1":
        lease = _protected_record_v27(
            config,
            repository,
            (
                "preparation-leases",
                "history",
                authorization_digest.removeprefix("sha256:") + ".json",
            ),
            kind="beads-preparation-lease",
            expected_record_sha256=authorization_digest,
        )["payload"]
        if (
            authority_body.get("authorityState") != "revoked"
            or lease.get("preparationState") != "commands-complete"
            or controller_key is None
            or not 32 <= len(controller_key) <= 4096
        ):
            raise ControllerProtocolError(
                "preparation finish does not bind a completed revoked sequence"
            )
        sequence_fields = {
            "repositoryLocatorSha256": repository,
            "preparationSequenceSha256": _digest(
                lease.get("preparationSequenceSha256"), "preparation sequence"
            ),
            "authorizationRecordSha256": _digest(
                lease.get("authorizationRecordSha256"), "preparation authorization"
            ),
            "leaseTransactionIntentSha256": _digest(
                lease.get("transactionIntentSha256"), "preparation lease transaction"
            ),
            "revokedAuthorityRecordSha256": _digest(
                lease.get("revokedAuthorityRecordSha256"),
                "preparation revoked current",
            ),
            "operatorGeneration": operator_generation,
        }
        operation_id = hmac.new(
            controller_key,
            b"startup-factory/beads/v27/preparation-sequence-operation\0"
            + _canonical(sequence_fields),
            hashlib.sha256,
        ).hexdigest()
        mode = lease.get("preparationMode")
        executable = _closed_effect_text_v27(
            lease.get("executablePath"), "preparation executable path"
        )
        if mode == "create":
            operation_class = "create-preparation"
            stage_path = Path(
                _closed_effect_text_v27(
                    lease.get("createStageDatabasePath"), "create-stage path"
                )
            )
            repository_path = str(stage_path.parent)
            database = f"/workspace/{stage_path.name}"
            config_value = _closed_effect_text_v27(
                lease.get("statusConfigValue"), "status config value"
            )
            preparation_commands = [
                ["/usr/local/bin/bd", "version", "--json"],
                [
                    "/usr/local/bin/bd", "--db", database, "--json",
                    "--sandbox", "init",
                ],
                [
                    "/usr/local/bin/bd", "--db", database, "--json",
                    "--sandbox", "config", "set", "status.custom", config_value,
                ],
                [
                    "/usr/local/bin/bd", "--db", database, "--json",
                    "--sandbox", "config", "list",
                ],
            ]
            stage_start, stage_end = 53, 63
        elif mode == "reattest":
            operation_class = "reattest-preparation"
            repository_path = _closed_effect_text_v27(
                lease.get("repositoryPath"), "repository path"
            )
            selector = Path(
                _closed_effect_text_v27(
                    lease.get("installedSelectorPath"), "installed selector"
                )
            )
            try:
                relative_selector = selector.relative_to(Path(repository_path))
            except ValueError as exc:
                raise ControllerProtocolError(
                    "reattest selector is outside its protected repository"
                ) from exc
            preparation_commands = [[
                "/usr/local/bin/bd", "--db",
                "/workspace/" + relative_selector.as_posix(), "--json",
                "--sandbox", "config", "list",
            ]]
            stage_start, stage_end = 14, 24
        else:
            raise ControllerProtocolError("preparation finish mode is invalid")
        argv = list(preparation_commands[0])
    else:
        raise ControllerProtocolError("operation has no native EXECUTE authority")
    read_back_plan = None
    if read_back_target_id is not None:
        assert isinstance(candidate, dict)
        read_back_plan = _derive_protected_read_back_plan_v27(
            config, repository, candidate, read_back_target_id
        )
    plan = native_boundary_v27.reference_supervised_effect_plan_v27(
        manifest,
        operation_id=operation_id,
        operation_class=operation_class,
        argv=argv,
        repository_path=repository_path,
        read_back_plan=read_back_plan,
        preparation_commands=preparation_commands,
        launch_core_sha256=_digest(
            prior.get("openBindingSha256"), "controller LaunchCore"
        ),
        operator_generation=operator_generation,
        config_epoch=config.config_epoch,
        key_epoch=config.key_epoch,
    )
    return plan, stage_start, stage_end


def _serve_packet(
    packet: bytes,
    peer_uid: int,
    config: ControllerConfig,
    key: bytes,
    *,
    operator_key: bytes | None = None,
    operator_state_path: Path = OPERATOR_STATE_PATH,
    supervisor_runner: Any = None,
    authority_loader: Any = None,
) -> bytes:
    if not config.beads_enabled:
        raise ControllerProtocolError("protected Beads boundary is disabled")
    operator_generation = 0
    if operator_key is not None:
        operator_state = verify_operator_lifecycle_v1(
            config,
            operator_key,
            state_path=operator_state_path,
            require_active=True,
        )
        operator_generation = int(operator_state["generation"])
    try:
        value = json.loads(packet)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("controller request contains malformed JSON") from exc
    data = _closed_mapping(value, _REQUEST_FIELDS, "controller request")
    if (
        _canonical(data) != packet
        or type(data["schemaVersion"]) is not int
        or data["schemaVersion"] != 1
        or not isinstance(data["protocol"], str)
        or data["protocol"] != PROTOCOL
    ):
        raise ControllerProtocolError("controller request is not exact canonical protocol v1")
    if peer_uid != config.broker_uid or peer_uid in {config.controller_uid, config.worker_uid}:
        raise ControllerProtocolError("request peer is not the distinct configured broker UID")
    action = _string(data["action"], "controller action")
    if action not in {"OPEN", "STEP", "VALIDATE", "RECOVER", "EXECUTE"}:
        raise ControllerProtocolError("unknown controller action")
    request = data["request"]
    request_sha = _sha(packet)
    if action == "OPEN":
        opened = _closed_mapping(request, _OPEN_FIELDS, "OPEN request")
        _operation_id(opened["operationId"])
        for field in ("repositoryLocatorSha256", "rootSetSha256", "requestSha256", "runtimeManifestSha256", "moduleSha256", "schemaSha256"):
            _digest(opened[field], field)
        operation = _string(opened["operation"], "OPEN operation")
        _positive_int(opened["configEpoch"], "OPEN configEpoch")
        _positive_int(opened["keyEpoch"], "OPEN keyEpoch")
        _positive_int(opened["issuedAtUnix"], "OPEN issuedAtUnix")
        _positive_int(opened["expiresAtUnix"], "OPEN expiresAtUnix")
        if operation not in ALLOWED_OPERATIONS or opened["rootSetSha256"] != config.root_set_sha256:
            raise ControllerProtocolError("OPEN request operation/root set mismatch")
        _nonce(opened["clientNonce"], "OPEN client nonce")
        if opened["operationId"] != hashlib.sha256(
            _canonical(
                {
                    "operation": opened["operation"],
                    "binding": {
                        "repositoryLocatorSha256": opened["repositoryLocatorSha256"],
                        "requestSha256": opened["requestSha256"],
                    },
                }
            )
        ).hexdigest():
            raise ControllerProtocolError("OPEN operationId does not bind the exact request")
        if (opened["runtimeManifestSha256"], opened["moduleSha256"], opened["schemaSha256"], opened["configEpoch"], opened["keyEpoch"]) != (
            config.runtime_manifest_sha256, config.module_sha256, config.schema_sha256, config.config_epoch, config.key_epoch
        ):
            raise ControllerProtocolError("OPEN request configured identity mismatch")
        now = int(time.time())
        if opened["issuedAtUnix"] > now + MAX_CLOCK_SKEW_SECONDS or opened["expiresAtUnix"] <= now or opened["expiresAtUnix"] - opened["issuedAtUnix"] > MAX_OPERATION_SECONDS:
            raise ControllerProtocolError("OPEN request lifetime is invalid")
        path = _state_file(opened["operationId"])
        loaded = _load_state(path, key, missing_ok=True)
        prior_bytes = None if loaded is None else loaded[0]
        open_binding = {
            key_name: opened[key_name]
            for key_name in sorted(
                _OPEN_FIELDS - {"clientNonce", "issuedAtUnix", "expiresAtUnix"}
            )
        }
        open_binding_sha256 = _sha(_canonical(open_binding))
        if prior_bytes is not None:
            assert loaded is not None
            prior = loaded[1]
            if prior.get("openBindingSha256") != open_binding_sha256:
                raise ControllerProtocolError("operationId was rebound to a different OPEN request")
            if opened["clientNonce"] in prior.get("usedNonces", []):
                raise ControllerProtocolError("OPEN nonce was already consumed")
            if prior.get("state") in {
                "effect-authorized",
                "result-stored",
                "publication-recovery-authorized",
                "publication-recovered",
            }:
                raise ControllerProtocolError("operation outcome is uncertain; inspect durable controller state")
            state = str(prior.get("state"))
            if state != "completed" and int(prior.get("expiresAtUnix", 0)) <= now:
                raise ControllerProtocolError("controller operation expired before recovery")
            response = _sign_response(key, action, {
                "status": "completed" if state == "completed" else "accepted",
                "state": state,
                "requestSha256": request_sha,
                "operationId": opened["operationId"],
                "sessionNonce": prior["response"]["sessionNonce"],
                "resultSha256": prior["response"].get("resultSha256"),
            })
            successor = {
                **prior,
                "usedNonces": [*prior["usedNonces"], opened["clientNonce"]],
                "response": response,
            }
            _write_state(path, successor, prior_bytes)
            return _canonical(response)
        session_nonce = secrets.token_hex(32)
        response = _sign_response(key, action, {
            "status": "accepted", "state": "accepted", "requestSha256": request_sha,
            "operationId": opened["operationId"], "sessionNonce": session_nonce,
            "resultSha256": None,
        })
        _write_state(path, {
            "openBindingSha256": open_binding_sha256,
            "expiresAtUnix": opened["expiresAtUnix"],
            "operation": operation,
            "repositoryLocatorSha256": opened["repositoryLocatorSha256"],
            "requestSha256": opened["requestSha256"],
            "operatorGeneration": operator_generation,
            "state": "accepted",
            "usedNonces": [opened["clientNonce"]],
            "response": response,
        }, None)
        return _canonical(response)
    if action == "STEP":
        step = _closed_mapping(request, _STEP_FIELDS, "STEP request")
        _operation_id(step["operationId"])
        _nonce(step["sessionNonce"], "STEP session nonce")
        _nonce(step["stepNonce"], "STEP nonce")
        _digest(step["predecessorReceiptSha256"], "STEP predecessorReceiptSha256")
        target = _string(step["targetState"], "STEP targetState")
        _digest(
            step["transactionIntentSha256"],
            "STEP transactionIntentSha256",
            nullable=True,
        )
        _digest(step["resultSha256"], "STEP resultSha256", nullable=True)
        path = _state_file(step["operationId"])
        loaded = _load_state(path, key)
        assert loaded is not None
        prior_bytes, prior = loaded
        if int(prior.get("expiresAtUnix", 0)) <= int(time.time()):
            raise ControllerProtocolError("controller operation expired before STEP")
        if step["stepNonce"] in prior.get("usedNonces", []):
            raise ControllerProtocolError("STEP nonce was already consumed")
        current = prior["state"]
        if (
            current not in _NORMAL_STATES
            or target not in _NORMAL_STATES
            or _NORMAL_STATES.index(target) != _NORMAL_STATES.index(current) + 1
        ):
            raise ControllerProtocolError("STEP is not the unique state successor")
        if step["sessionNonce"] != prior["response"]["sessionNonce"] or step["predecessorReceiptSha256"] != prior["response"]["receiptSha256"]:
            raise ControllerProtocolError("STEP predecessor/session mismatch")
        if target in {"intent-bound", "effect-authorized"}:
            _digest(step["transactionIntentSha256"], "transactionIntentSha256")
            if step["resultSha256"] is not None:
                raise ControllerProtocolError("pre-effect STEP cannot carry a result")
        if target in {"result-stored", "completed"}:
            _digest(step["resultSha256"], "resultSha256")
            if step["transactionIntentSha256"] is not None:
                raise ControllerProtocolError("result STEP cannot change the transaction intent")
        if target == "effect-authorized" and step["transactionIntentSha256"] != prior.get("transactionIntentSha256"):
            raise ControllerProtocolError("effect authorization changed the bound transaction intent")
        if target == "completed" and step["resultSha256"] != prior["response"].get("resultSha256"):
            raise ControllerProtocolError("completion changed the stored result")
        response = _sign_response(key, action, {
            "status": "completed" if target == "completed" else "accepted",
            "state": target, "requestSha256": request_sha,
            "operationId": step["operationId"], "sessionNonce": step["sessionNonce"],
            "resultSha256": step["resultSha256"],
        })
        successor = {
            **prior,
            "state": target,
            "usedNonces": [*prior["usedNonces"], step["stepNonce"]],
            "response": response,
        }
        if target == "intent-bound":
            successor["transactionIntentSha256"] = step["transactionIntentSha256"]
        if target == "effect-authorized":
            successor["effectAuthorizationReceiptSha256"] = response[
                "receiptSha256"
            ]
            successor["nativeEffectAuthorizationRecordSha256"] = None
            successor["nativeEffectPlanSha256"] = None
            successor["nativeEffectOperatorGeneration"] = None
            successor["nativeEffectResultSha256"] = None
            successor["nativeEffectResult"] = None
        _write_state(path, successor, prior_bytes)
        return _canonical(response)
    if action == "VALIDATE":
        validation = _closed_mapping(request, _VALIDATE_FIELDS, "VALIDATE request")
        _operation_id(validation["operationId"])
        _nonce(validation["validationNonce"], "VALIDATE nonce")
        expected_state = _string(
            validation["expectedState"], "VALIDATE expectedState"
        )
        if expected_state not in _STATES:
            raise ControllerProtocolError("VALIDATE state is invalid")
        _digest(validation["storedReceiptSha256"], "storedReceiptSha256")
        _digest(validation["expectedResultSha256"], "expectedResultSha256", nullable=True)
        path = _state_file(validation["operationId"])
        loaded = _load_state(path, key)
        assert loaded is not None
        prior_bytes, prior = loaded
        if prior.get("state") != "completed" and int(prior.get("expiresAtUnix", 0)) <= int(time.time()):
            raise ControllerProtocolError("controller operation expired before VALIDATE")
        if validation["validationNonce"] in prior.get("usedNonces", []):
            raise ControllerProtocolError("VALIDATE nonce was already consumed")
        if prior["state"] != validation["expectedState"] or prior["response"]["receiptSha256"] != validation["storedReceiptSha256"] or prior["response"].get("resultSha256") != validation["expectedResultSha256"]:
            raise ControllerProtocolError("stored receipt is not the current controller result")
        response = _sign_response(key, action, {
            "status": "validated", "state": prior["state"], "requestSha256": request_sha,
            "operationId": validation["operationId"], "sessionNonce": prior["response"]["sessionNonce"],
            "resultSha256": prior["response"].get("resultSha256"),
        })
        _write_state(path, {**prior, "usedNonces": [*prior["usedNonces"], validation["validationNonce"]]}, prior_bytes)
        return _canonical(response)
    if action == "EXECUTE":
        execution = _closed_mapping(request, _EXECUTE_FIELDS, "EXECUTE request")
        operation_id = _operation_id(execution["operationId"])
        _nonce(execution["sessionNonce"], "EXECUTE session nonce")
        _nonce(execution["executionNonce"], "EXECUTE nonce")
        _digest(
            execution["predecessorReceiptSha256"],
            "EXECUTE predecessorReceiptSha256",
        )
        authorization_digest = _digest(
            execution["authorizationRecordSha256"],
            "EXECUTE authorizationRecordSha256",
        )
        path = _state_file(operation_id)
        loaded = _load_state(path, key)
        assert loaded is not None
        prior_bytes, prior = loaded
        if (
            prior.get("state") != "effect-authorized"
            or execution["sessionNonce"] != prior["response"]["sessionNonce"]
            or execution["predecessorReceiptSha256"]
            != prior["response"]["receiptSha256"]
            or int(prior.get("expiresAtUnix", 0)) <= int(time.time())
            or int(prior.get("operatorGeneration", -1)) != operator_generation
        ):
            raise ControllerProtocolError(
                "EXECUTE does not bind the live effect-authorized predecessor"
            )
        if execution["executionNonce"] in prior.get("usedNonces", []):
            raise ControllerProtocolError("EXECUTE nonce was already consumed")
        manifest = _verify_installed_artifacts(config)
        _verify_native_platform_gate(manifest, run_probe=False)
        derive = (
            _derive_protected_effect_authority_v27
            if authority_loader is None
            else authority_loader
        )
        if authority_loader is None:
            derived_value = derive(
                config,
                prior,
                authorization_digest,
                manifest,
                operation_id,
                controller_key=key,
                operator_generation=operator_generation,
            )
        else:
            derived_value = derive(
                config, prior, authorization_digest, manifest, operation_id
            )
        if (
            isinstance(derived_value, tuple)
            and len(derived_value) == 3
        ):
            raw_plan, stage_start, stage_end = derived_value
        else:
            raw_plan, stage_start, stage_end = derived_value, 1, None
        plan = native_boundary_v27.validate_supervised_effect_plan_v27(
            raw_plan, manifest
        )
        if (
            plan["operationClass"]
            not in {"create-preparation", "reattest-preparation"}
            and plan["operationId"] != operation_id
        ):
            raise ControllerProtocolError(
                "EXECUTE plan operationId differs from the controller lineage"
            )
        stored_plan = prior.get("nativeEffectPlanSha256")
        if stored_plan is not None and stored_plan != plan["planSha256"]:
            raise ControllerProtocolError(
                "EXECUTE attempted to rebind a consumed native effect plan"
            )
        stored_authorization = prior.get("nativeEffectAuthorizationRecordSha256")
        if stored_authorization is not None and stored_authorization != authorization_digest:
            raise ControllerProtocolError(
                "EXECUTE attempted to rebind a consumed protected authorization"
            )
        if prior.get("nativeEffectResult") is not None:
            stored_native_result = prior["nativeEffectResult"]
            if (
                not isinstance(stored_native_result, dict)
                or _sha(_canonical(stored_native_result))
                != prior.get("nativeEffectResultSha256")
            ):
                raise ControllerProtocolError("stored native result authentication changed")
            response = _sign_response(
                key,
                action,
                {
                    "status": "executed",
                    "state": "effect-authorized",
                    "requestSha256": request_sha,
                    "operationId": operation_id,
                    "sessionNonce": execution["sessionNonce"],
                    "resultSha256": prior["nativeEffectResultSha256"],
                    "nativeResult": stored_native_result,
                },
            )
            _write_state(
                path,
                {
                    **prior,
                    "usedNonces": [*prior["usedNonces"], execution["executionNonce"]],
                },
                prior_bytes,
            )
            return _canonical(response)
        consumed = {
            **prior,
            "usedNonces": [*prior["usedNonces"], execution["executionNonce"]],
            "nativeEffectAuthorizationRecordSha256": authorization_digest,
            "nativeEffectPlanSha256": plan["planSha256"],
            "nativeEffectOperatorGeneration": operator_generation,
        }
        _write_state(path, consumed, prior_bytes)
        prior_bytes = _canonical(consumed)
        prior = consumed
        try:
            native_result = native_boundary_v27.execute_supervised_effect_v27(
                STATE_ROOT,
                key,
                manifest,
                plan,
                runner=(
                    native_boundary_v27.run_native_stage_action_v27
                    if supervisor_runner is None
                    else supervisor_runner
                ),
                start_location=stage_start,
                end_location=stage_end,
            )
        except native_boundary_v27.NativeBoundaryV27Error as exc:
            raise ControllerProtocolError(
                f"EXECUTE native supervisor boundary failed: {exc}"
            ) from exc
        result_digest = _sha(_canonical(native_result))
        stored_result = prior.get("nativeEffectResultSha256")
        if stored_result is not None and stored_result != result_digest:
            raise ControllerProtocolError(
                "EXECUTE native result changed after durable completion"
            )
        response = _sign_response(
            key,
            action,
            {
                "status": "executed",
                "state": "effect-authorized",
                "requestSha256": request_sha,
                "operationId": operation_id,
                "sessionNonce": execution["sessionNonce"],
                "resultSha256": result_digest,
                "nativeResult": native_result,
            },
        )
        _write_state(
            path,
            {
                **prior,
                "nativeEffectPlanSha256": plan["planSha256"],
                "nativeEffectResultSha256": result_digest,
                "nativeEffectResult": native_result,
            },
            prior_bytes,
        )
        return _canonical(response)
    recovery = _closed_mapping(request, _RECOVER_FIELDS, "RECOVER request")
    _operation_id(recovery["operationId"])
    _nonce(recovery["recoveryNonce"], "RECOVER nonce")
    phase = _string(recovery["recoveryPhase"], "RECOVER phase")
    operation = _string(recovery["operation"], "RECOVER operation")
    if phase not in {"inspect", "authorize-publication", "complete-publication"}:
        raise ControllerProtocolError("RECOVER phase is invalid")
    if operation not in ALLOWED_OPERATIONS:
        raise ControllerProtocolError("RECOVER operation is outside the fixed set")
    for field in (
        "repositoryLocatorSha256",
        "rootSetSha256",
        "requestSha256",
        "transactionIntentSha256",
        "runtimeManifestSha256",
        "moduleSha256",
        "schemaSha256",
    ):
        _digest(recovery[field], f"RECOVER {field}")
    _positive_int(recovery["configEpoch"], "RECOVER configEpoch")
    _positive_int(recovery["keyEpoch"], "RECOVER keyEpoch")
    _nonce(recovery["sessionNonce"], "RECOVER sessionNonce", nullable=True)
    _digest(
        recovery["predecessorReceiptSha256"],
        "RECOVER predecessorReceiptSha256",
        nullable=True,
    )
    _digest(
        recovery["effectAuthorizationReceiptSha256"],
        "RECOVER effectAuthorizationReceiptSha256",
        nullable=True,
    )
    _digest(
        recovery["publicationIntentSha256"],
        "RECOVER publicationIntentSha256",
        nullable=True,
    )
    _digest(
        recovery["recoveryResultSha256"],
        "RECOVER recoveryResultSha256",
        nullable=True,
    )
    expected_operation_id = hashlib.sha256(
        _canonical(
            {
                "operation": operation,
                "binding": {
                    "repositoryLocatorSha256": recovery[
                        "repositoryLocatorSha256"
                    ],
                    "requestSha256": recovery["requestSha256"],
                },
            }
        )
    ).hexdigest()
    if recovery["operationId"] != expected_operation_id:
        raise ControllerProtocolError("RECOVER operationId changed the exact request")
    if recovery["transactionIntentSha256"] != recovery["requestSha256"]:
        raise ControllerProtocolError("RECOVER changed the outer transaction intent")
    if (
        recovery["rootSetSha256"],
        recovery["runtimeManifestSha256"],
        recovery["moduleSha256"],
        recovery["schemaSha256"],
        recovery["configEpoch"],
        recovery["keyEpoch"],
    ) != (
        config.root_set_sha256,
        config.runtime_manifest_sha256,
        config.module_sha256,
        config.schema_sha256,
        config.config_epoch,
        config.key_epoch,
    ):
        raise ControllerProtocolError("RECOVER configured identity mismatch")
    path = _state_file(recovery["operationId"])
    loaded = _load_state(path, key)
    assert loaded is not None
    prior_bytes, prior = loaded
    if int(prior["expiresAtUnix"]) <= int(time.time()):
        raise ControllerProtocolError("controller operation expired before recovery")
    open_binding = {
        "operationId": recovery["operationId"],
        "operation": recovery["operation"],
        "repositoryLocatorSha256": recovery["repositoryLocatorSha256"],
        "rootSetSha256": recovery["rootSetSha256"],
        "requestSha256": recovery["requestSha256"],
        "runtimeManifestSha256": recovery["runtimeManifestSha256"],
        "moduleSha256": recovery["moduleSha256"],
        "schemaSha256": recovery["schemaSha256"],
        "configEpoch": recovery["configEpoch"],
        "keyEpoch": recovery["keyEpoch"],
    }
    if prior["openBindingSha256"] != _sha(_canonical(open_binding)):
        raise ControllerProtocolError("RECOVER changed the exact OPEN binding")
    if prior.get("transactionIntentSha256") != recovery["transactionIntentSha256"]:
        raise ControllerProtocolError("RECOVER transaction intent mismatch")
    if recovery["recoveryNonce"] in prior["usedNonces"]:
        raise ControllerProtocolError("RECOVER nonce was already consumed")
    if prior["state"] not in {
        "effect-authorized",
        "publication-recovery-authorized",
        "publication-recovered",
    }:
        raise ControllerProtocolError(
            "only an uncertain effect-authorized publication may recover"
        )
    current_response = prior["response"]
    if recovery["sessionNonce"] is not None and recovery["sessionNonce"] != current_response["sessionNonce"]:
        raise ControllerProtocolError("RECOVER session mismatch")
    if recovery["predecessorReceiptSha256"] is not None and recovery["predecessorReceiptSha256"] != current_response["receiptSha256"]:
        raise ControllerProtocolError("RECOVER predecessor mismatch")
    effect_receipt = prior["effectAuthorizationReceiptSha256"]
    if recovery["effectAuthorizationReceiptSha256"] is not None and recovery["effectAuthorizationReceiptSha256"] != effect_receipt:
        raise ControllerProtocolError("RECOVER changed effect authorization")
    publication_intent = prior.get("recoveryPublicationIntentSha256")
    if phase == "inspect":
        if recovery["publicationIntentSha256"] is not None or recovery["recoveryResultSha256"] is not None:
            raise ControllerProtocolError("RECOVER inspection cannot authorize mutation")
        target_state = prior["state"]
        result_digest = prior["response"].get("resultSha256")
    elif phase == "authorize-publication":
        if prior["state"] == "publication-recovered":
            raise ControllerProtocolError(
                "completed publication recovery cannot authorize another mutation"
            )
        requested_publication = recovery["publicationIntentSha256"]
        if requested_publication is None or recovery["recoveryResultSha256"] is not None:
            raise ControllerProtocolError("RECOVER authorization needs one publication intent")
        if publication_intent is not None and publication_intent != requested_publication:
            raise ControllerProtocolError("RECOVER attempted a different publication")
        publication_intent = requested_publication
        target_state = "publication-recovery-authorized"
        result_digest = None
    else:
        if (
            prior["state"] != "publication-recovery-authorized"
            or recovery["publicationIntentSha256"] != publication_intent
            or recovery["recoveryResultSha256"] is None
        ):
            raise ControllerProtocolError("RECOVER completion changed publication authority")
        target_state = "publication-recovered"
        result_digest = recovery["recoveryResultSha256"]
    response = _sign_response(
        key,
        action,
        {
            "status": "recovered" if target_state == "publication-recovered" else "accepted",
            "state": target_state,
            "requestSha256": request_sha,
            "operationId": recovery["operationId"],
            "sessionNonce": current_response["sessionNonce"],
            "resultSha256": result_digest,
            "effectAuthorizationReceiptSha256": effect_receipt,
            "operationExpiresAtUnix": prior["expiresAtUnix"],
            "recoveryPublicationIntentSha256": publication_intent,
        },
    )
    successor = {
        **prior,
        "state": target_state,
        "usedNonces": [*prior["usedNonces"], recovery["recoveryNonce"]],
        "response": response,
    }
    if publication_intent is not None:
        successor["recoveryPublicationIntentSha256"] = publication_intent
    _write_state(path, successor, prior_bytes)
    return _canonical(response)


def _serve_connection(
    connection: socket.socket,
    config: ControllerConfig,
    key: bytes,
    operator_key: bytes | None = None,
    supervisor_runner: Any = None,
) -> None:
    """Contain every untrusted connection failure and emit no error oracle."""

    try:
        try:
            # Bound both the first packet and the response write.  A broker
            # that connects and idles, stops reading, or supplies malformed
            # bytes is contained to this connection and cannot pin the
            # single-threaded controller indefinitely.
            connection.settimeout(CONNECTION_DEADLINE_SECONDS)
            _, peer_uid, _ = _peer_credentials(connection)
            packet = connection.recv(MAX_MESSAGE_BYTES + 1)
            if not packet or len(packet) > MAX_MESSAGE_BYTES:
                raise ControllerProtocolError(
                    "controller connection supplied an empty or oversized packet"
                )
            try:
                extra = connection.recv(
                    1,
                    getattr(socket, "MSG_PEEK", 0)
                    | getattr(socket, "MSG_DONTWAIT", 0),
                )
            except BlockingIOError:
                extra = b""
            if extra:
                raise ControllerProtocolError(
                    "controller connection supplied more than one request packet"
                )
            response = _serve_packet(
                packet,
                peer_uid,
                config,
                key,
                operator_key=operator_key,
                supervisor_runner=supervisor_runner,
            )
            connection.sendall(response)
        except Exception:
            # Protocol, type, parser, filesystem and unexpected per-client
            # failures are connection-scoped.  Invalid clients receive no
            # signed response and cannot terminate the accept loop.
            return
    finally:
        connection.close()


def _remove_stale_endpoint(config: ControllerConfig) -> None:
    """Remove only the fixed controller-owned socket from the root-only parent."""

    try:
        info = os.lstat(ENDPOINT_PATH)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ControllerProtocolError(
            f"cannot inspect fixed controller endpoint before bind: {exc}"
        ) from exc
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != config.controller_uid
        or info.st_gid != config.transport_gid
        or stat.S_IMODE(info.st_mode) != 0o660
    ):
        raise ControllerProtocolError(
            "fixed controller endpoint collision is not the exact stale controller socket"
        )
    try:
        os.unlink(ENDPOINT_PATH)
    except OSError as exc:
        raise ControllerProtocolError(
            f"cannot retire exact stale controller endpoint: {exc}"
        ) from exc


def _create_listener(config: ControllerConfig) -> socket.socket:
    """Bind as root, fix ownership/mode, then irreversibly become controller.

    The returned socket is deliberately not listening yet.  The dropped
    controller identity must first read its own private key and state root;
    only a completely successful preflight may expose listener readiness.
    """

    if os.geteuid() != 0:
        raise ControllerProtocolError(
            "controller service must start as root to create the fixed root-parented endpoint"
        )
    _validate_endpoint_parent(config)
    _remove_stale_endpoint(config)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        listener.bind(str(ENDPOINT_PATH))
        os.chown(
            ENDPOINT_PATH,
            config.controller_uid,
            config.transport_gid,
            follow_symlinks=False,
        )
        # The fixed parent is root-owned mode 0750 and only root can mutate
        # names within it, so this pathname cannot be substituted by either
        # controller, broker or worker while the root bootstrap runs.
        os.chmod(ENDPOINT_PATH, 0o660)

        # Drop before listen so every connecting client observes the distinct
        # configured controller UID through SO_PEERCRED.  The transport group
        # is the only supplementary and primary group retained.
        os.setgroups([config.transport_gid])
        os.setgid(config.transport_gid)
        os.setuid(config.controller_uid)
        if (
            os.geteuid() != config.controller_uid
            or os.getegid() != config.transport_gid
            or set(os.getgroups()) != {config.transport_gid}
        ):
            raise ControllerProtocolError(
                "controller could not enter the exact configured controller/transport identity"
            )
        _endpoint_metadata(config)
        return listener
    except Exception:
        listener.close()
        raise


def serve_forever() -> None:
    config = load_controller_config()
    if not config.beads_enabled:
        raise ControllerProtocolError("protected Beads boundary is disabled")
    if not sys.platform.startswith("linux"):
        raise ControllerProtocolError("controller service requires Linux")
    if os.geteuid() != 0:
        raise ControllerProtocolError(
            "controller service must start as root and drop to the configured controller UID"
        )
    _validate_transport_group(config)
    _validate_endpoint_parent(config)
    native_manifest = _verify_installed_artifacts(config)
    _verify_native_platform_gate(native_manifest, run_probe=False)
    worker = _spawn_worker_channel_v27(config, native_manifest)
    listener: socket.socket | None = None
    try:
        # Spawn before either operator or controller HMAC material is read, so
        # the forked worker cannot inherit either secret.  The worker drops to
        # workerUid, closes every inherited descriptor, proves DAC denial, and
        # performs all Podman/supervisor probes under that identity.
        try:
            key_info = os.lstat(CONTROLLER_KEY_PATH)
            if (
                stat.S_ISLNK(key_info.st_mode)
                or not stat.S_ISREG(key_info.st_mode)
                or key_info.st_uid != config.controller_uid
                or key_info.st_nlink != 1
                or stat.S_IMODE(key_info.st_mode) & 0o077
            ):
                raise ControllerProtocolError(
                    "controller HMAC key must be a controller-owned private regular file"
                )
            key_fd = os.open(
                CONTROLLER_KEY_PATH,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                opened = os.fstat(key_fd)
                if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode) != (
                    key_info.st_dev, key_info.st_ino, key_info.st_uid, key_info.st_mode
                ):
                    raise ControllerProtocolError("controller HMAC key changed before open")
                key = os.read(key_fd, 4097)
            finally:
                os.close(key_fd)
        except ControllerProtocolError:
            raise
        except OSError as exc:
            raise ControllerProtocolError(f"cannot read controller HMAC key: {exc}") from exc
        if len(key) < 32 or len(key) > 4096:
            raise ControllerProtocolError("controller HMAC key must contain 32..4096 bytes")
        _validate_controller_directory(STATE_ROOT, config, "controller state root")
        recovered = _recover_controller_payload_cgroups_v27(
            worker.supervisor_cgroup_fd,
            controller_uid=config.controller_uid,
            worker_uid=config.worker_uid,
            worker_gid=worker.cgroup_worker_gid,
            controller_key=key,
            recovery_journal_root=STATE_ROOT / "cgroup-recovery-v27",
        )
        worker.retirement_receipts.update(recovered)
        operator_key = _read_operator_key()
        verify_operator_lifecycle_v1(config, operator_key, require_active=True)
        # Bind/chown the endpoint and irreversibly drop to controllerUid before
        # mutating controller-owned handoff journals or leaf modes.
        listener = _create_listener(config)
        worker.await_ready()
        native_boundary_v27.recover_repository_custody_v27(
            STATE_ROOT,
            key,
            native_manifest,
            {
                "rootPath": str(REPOSITORY_HANDOFF_ROOT_V27),
                "controllerUid": config.controller_uid,
                "workerGid": worker.cgroup_worker_gid,
                "workerSessionNonce": worker.worker_session_nonce,
            },
            release_probe=lambda plan, request_key: worker._probe_repository_release(
                native_manifest,
                plan,
                request_key=request_key,
                lifecycle_check=lambda: None,
            ),
        )
        listener.listen(LISTEN_BACKLOG)
        listener.settimeout(1.0)

        def live_execution_lifecycle() -> dict[str, Any]:
            live_config = load_controller_config()
            fixed_live = dataclasses.replace(
                live_config, beads_enabled=config.beads_enabled
            )
            if fixed_live != config:
                raise ControllerProtocolError(
                    "live Beads controller configuration identity changed"
                )
            operator = verify_operator_lifecycle_v1(
                live_config, operator_key, require_active=False
            )
            return {
                **operator,
                "authenticatedOperatorState": operator["operatorState"],
                "configEnabled": live_config.beads_enabled,
                "operatorState": (
                    operator["operatorState"]
                    if live_config.beads_enabled
                    else "disabled"
                ),
            }

        while True:
            # A root operator disable replaces authenticated state in /etc.
            # Re-read it before every accept and request.  A disabled state
            # fences new work and closes the listener so systemd can drain the
            # complete delegated service cgroup.
            if live_execution_lifecycle()["operatorState"] != "active":
                raise ControllerProtocolError(
                    "local operator state is not active"
                )
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            _serve_connection(
                connection,
                config,
                key,
                operator_key,
                supervisor_runner=_WorkerStageRunnerV27(
                    worker,
                    live_execution_lifecycle,
                    key,
                ),
            )
    finally:
        if listener is not None:
            listener.close()
        worker.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="startup-factory-beads-controller")
    parser.add_argument(
        "command",
        choices=(
            "validate-config",
            "require-enabled",
            "serve",
            "operator-preview",
            "operator-apply",
            "operator-disable",
            "operator-reactivate",
            "operator-status",
        ),
    )
    parser.add_argument("--plan-digest")
    parser.add_argument(
        "--transition", choices=("apply", "disable", "reactivate"), default="apply"
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            serve_forever()
        else:
            config = load_controller_config()
            if args.command == "require-enabled":
                if not config.beads_enabled:
                    raise ControllerProtocolError(
                        "protected Beads boundary is disabled; set beadsEnabled=true only after the external V27 proof gate passes"
                    )
                verify_operator_lifecycle_v1(
                    config, _read_operator_key(), require_active=True
                )
                return 0
            if args.command.startswith("operator-"):
                operator_key = _read_operator_key()
                action = args.command.removeprefix("operator-")
                if action == "status":
                    print(
                        _canonical(
                            verify_operator_lifecycle_v1(config, operator_key)
                        ).decode("utf-8")
                    )
                    return 0
                if action == "preview":
                    action = args.transition
                    print(
                        _canonical(
                            preview_operator_lifecycle_v1(
                                config, action, operator_key=operator_key
                            )
                        ).decode("utf-8")
                    )
                    return 0
                if args.plan_digest is None:
                    raise ControllerProtocolError(
                        "operator lifecycle Apply requires --plan-digest from preview"
                    )
                transition = "apply" if action == "apply" else action
                print(
                    _canonical(
                        apply_operator_lifecycle_v1(
                            config,
                            transition,
                            args.plan_digest,
                            operator_key=operator_key,
                        )
                    ).decode("utf-8")
                )
                return 0
            print(_canonical({
                "schemaVersion": 1,
                "protocol": PROTOCOL,
                "configured": config.beads_enabled,
                "endpointPath": str(ENDPOINT_PATH),
                "rootSetSha256": config.root_set_sha256,
                "proofState": (
                    "configured_unproved" if config.beads_enabled else "disabled"
                ),
            }).decode())
        return 0
    except ControllerProtocolError as exc:
        print(f"startup-factory-beads-controller: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
