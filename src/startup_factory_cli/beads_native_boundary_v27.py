"""Internal V27 contracts for the protected Beads native boundary.

This module is deliberately not re-exported by ``startup_factory_cli`` or the
public protected-runtime module.  It validates the root-owned Linux execution
profile and the evidence shapes consumed by the controller.  It grants no
authority by itself: production authority still requires the live controller,
native supervisor, enforcing SELinux, systemd and rootless Podman gates.
"""

from __future__ import annotations

import base64
import dataclasses
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final


PROFILE: Final = "startup-factory/beads-native-boundary/v27"
SYSTEMD_VERSION: Final = "254"
PODMAN_VERSION: Final = "5.4.1"
CONMON_VERSION: Final = "2.1.12"
MAX_CANONICAL_BYTES: Final = 1_048_576
_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_CONTEXT_INTERFACES: Final = MappingProxyType(
    {
        "proc-current-preexec": ("none", "beads_controller_t"),
        "proc-exec-preexec": ("empty", None),
        "file-xattr-supervisor-exec": (
            "one-trailing-nul",
            "beads_supervisor_exec_t",
        ),
        "proc-current-setupready": ("none", "beads_native_supervisor_t"),
    }
)

HMAC_DOMAINS_V27: Final = MappingProxyType(
    {
        "StageCurrentV3": b"startup-factory/beads/stage-current/v3\0",
        "SupervisorResultEnvelopeV4": b"startup-factory/beads/supervisor-result-envelope/v4\0",
        "PriorRecoveryAttemptPrefixV2": b"startup-factory/beads/prior-recovery-attempt-prefix/v2\0",
        "OldRecoveryAttemptInertReceiptV2": b"startup-factory/beads/old-recovery-attempt-inert-receipt/v2\0",
        "PriorRecoveryAttemptResultV3": b"startup-factory/beads/prior-recovery-attempt-result/v3\0",
        "RecoveryOperationLockAttemptV6": b"startup-factory/beads/recovery-operation-lock-attempt/v6\0",
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


class NativeBoundaryV27Error(RuntimeError):
    """A closed native-boundary invariant failed."""


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
    supervisor_path: Path
    supervisor_sha256: str
    podman_path: Path
    podman_sha256: str
    conmon_path: Path
    conmon_sha256: str
    selinux_policy_sha256: str
    selinux_contexts: Mapping[str, SELinuxRawContextExpectationV1]
    image_reference: str
    image_digest: str
    systemd_version: str = SYSTEMD_VERSION
    podman_version: str = PODMAN_VERSION
    conmon_version: str = CONMON_VERSION
    selinux_mode: str = "enforcing"


_MANIFEST_FIELDS = {
    "schemaVersion",
    "profile",
    "systemdVersion",
    "podmanVersion",
    "conmonVersion",
    "selinuxMode",
    "supervisorPath",
    "supervisorSha256",
    "podmanPath",
    "podmanSha256",
    "conmonPath",
    "conmonSha256",
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
        "selinuxMode": "enforcing",
    }
    for field, expected in exact_scalars.items():
        if type(data[field]) is not str or data[field] != expected:
            raise NativeBoundaryV27Error(
                f"native-boundary {field} differs from the closed profile"
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
        _absolute(data["supervisorPath"], "supervisorPath"),
        _absolute(data["podmanPath"], "podmanPath"),
        _absolute(data["conmonPath"], "conmonPath"),
    )
    if len(set(paths)) != 3:
        raise NativeBoundaryV27Error(
            "supervisor, Podman and conmon paths must be distinct"
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
        supervisor_path=paths[0],
        supervisor_sha256=str(_digest(data["supervisorSha256"], "supervisorSha256")),
        podman_path=paths[1],
        podman_sha256=str(_digest(data["podmanSha256"], "podmanSha256")),
        conmon_path=paths[2],
        conmon_sha256=str(_digest(data["conmonSha256"], "conmonSha256")),
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
    "selinuxMode",
    "supervisorSha256",
    "podmanSha256",
    "conmonSha256",
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
        "selinuxMode": manifest.selinux_mode,
        "supervisorSha256": manifest.supervisor_sha256,
        "podmanSha256": manifest.podman_sha256,
        "conmonSha256": manifest.conmon_sha256,
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
            "selinuxMode": manifest.selinux_mode,
            "supervisorSha256": manifest.supervisor_sha256,
            "podmanSha256": manifest.podman_sha256,
            "conmonSha256": manifest.conmon_sha256,
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


def _drain_delegated_supervisor_cgroup_v27() -> None:
    """Kill and prove empty the service's fixed delegated supervisor subgroup."""

    if not sys.platform.startswith("linux"):
        raise NativeBoundaryV27Error("V27 descendant drain requires Linux cgroup v2")
    try:
        raw = Path("/proc/self/cgroup").read_bytes()
        lines = raw.splitlines()
        if len(lines) != 1 or not lines[0].startswith(b"0::/"):
            raise NativeBoundaryV27Error("controller is not in one exact cgroup-v2 unit")
        relative = lines[0][3:].decode("utf-8", "strict")
        if not relative or ".." in Path(relative).parts:
            raise NativeBoundaryV27Error("controller cgroup path is unsafe")
        subgroup = Path("/sys/fs/cgroup") / relative / "supervisor"
        kill_path = subgroup / "cgroup.kill"
        events_path = subgroup / "cgroup.events"
        kill_fd = os.open(kill_path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.write(kill_fd, b"1\n")
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
    except (OSError, UnicodeDecodeError) as exc:
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
) -> subprocess.CompletedProcess[bytes]:
    """Stream both pipes with a hard cap; never buffer an unbounded child."""

    if not argv or any(not isinstance(item, str) or not item or "\0" in item for item in argv):
        raise NativeBoundaryV27Error("V27 bounded runner argv is invalid")
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
    )
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


def _validate_rootless_podman_info_v27(
    value: Any, *, expected_worker_uid: int | None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeBoundaryV27Error("Podman info is not one JSON object")
    host = value.get("host")
    if not isinstance(host, dict):
        raise NativeBoundaryV27Error("Podman info has no host observation")
    security = host.get("security")
    mappings = host.get("idMappings")
    if (
        not isinstance(security, dict)
        or security.get("rootless") is not True
        or host.get("cgroupVersion") != "v2"
        or host.get("cgroupManager") != "systemd"
        or not isinstance(mappings, dict)
        or set(mappings) != {"uidmap", "gidmap"}
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
    return {"rootless": True, "idMappings": normalized}


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
) -> dict[str, Any]:
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
            "HOME": "/run/startup-factory/home",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        },
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
            "HOME": "/run/startup-factory/home",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }
    ):
        raise NativeBoundaryV27Error(
            "V27 supervised-effect changed the image, network, pull or environment policy"
        )
    if data["planSha256"] != _effect_plan_digest(data):
        raise NativeBoundaryV27Error("V27 supervised-effect plan digest mismatch")
    return {
        **data,
        "repositoryPath": str(repository),
        "argv": list(argv),
        "environment": dict(data["environment"]),
    }


def _effect_fault(phase: str) -> None:
    if _EFFECT_FAULT.get() == phase:
        raise SystemExit(f"intentional V27 native-effect fault after {phase}")


@contextmanager
def inject_native_effect_fault_v27(phase: str):
    token = _EFFECT_FAULT.set(phase)
    try:
        yield
    finally:
        _EFFECT_FAULT.reset(token)


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


def _write_effect_immutable(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_bytes(dict(value))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except FileExistsError:
        raise NativeBoundaryV27Error("V27 immutable effect object appeared concurrently")


def _publish_effect_object(path: Path, envelope: Mapping[str, Any], key: bytes) -> None:
    if path.exists():
        existing = _read_effect_record(path, key, expected_kind=str(envelope["kind"]))
        if canonical_bytes(existing) != canonical_bytes(dict(envelope)):
            raise NativeBoundaryV27Error("V27 immutable effect object conflicts")
        return
    _write_effect_immutable(path, envelope)


def _replace_effect_current(
    path: Path,
    envelope: Mapping[str, Any],
    *,
    expected: bytes | None,
) -> None:
    try:
        current = path.read_bytes()
    except FileNotFoundError:
        current = None
    if current != expected:
        raise NativeBoundaryV27Error("V27 StageCurrent predecessor changed")
    raw = canonical_bytes(dict(envelope))
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
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
    if isinstance(value, Mapping) and set(value) == {"nativeObservation"}:
        observation = value["nativeObservation"]
        if not isinstance(observation, Mapping) or set(observation) != {
            "exitCode",
            "stdoutSha256",
            "stderrSha256",
            "readBackSha256",
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
        ):
            raise NativeBoundaryV27Error(
                "native supervisor observation is outside the closed lifecycle"
            )
        for field in ("stdoutSha256", "stderrSha256", "readBackSha256"):
            _digest(observation[field], field)
        return dict(observation)
    if not isinstance(value, Mapping) or set(value) != {
        "exitCode",
        "stdout",
        "stderr",
        "readBack",
        "lifecycle",
    }:
        raise NativeBoundaryV27Error("native supervisor result shape is invalid")
    if (
        type(value["exitCode"]) is not int
        or not -255 <= value["exitCode"] <= 255
        or list(value["lifecycle"]) != list(_EFFECT_LIFECYCLE)
        or any(
            not isinstance(value[field], bytes)
            or len(value[field]) > MAX_CANONICAL_BYTES
            for field in ("stdout", "stderr", "readBack")
        )
    ):
        raise NativeBoundaryV27Error("native supervisor result is outside the closed lifecycle")
    return {
        "exitCode": value["exitCode"],
        "stdoutSha256": sha256(value["stdout"]),
        "stderrSha256": sha256(value["stderr"]),
        "readBackSha256": sha256(value["readBack"]),
        "lifecycle": list(_EFFECT_LIFECYCLE),
        "observedByNativeSupervisor": True,
    }


def inspect_supervised_effect_v27(
    state_root: Path, key: bytes, operation_id: str
) -> dict[str, Any]:
    operation, _, _ = _effect_state_paths(state_root, operation_id)
    return _read_effect_record(
        operation / "current.json", key, expected_kind="StageCurrentV3"
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
) -> dict[str, Any]:
    plan = validate_supervised_effect_plan_v27(value, manifest)
    if runner is None:
        runner = run_native_supervisor_v27
    operation, history, objects = _effect_state_paths(
        state_root, plan["operationId"]
    )
    current_path = operation / "current.json"
    done = DONE_LOCATIONS_V27[plan["operationClass"]]
    with _effect_lock(operation / "operation.lock"):
        current: dict[str, Any] | None = None
        if current_path.exists():
            current = _read_effect_record(
                current_path, key, expected_kind="StageCurrentV3"
            )
            payload = current["payload"]
            if (
                payload.get("operationId") != plan["operationId"]
                or payload.get("operationClass") != plan["operationClass"]
                or payload.get("planSha256") != plan["planSha256"]
            ):
                raise NativeBoundaryV27Error("V27 current was rebound to another plan")
            if payload.get("state") == "completion" and payload.get("location") == done:
                return _load_effect_result(objects, current, key)
            if payload.get("state") == "launch-consumed-current":
                recovered = _recover_stored_effect_result_v27(
                    current_path=current_path,
                    history=history,
                    objects=objects,
                    current=current,
                    plan=plan,
                    key=key,
                    done=done,
                )
                if recovered is not None:
                    return recovered
                raise NativeBoundaryV27Error(
                    "V27 launch was consumed with no durable result; possible effect is quarantined and never replayed"
                )
            raise NativeBoundaryV27Error("V27 effect current is nonterminal or conflicted")

        intent = _install_stage_current(
            current_path,
            history,
            key,
            _stage_current_payload(
                plan,
                generation=1,
                location=done - 3,
                state="intent-current",
                predecessor=None,
                result_record_sha256=None,
            ),
            expected=None,
        )
        _effect_fault("intent-current")
        consumed = _install_stage_current(
            current_path,
            history,
            key,
            _stage_current_payload(
                plan,
                generation=2,
                location=done - 2,
                state="launch-consumed-current",
                predecessor=intent,
                result_record_sha256=None,
            ),
            expected=intent,
        )
        _effect_fault("launch-consumed-current")
        raw_result = runner(manifest, plan)
        observation = _decode_supervisor_result(raw_result)
        result_payload = {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "predecessorCurrentRecordSha256": consumed["recordSha256"],
            "observation": observation,
        }
        result = _effect_sign("SupervisorResultEnvelopeV4", result_payload, key)
        result_path = objects / f"{result['recordSha256'].removeprefix('sha256:')}.json"
        _publish_effect_object(result_path, result, key)
        _effect_fault("result-object-written")
        result_current = _install_stage_current(
            current_path,
            history,
            key,
            _stage_current_payload(
                plan,
                generation=3,
                location=done - 1,
                state="result-stored-current",
                predecessor=consumed,
                result_record_sha256=result["recordSha256"],
            ),
            expected=consumed,
        )
        _effect_fault("result-current-installed")
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
        _effect_fault("completion-current-installed")
        return _load_effect_result(objects, completed, key)


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
        os.write(descriptor, raw)
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


def _encode_native_plan_v27(plan: Mapping[str, Any]) -> bytes:
    fields = (
        str(plan["operationId"]),
        str(plan["planSha256"]),
        str(plan["imageReference"]),
        str(plan["repositoryPath"]),
    )
    encoded = bytearray(b"SFV27P1\0")
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
        raise NativeBoundaryV27Error("native V27 binary plan is oversized")
    return bytes(encoded)


def run_native_supervisor_v27(
    manifest: NativeBoundaryManifestV27,
    value: Any,
    *,
    process_runner: Any = None,
) -> dict[str, Any]:
    plan = validate_supervised_effect_plan_v27(value, manifest)
    plan_raw = _encode_native_plan_v27(plan)
    descriptor = -1
    production_runner = process_runner is None
    if production_runner:
        descriptor = _sealed_plan_descriptor_v27(plan_raw)
    else:
        handle = tempfile.TemporaryFile()
        handle.write(plan_raw)
        handle.flush()
        handle.seek(0)
        descriptor = handle.fileno()
    try:
        argv = [str(manifest.supervisor_path), "--startup-factory-execute-v27"]
        preexec = lambda: os.dup2(descriptor, 3)
        if production_runner:
            completed = _run_bounded_process_v27(
                argv,
                timeout=150,
                pass_fds=(descriptor,),
                preexec_fn=preexec,
                drain_on_failure=True,
            )
        else:
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
                preexec_fn=preexec,
            )
    finally:
        if production_runner and descriptor >= 0:
            os.close(descriptor)
        elif not production_runner:
            handle.close()
    if completed.returncode != 0:
        raise NativeBoundaryV27Error(
            f"native V27 supervisor failed rc={completed.returncode}"
        )
    value = _strict_probe_json(completed.stdout)
    if set(value) != {
        "exitCode",
        "lifecycle",
        "readBackBase64",
        "stderrBase64",
        "stdoutBase64",
    }:
        raise NativeBoundaryV27Error("native V27 supervisor result schema changed")
    try:
        decoded = {
            "exitCode": value["exitCode"],
            "lifecycle": value["lifecycle"],
            "readBack": base64.b64decode(value["readBackBase64"], validate=True),
            "stderr": base64.b64decode(value["stderrBase64"], validate=True),
            "stdout": base64.b64decode(value["stdoutBase64"], validate=True),
        }
    except (TypeError, ValueError) as exc:
        raise NativeBoundaryV27Error(
            "native V27 supervisor result base64 is invalid"
        ) from exc
    _decode_supervisor_result(decoded)
    return decoded


INTERNAL_SCHEMA_NAMES: Final = tuple(dict.fromkeys((
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
