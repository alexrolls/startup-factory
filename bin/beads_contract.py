#!/usr/bin/env python3
"""Unsigned canonical contracts for the optional Beads adapter.

The read-back candidate in this module is inert nested data.  It contains only
the registered v1.1.2 command templates and bounds; it cannot select an
executable, path, environment, process, container, output, or authority.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any, Final


# Registry line 135 owns this already-registered task-2 surface.  Registry line
# 151 adds no candidate export: every read-back symbol remains underscored.
__all__: tuple[str, ...] = (
    "PreparedBeadsStorePayloadInputsV1",
    "PreparedBeadsStoreExpectedBindingsV1",
    "PreparedBeadsStorePayloadV1",
    "VerifiedPreparedBeadsStorePayloadV1",
    "build_prepared_beads_store_payload_v1",
    "validate_prepared_beads_store_payload_v1",
)

_BEADS_BASELINE_VERSION: Final = "1.1.2"
_BEADS_BASELINE_SOURCE_COMMIT: Final = (
    "20e493e569c922d1253bdeff068c5e56c94957fb"
)
_READ_BACK_PLAN_CANDIDATE_DOMAIN: Final = (
    b"startup-factory/beads-read-back-plan-candidate/v1\0"
)
_MAX_READ_BACK_PLAN_CANDIDATE_BYTES: Final = 32_768
_MAX_PREPARED_PAYLOAD_BYTES: Final = 32_768
_PREPARED_PAYLOAD_DOMAIN: Final = b"startup-factory/prepared-beads-store-payload/v1\0"

_PREPARED_KIND: Final = "prepared-beads-store-payload-v1"
_CANDIDATE_KIND: Final = "beads-read-back-plan-candidate-v1"
_CANDIDATE_FIELD: Final = "readBackPlanCandidate"
_CANDIDATE_DIGEST_FIELD: Final = "readBackPlanCandidateSha256"
_CARRIER_ALIASES: Final = frozenset(
    {
        "beadsReadBackPlanCandidate",
        "readbackPlanCandidate",
        "readBackPlan",
        "readBackPlanCandidateCanonicalJson",
        "readBackPlanSha256",
    }
)

_ENVELOPE: Final = {
    "outerKeys": ["data", "schema_version"],
    "schemaVersion": 1,
    "noExtras": True,
    "noDuplicates": True,
    "noTrailingValue": True,
}

_STEPS: Final = [
    {
        "ordinal": 0,
        "requires": "terminal-mutation-process-group",
        "argvShape": [
            "$B",
            "--db",
            "$E",
            "--json",
            "--readonly",
            "--sandbox",
            "list",
            "--id",
            "$ID",
            "--all",
            "--limit",
            "0",
        ],
        "dataShape": "exact-one-issue-with-counts-v112",
    },
    {
        "ordinal": 1,
        "requires": "usable-ordinal-0-and-physical-equality",
        "argvShape": [
            "$B",
            "--db",
            "$E",
            "--json",
            "--readonly",
            "--sandbox",
            "label",
            "list",
            "$ID",
        ],
        "dataShape": "complete-label-string-array-v112",
    },
    {
        "ordinal": 2,
        "requires": "usable-ordinal-1-and-physical-equality",
        "argvShape": [
            "$B",
            "--db",
            "$E",
            "--json",
            "--readonly",
            "--sandbox",
            "comments",
            "$ID",
        ],
        "dataShape": "complete-comment-array-v112",
    },
    {
        "ordinal": 3,
        "requires": "usable-ordinal-2-and-physical-equality",
        "argvShape": [
            "$B",
            "--db",
            "$E",
            "--json",
            "--readonly",
            "--sandbox",
            "dep",
            "list",
            "$ID",
            "--direction",
            "down",
        ],
        "dataShape": "complete-one-id-dependency-projection-array-v112",
    },
]

_BODY: Final = {
    "schemaVersion": 1,
    "kind": _CANDIDATE_KIND,
    "baselineVersion": _BEADS_BASELINE_VERSION,
    "sourceCommit": _BEADS_BASELINE_SOURCE_COMMIT,
    "envelope": _ENVELOPE,
    "environmentProfile": "beads-protected-readback-env-v1",
    "aggregateDeadlineSeconds": 120,
    "maxSpawnCount": 4,
    "stdoutLimitBytesPerChild": 1_048_576,
    "stderrLimitBytesPerChild": 1_048_576,
    "maxArgvBytes": 65_536,
    "maxRecordBytes": 262_144,
    "maxStringBytes": 65_536,
    "steps": _STEPS,
}


class _BeadsContractError(ValueError):
    """A canonical unsigned Beads contract is malformed or inconsistent."""


def _reject_constant(value: str) -> None:
    raise _BeadsContractError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _BeadsContractError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _validate_nfc_json(value: Any, *, depth: int = 0) -> None:
    if depth > 16:
        raise _BeadsContractError("canonical JSON nesting exceeds 16 levels")
    if value is None or isinstance(value, bool) or type(value) is int:
        return
    if isinstance(value, str):
        if value != unicodedata.normalize("NFC", value):
            raise _BeadsContractError("canonical JSON strings must be NFC")
        if len(value.encode("utf-8")) > 65_536:
            raise _BeadsContractError("canonical JSON string exceeds 65536 bytes")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise _BeadsContractError(
                    "canonical JSON keys must be nonempty strings"
                )
            _validate_nfc_json(key, depth=depth + 1)
            _validate_nfc_json(item, depth=depth + 1)
        return
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        if len(value) > 64:
            raise _BeadsContractError("canonical JSON sequence is oversized")
        for item in value:
            _validate_nfc_json(item, depth=depth + 1)
        return
    raise _BeadsContractError(
        f"unsupported canonical JSON value: {type(value).__name__}"
    )


def _canonical_bytes(value: Any) -> bytes:
    _validate_nfc_json(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _BeadsContractError("value is not canonical JSON") from exc


def _plain_copy(value: Any) -> Any:
    # The validated material contains JSON values only.  A canonical round trip
    # returns a detached copy and avoids exposing mutable module constants.
    return json.loads(_canonical_bytes(value).decode("utf-8"))


def _plan_sha256(body: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        _READ_BACK_PLAN_CANDIDATE_DOMAIN + _canonical_bytes(body)
    ).hexdigest()


@dataclasses.dataclass(frozen=True, slots=True)
class _BeadsReadBackPlanCandidateV1:
    """Validated inert candidate bytes; intentionally absent from ``__all__``."""

    canonical_bytes: bytes
    plan_sha256: str

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.canonical_bytes.decode("utf-8"))


def _expected_candidate_payload() -> dict[str, Any]:
    body = _plain_copy(_BODY)
    return {**body, "planSha256": _plan_sha256(body)}


def _build_beads_read_back_plan_candidate_v1() -> _BeadsReadBackPlanCandidateV1:
    """Build the one registered unsigned v1.1.2 candidate."""

    payload = _expected_candidate_payload()
    encoded = _canonical_bytes(payload)
    if len(encoded) > _MAX_READ_BACK_PLAN_CANDIDATE_BYTES:
        raise _BeadsContractError("registered read-back candidate is oversized")
    return _BeadsReadBackPlanCandidateV1(
        canonical_bytes=encoded,
        plan_sha256=str(payload["planSha256"]),
    )


def _validate_beads_read_back_plan_candidate_v1(
    candidate_canonical_bytes: bytes,
) -> _BeadsReadBackPlanCandidateV1:
    """Parse and validate exact canonical candidate bytes without authority."""

    if type(candidate_canonical_bytes) is not bytes:
        raise _BeadsContractError("read-back candidate must be exact bytes")
    if not candidate_canonical_bytes:
        raise _BeadsContractError("read-back candidate must not be empty")
    if len(candidate_canonical_bytes) > _MAX_READ_BACK_PLAN_CANDIDATE_BYTES:
        raise _BeadsContractError("read-back candidate exceeds 32768 bytes")
    if candidate_canonical_bytes.startswith(b"\xef\xbb\xbf"):
        raise _BeadsContractError("read-back candidate must not contain a BOM")
    try:
        decoded = candidate_canonical_bytes.decode("utf-8", errors="strict")
        payload = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except _BeadsContractError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _BeadsContractError("read-back candidate is not one UTF-8 JSON value") from exc
    if not isinstance(payload, dict):
        raise _BeadsContractError("read-back candidate must be a JSON object")
    if _canonical_bytes(payload) != candidate_canonical_bytes:
        raise _BeadsContractError(
            "read-back candidate bytes are not compact sorted-key canonical JSON"
        )

    expected = _expected_candidate_payload()
    # Compare canonical encodings, not Python values: ``True == 1`` in Python,
    # but booleans are never valid aliases for the registered integer fields.
    if _canonical_bytes(payload) != _canonical_bytes(expected):
        raise _BeadsContractError(
            "read-back candidate differs from the registered closed v1.1.2 plan"
        )
    if set(payload) != set(_BODY) | {"planSha256"}:
        raise _BeadsContractError("read-back candidate has an unknown or missing field")
    if type(payload.get("schemaVersion")) is not int:
        raise _BeadsContractError("read-back candidate schemaVersion must be integer 1")
    if not isinstance(payload.get("steps"), list) or len(payload["steps"]) != 4:
        raise _BeadsContractError("read-back candidate must have exactly four steps")
    if [step.get("ordinal") for step in payload["steps"]] != [0, 1, 2, 3]:
        raise _BeadsContractError("read-back candidate ordinals must be exactly 0..3")

    body = {key: value for key, value in payload.items() if key != "planSha256"}
    plan_sha256 = _plan_sha256(body)
    if payload["planSha256"] != plan_sha256:
        raise _BeadsContractError("read-back candidate domain digest mismatch")
    return _BeadsReadBackPlanCandidateV1(
        canonical_bytes=candidate_canonical_bytes,
        plan_sha256=plan_sha256,
    )


_SHA256_RE: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EPOCH_RE: Final = re.compile(r"[0-9a-f]{32}\Z")
_DATABASE_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_MODE_RE: Final = re.compile(r"[0-7]{4}\Z")
_UINT64_MAX: Final = 18_446_744_073_709_551_615
_UINT32_MAX: Final = 4_294_967_295

_STAT_FIELDS: Final = frozenset(
    {"device", "inode", "uid", "mode", "linkCount", "size"}
)
_EXECUTABLE_FIELDS: Final = frozenset(
    {
        "pathLocatorSha256",
        "sha256",
        "device",
        "inode",
        "uid",
        "mode",
        "linkCount",
        "size",
        "mtimeNs",
        "version",
        "sourceCommit",
    }
)
_IMMUTABLE_FILE_FIELDS: Final = frozenset({"path", "size", "sha256", "stat"})
_METADATA_FIELDS: Final = frozenset(
    {"database", "backend", "doltMode", "doltDatabase", "projectId", "sha256"}
)
_LAST_TOUCHED_FIELDS: Final = frozenset(
    {
        "relativePath",
        "absentAllowed",
        "presentMode",
        "maximumBytes",
        "exactMutationPostcondition",
    }
)
_PREPARED_FIELDS: Final = frozenset(
    {
        "schemaVersion",
        "kind",
        "preparationMode",
        "repositoryLocatorSha256",
        "projectRootLocatorSha256",
        "beadsRootRelative",
        "beadsRootLocatorSha256",
        "beadsRootStat",
        "embeddedDataRootRelative",
        "embeddedDataRootStat",
        "databaseName",
        "databaseRootRelative",
        "databaseRootStat",
        "databaseDoltRootStat",
        "executable",
        "immutableFiles",
        "metadata",
        "statusProfilePayloadSha256",
        "statusProfileStaticBindingsSha256",
        "statusProfileDerivationPolicySha256",
        "statusProfileDynamicBindingsSha256",
        "statusProfileExpectedBindingsSha256",
        "derivationJournalHeadSha256",
        "runtimeApiManifestSha256",
        "releaseManifestSha256",
        "genericStatusConfigSha256",
        "preStoreObservationSha256",
        "postStoreObservationSha256",
        "storeStateSha256",
        "configEnvelopeCanonicalSha256",
        "cleanupObservationSha256",
        "preparationPlanSha256",
        "authorityEpoch",
        "predecessorPreparedStorePayloadSha256",
        "lastTouchedPolicy",
        _CANDIDATE_FIELD,
        _CANDIDATE_DIGEST_FIELD,
    }
)


@dataclasses.dataclass(frozen=True, slots=True)
class PreparedBeadsStorePayloadInputsV1:
    """Typed inputs to the sole task-2 unsigned preparation entry path."""

    preparation_mode: str
    repository_locator_sha256: str
    project_root_locator_sha256: str
    beads_root_locator_sha256: str
    beads_root_stat: Mapping[str, Any]
    embedded_data_root_stat: Mapping[str, Any]
    database_name: str
    database_root_stat: Mapping[str, Any]
    database_dolt_root_stat: Mapping[str, Any]
    executable: Mapping[str, Any]
    immutable_files: Sequence[Mapping[str, Any]]
    metadata: Mapping[str, Any]
    status_profile_payload_sha256: str
    status_profile_static_bindings_sha256: str
    status_profile_derivation_policy_sha256: str
    status_profile_dynamic_bindings_sha256: str
    status_profile_expected_bindings_sha256: str
    derivation_journal_head_sha256: str
    runtime_api_manifest_sha256: str
    release_manifest_sha256: str
    generic_status_config_sha256: str
    pre_store_observation_sha256: str
    post_store_observation_sha256: str
    store_state_sha256: str
    config_envelope_canonical_sha256: str
    cleanup_observation_sha256: str | None
    preparation_plan_sha256: str
    authority_epoch: str
    predecessor_prepared_store_payload_sha256: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class PreparedBeadsStoreExpectedBindingsV1:
    """Independent bindings supplied separately from payload-builder inputs."""

    preparation_mode: str
    repository_locator_sha256: str
    project_root_locator_sha256: str
    beads_root_locator_sha256: str
    database_name: str
    metadata_sha256: str
    status_profile_payload_sha256: str
    status_profile_static_bindings_sha256: str
    status_profile_derivation_policy_sha256: str
    status_profile_dynamic_bindings_sha256: str
    status_profile_expected_bindings_sha256: str
    derivation_journal_head_sha256: str
    runtime_api_manifest_sha256: str
    release_manifest_sha256: str
    generic_status_config_sha256: str
    pre_store_observation_sha256: str
    post_store_observation_sha256: str
    store_state_sha256: str
    config_envelope_canonical_sha256: str
    cleanup_observation_sha256: str | None
    preparation_plan_sha256: str
    authority_epoch: str
    predecessor_prepared_store_payload_sha256: str | None
    read_back_plan_candidate_sha256: str
    payload_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class PreparedBeadsStorePayloadV1:
    """Canonical unsigned prepared-store payload descriptor."""

    canonical_bytes: bytes
    payload_sha256: str

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.canonical_bytes.decode("utf-8"))


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedPreparedBeadsStorePayloadV1:
    """Semantically verified canonical unsigned prepared-store payload."""

    canonical_bytes: bytes
    payload_sha256: str

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.canonical_bytes.decode("utf-8"))


def _require_exact_fields(
    value: Any, expected: frozenset[str], *, label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _BeadsContractError(f"{label} must be an object")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise _BeadsContractError(
            f"{label} has non-exact fields; missing={missing!r}; extra={extra!r}"
        )
    return value


def _require_uint(value: Any, *, label: str, maximum: int = _UINT64_MAX) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise _BeadsContractError(f"{label} must be a bounded nonnegative integer")
    return value


def _require_sha256(value: Any, *, label: str, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise _BeadsContractError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def _validate_stat(
    value: Any,
    *,
    label: str,
    exact_mode: str | None = None,
    single_link: bool = False,
) -> None:
    item = _require_exact_fields(value, _STAT_FIELDS, label=label)
    _require_uint(item["device"], label=f"{label}.device")
    _require_uint(item["inode"], label=f"{label}.inode")
    _require_uint(item["uid"], label=f"{label}.uid", maximum=_UINT32_MAX)
    link_count = _require_uint(item["linkCount"], label=f"{label}.linkCount")
    _require_uint(item["size"], label=f"{label}.size")
    if not isinstance(item["mode"], str) or _MODE_RE.fullmatch(item["mode"]) is None:
        raise _BeadsContractError(f"{label}.mode must be four octal digits")
    if exact_mode is not None and item["mode"] != exact_mode:
        raise _BeadsContractError(f"{label}.mode must be exactly {exact_mode}")
    if exact_mode is None and int(item["mode"], 8) & 0o022:
        raise _BeadsContractError(f"{label}.mode must not be group/world writable")
    if single_link and link_count != 1:
        raise _BeadsContractError(f"{label}.linkCount must be exactly 1")
    if not single_link and link_count < 1:
        raise _BeadsContractError(f"{label}.linkCount must be positive")


def _validate_safe_relative_path(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1_024:
        raise _BeadsContractError(f"{label} must be a bounded relative POSIX path")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        raise _BeadsContractError(f"{label} must be a safe relative POSIX path")
    pieces = value.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces):
        raise _BeadsContractError(f"{label} has an unsafe component")
    if value != unicodedata.normalize("NFC", value):
        raise _BeadsContractError(f"{label} must be NFC")
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value):
        raise _BeadsContractError(f"{label} must not contain control characters")
    return value


def _validate_executable(value: Any) -> None:
    item = _require_exact_fields(value, _EXECUTABLE_FIELDS, label="executable")
    for field in ("pathLocatorSha256", "sha256"):
        _require_sha256(item[field], label=f"executable.{field}")
    for field in ("device", "inode", "linkCount", "size", "mtimeNs"):
        _require_uint(item[field], label=f"executable.{field}")
    _require_uint(item["uid"], label="executable.uid", maximum=_UINT32_MAX)
    if item["mode"] != "0500":
        raise _BeadsContractError("executable.mode must be exactly 0500")
    if item["linkCount"] != 1:
        raise _BeadsContractError("executable.linkCount must be exactly 1")
    if item["version"] != _BEADS_BASELINE_VERSION:
        raise _BeadsContractError("executable.version must be exactly 1.1.2")
    if item["sourceCommit"] != _BEADS_BASELINE_SOURCE_COMMIT:
        raise _BeadsContractError("executable.sourceCommit must be the full pinned commit")


def _validate_immutable_files(value: Any) -> None:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise _BeadsContractError("immutableFiles must contain 1..64 entries")
    paths: list[str] = []
    for ordinal, raw in enumerate(value):
        label = f"immutableFiles[{ordinal}]"
        item = _require_exact_fields(raw, _IMMUTABLE_FILE_FIELDS, label=label)
        path = _validate_safe_relative_path(item["path"], label=f"{label}.path")
        size = _require_uint(item["size"], label=f"{label}.size")
        _require_sha256(item["sha256"], label=f"{label}.sha256")
        _validate_stat(item["stat"], label=f"{label}.stat", single_link=True)
        if item["stat"]["mode"] not in {"0400", "0600"}:
            raise _BeadsContractError(f"{label}.stat.mode must be 0400 or 0600")
        if item["stat"]["size"] != size:
            raise _BeadsContractError(f"{label} size/stat.size mismatch")
        paths.append(path)
    encoded_paths = [path.encode("utf-8") for path in paths]
    if encoded_paths != sorted(encoded_paths) or len(set(encoded_paths)) != len(paths):
        raise _BeadsContractError("immutableFiles must be unique and bytewise-path sorted")


def _validate_metadata(value: Any, *, database_name: str) -> None:
    item = _require_exact_fields(value, _METADATA_FIELDS, label="metadata")
    exact = {
        "database": "dolt",
        "backend": "dolt",
        "doltMode": "embedded",
        "doltDatabase": database_name,
    }
    for field, expected in exact.items():
        if item[field] != expected:
            raise _BeadsContractError(f"metadata.{field} must equal {expected!r}")
    project_id = item["projectId"]
    if (
        not isinstance(project_id, str)
        or not project_id
        or len(project_id.encode("utf-8")) > 128
        or any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in project_id)
        or project_id != unicodedata.normalize("NFC", project_id)
    ):
        raise _BeadsContractError("metadata.projectId must be a bounded NFC string")
    _require_sha256(item["sha256"], label="metadata.sha256")


def _validate_last_touched_policy(value: Any) -> None:
    item = _require_exact_fields(value, _LAST_TOUCHED_FIELDS, label="lastTouchedPolicy")
    expected = {
        "relativePath": "last-touched",
        "absentAllowed": True,
        "presentMode": "0600",
        "maximumBytes": 129,
        "exactMutationPostcondition": "TARGET_ID_LF",
    }
    if _canonical_bytes(item) != _canonical_bytes(expected):
        raise _BeadsContractError("lastTouchedPolicy differs from the exact v1 policy")


def _validate_candidate_forbidden_names(value: Any) -> None:
    forbidden = ("process", "path", "authority")
    allowed = "terminal-mutation-process-group"
    if isinstance(value, Mapping):
        for key, item in value.items():
            if any(token in key.casefold() for token in forbidden):
                raise _BeadsContractError("read-back candidate has a forbidden shaped key")
            _validate_candidate_forbidden_names(item)
    elif isinstance(value, list):
        for item in value:
            _validate_candidate_forbidden_names(item)
    elif isinstance(value, str) and any(
        token in value.casefold() for token in forbidden
    ) and value != allowed:
        raise _BeadsContractError("read-back candidate has a forbidden shaped value")


def _validate_nested_candidate(payload: Mapping[str, Any]) -> _BeadsReadBackPlanCandidateV1:
    nested = payload[_CANDIDATE_FIELD]
    if not isinstance(nested, Mapping):
        raise _BeadsContractError("readBackPlanCandidate must be a nested object")
    _validate_candidate_forbidden_names(nested)
    candidate = _validate_beads_read_back_plan_candidate_v1(_canonical_bytes(nested))
    if payload[_CANDIDATE_DIGEST_FIELD] != candidate.plan_sha256:
        raise _BeadsContractError(
            "readBackPlanCandidateSha256 must equal nested planSha256"
        )
    return candidate


def _validate_prepared_object(payload: Any) -> Mapping[str, Any]:
    item = _require_exact_fields(payload, _PREPARED_FIELDS, label="prepared payload")
    if type(item["schemaVersion"]) is not int or item["schemaVersion"] != 1:
        raise _BeadsContractError("prepared payload schemaVersion must be integer 1")
    if item["kind"] != _PREPARED_KIND:
        raise _BeadsContractError("prepared payload kind mismatch")
    mode = item["preparationMode"]
    if mode not in {"create", "reattest"}:
        raise _BeadsContractError("preparationMode must be create or reattest")
    if item["beadsRootRelative"] != ".beads":
        raise _BeadsContractError("beadsRootRelative must be exactly .beads")
    if item["embeddedDataRootRelative"] != "embeddeddolt":
        raise _BeadsContractError("embeddedDataRootRelative must be exactly embeddeddolt")
    database_name = item["databaseName"]
    if not isinstance(database_name, str) or _DATABASE_RE.fullmatch(database_name) is None:
        raise _BeadsContractError("databaseName has invalid grammar")
    if item["databaseRootRelative"] != f"embeddeddolt/{database_name}":
        raise _BeadsContractError("databaseRootRelative/databaseName mismatch")
    for field in (
        "repositoryLocatorSha256",
        "projectRootLocatorSha256",
        "beadsRootLocatorSha256",
        "statusProfilePayloadSha256",
        "statusProfileStaticBindingsSha256",
        "statusProfileDerivationPolicySha256",
        "statusProfileDynamicBindingsSha256",
        "statusProfileExpectedBindingsSha256",
        "derivationJournalHeadSha256",
        "runtimeApiManifestSha256",
        "releaseManifestSha256",
        "genericStatusConfigSha256",
        "preStoreObservationSha256",
        "postStoreObservationSha256",
        "storeStateSha256",
        "configEnvelopeCanonicalSha256",
        "preparationPlanSha256",
        _CANDIDATE_DIGEST_FIELD,
    ):
        _require_sha256(item[field], label=field)
    _require_sha256(item["cleanupObservationSha256"], label="cleanupObservationSha256", nullable=True)
    _require_sha256(
        item["predecessorPreparedStorePayloadSha256"],
        label="predecessorPreparedStorePayloadSha256",
        nullable=True,
    )
    if not isinstance(item["authorityEpoch"], str) or _EPOCH_RE.fullmatch(item["authorityEpoch"]) is None:
        raise _BeadsContractError("authorityEpoch must be 32 lowercase hex")
    if mode == "create":
        if item["cleanupObservationSha256"] is None or item["predecessorPreparedStorePayloadSha256"] is not None:
            raise _BeadsContractError("create cleanup/predecessor nullability mismatch")
    elif item["cleanupObservationSha256"] is not None or item["predecessorPreparedStorePayloadSha256"] is None:
        raise _BeadsContractError("reattest cleanup/predecessor nullability mismatch")
    if item["preStoreObservationSha256"] == item["postStoreObservationSha256"]:
        raise _BeadsContractError("pre/post store observations must be distinct")
    root_stat_fields = (
        "beadsRootStat",
        "embeddedDataRootStat",
        "databaseRootStat",
        "databaseDoltRootStat",
    )
    for field in root_stat_fields:
        _validate_stat(item[field], label=field, exact_mode="0700")
    _validate_executable(item["executable"])
    _validate_immutable_files(item["immutableFiles"])
    owner_uid = item["beadsRootStat"]["uid"]
    if any(item[field]["uid"] != owner_uid for field in root_stat_fields):
        raise _BeadsContractError("all prepared-store root stats must share one uid")
    if item["executable"]["uid"] != owner_uid:
        raise _BeadsContractError("executable uid must equal prepared-store owner uid")
    if any(file["stat"]["uid"] != owner_uid for file in item["immutableFiles"]):
        raise _BeadsContractError("immutable-file uid must equal prepared-store owner uid")
    _validate_metadata(item["metadata"], database_name=database_name)
    _validate_last_touched_policy(item["lastTouchedPolicy"])
    _validate_nested_candidate(item)
    return item


def _parse_prepared_payload(payload_canonical_bytes: bytes) -> Mapping[str, Any]:
    if type(payload_canonical_bytes) is not bytes:
        raise _BeadsContractError("prepared payload must be exact bytes")
    if not payload_canonical_bytes or len(payload_canonical_bytes) > _MAX_PREPARED_PAYLOAD_BYTES:
        raise _BeadsContractError("prepared payload must contain 1..32768 bytes")
    if payload_canonical_bytes.startswith(b"\xef\xbb\xbf"):
        raise _BeadsContractError("prepared payload must not contain a BOM")
    try:
        text = payload_canonical_bytes.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except _BeadsContractError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _BeadsContractError("prepared payload is not one UTF-8 JSON value") from exc
    if not isinstance(payload, dict):
        raise _BeadsContractError("prepared payload must be a JSON object")
    if _canonical_bytes(payload) != payload_canonical_bytes:
        raise _BeadsContractError(
            "prepared payload bytes are not compact sorted-key canonical JSON"
        )
    return _validate_prepared_object(payload)


def _payload_from_inputs(inputs: PreparedBeadsStorePayloadInputsV1) -> dict[str, Any]:
    if type(inputs) is not PreparedBeadsStorePayloadInputsV1:
        raise _BeadsContractError("prepared payload builder requires typed inputs")
    candidate = _build_beads_read_back_plan_candidate_v1()
    return {
        "schemaVersion": 1,
        "kind": _PREPARED_KIND,
        "preparationMode": inputs.preparation_mode,
        "repositoryLocatorSha256": inputs.repository_locator_sha256,
        "projectRootLocatorSha256": inputs.project_root_locator_sha256,
        "beadsRootRelative": ".beads",
        "beadsRootLocatorSha256": inputs.beads_root_locator_sha256,
        "beadsRootStat": _plain_copy(inputs.beads_root_stat),
        "embeddedDataRootRelative": "embeddeddolt",
        "embeddedDataRootStat": _plain_copy(inputs.embedded_data_root_stat),
        "databaseName": inputs.database_name,
        "databaseRootRelative": f"embeddeddolt/{inputs.database_name}",
        "databaseRootStat": _plain_copy(inputs.database_root_stat),
        "databaseDoltRootStat": _plain_copy(inputs.database_dolt_root_stat),
        "executable": _plain_copy(inputs.executable),
        "immutableFiles": _plain_copy(inputs.immutable_files),
        "metadata": _plain_copy(inputs.metadata),
        "statusProfilePayloadSha256": inputs.status_profile_payload_sha256,
        "statusProfileStaticBindingsSha256": inputs.status_profile_static_bindings_sha256,
        "statusProfileDerivationPolicySha256": inputs.status_profile_derivation_policy_sha256,
        "statusProfileDynamicBindingsSha256": inputs.status_profile_dynamic_bindings_sha256,
        "statusProfileExpectedBindingsSha256": inputs.status_profile_expected_bindings_sha256,
        "derivationJournalHeadSha256": inputs.derivation_journal_head_sha256,
        "runtimeApiManifestSha256": inputs.runtime_api_manifest_sha256,
        "releaseManifestSha256": inputs.release_manifest_sha256,
        "genericStatusConfigSha256": inputs.generic_status_config_sha256,
        "preStoreObservationSha256": inputs.pre_store_observation_sha256,
        "postStoreObservationSha256": inputs.post_store_observation_sha256,
        "storeStateSha256": inputs.store_state_sha256,
        "configEnvelopeCanonicalSha256": inputs.config_envelope_canonical_sha256,
        "cleanupObservationSha256": inputs.cleanup_observation_sha256,
        "preparationPlanSha256": inputs.preparation_plan_sha256,
        "authorityEpoch": inputs.authority_epoch,
        "predecessorPreparedStorePayloadSha256": inputs.predecessor_prepared_store_payload_sha256,
        "lastTouchedPolicy": {
            "relativePath": "last-touched",
            "absentAllowed": True,
            "presentMode": "0600",
            "maximumBytes": 129,
            "exactMutationPostcondition": "TARGET_ID_LF",
        },
        _CANDIDATE_FIELD: candidate.payload,
        _CANDIDATE_DIGEST_FIELD: candidate.plan_sha256,
    }


def build_prepared_beads_store_payload_v1(
    inputs: PreparedBeadsStorePayloadInputsV1,
) -> bytes:
    """Build the closed canonical unsigned payload consumed by task 3."""

    payload = _payload_from_inputs(inputs)
    _validate_prepared_object(payload)
    encoded = _canonical_bytes(payload)
    if len(encoded) > _MAX_PREPARED_PAYLOAD_BYTES:
        raise _BeadsContractError("prepared payload exceeds 32768 bytes")
    return encoded


def _validate_expected_bindings(
    payload: Mapping[str, Any],
    expected: PreparedBeadsStoreExpectedBindingsV1,
    payload_sha256: str,
) -> None:
    if type(expected) is not PreparedBeadsStoreExpectedBindingsV1:
        raise _BeadsContractError("prepared payload validator requires typed expected bindings")
    projection = {
        "preparation_mode": payload["preparationMode"],
        "repository_locator_sha256": payload["repositoryLocatorSha256"],
        "project_root_locator_sha256": payload["projectRootLocatorSha256"],
        "beads_root_locator_sha256": payload["beadsRootLocatorSha256"],
        "database_name": payload["databaseName"],
        "metadata_sha256": payload["metadata"]["sha256"],
        "status_profile_payload_sha256": payload["statusProfilePayloadSha256"],
        "status_profile_static_bindings_sha256": payload["statusProfileStaticBindingsSha256"],
        "status_profile_derivation_policy_sha256": payload["statusProfileDerivationPolicySha256"],
        "status_profile_dynamic_bindings_sha256": payload["statusProfileDynamicBindingsSha256"],
        "status_profile_expected_bindings_sha256": payload["statusProfileExpectedBindingsSha256"],
        "derivation_journal_head_sha256": payload["derivationJournalHeadSha256"],
        "runtime_api_manifest_sha256": payload["runtimeApiManifestSha256"],
        "release_manifest_sha256": payload["releaseManifestSha256"],
        "generic_status_config_sha256": payload["genericStatusConfigSha256"],
        "pre_store_observation_sha256": payload["preStoreObservationSha256"],
        "post_store_observation_sha256": payload["postStoreObservationSha256"],
        "store_state_sha256": payload["storeStateSha256"],
        "config_envelope_canonical_sha256": payload["configEnvelopeCanonicalSha256"],
        "cleanup_observation_sha256": payload["cleanupObservationSha256"],
        "preparation_plan_sha256": payload["preparationPlanSha256"],
        "authority_epoch": payload["authorityEpoch"],
        "predecessor_prepared_store_payload_sha256": payload["predecessorPreparedStorePayloadSha256"],
        "read_back_plan_candidate_sha256": payload[_CANDIDATE_DIGEST_FIELD],
        "payload_sha256": payload_sha256,
    }
    expected_projection = {
        field.name: getattr(expected, field.name) for field in dataclasses.fields(expected)
    }
    if _canonical_bytes(projection) != _canonical_bytes(expected_projection):
        raise _BeadsContractError("prepared payload expected-binding mismatch")


def validate_prepared_beads_store_payload_v1(
    payload_canonical_bytes: bytes,
    expected: PreparedBeadsStoreExpectedBindingsV1,
) -> VerifiedPreparedBeadsStorePayloadV1:
    """Strictly parse canonical bytes and revalidate every unsigned binding."""

    payload = _parse_prepared_payload(payload_canonical_bytes)
    digest = "sha256:" + hashlib.sha256(
        _PREPARED_PAYLOAD_DOMAIN + payload_canonical_bytes
    ).hexdigest()
    _validate_expected_bindings(payload, expected, digest)
    return VerifiedPreparedBeadsStorePayloadV1(
        canonical_bytes=payload_canonical_bytes,
        payload_sha256=digest,
    )
