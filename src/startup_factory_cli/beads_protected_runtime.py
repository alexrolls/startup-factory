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

import dataclasses
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
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


def _request(value: _WireRecord, expected_name: str) -> dict[str, Any]:
    if type(value).__name__ != expected_name:
        raise BeadsProtectedRuntimeError(f"expected {expected_name}, received {type(value).__name__}")
    if value.auth is not None or value.record_sha256 is not None or value.full_bytes_sha256 is not None:
        raise BeadsProtectedRuntimeError("request objects cannot carry broker authentication fields")
    return _plain(value.payload)


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
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise BeadsProtectedRuntimeError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BeadsProtectedRuntimeError(f"{label} must be a non-symlink single-link regular file")
    if metadata.st_uid != os.getuid():
        raise BeadsProtectedRuntimeError(f"{label} must be owned by the broker uid")
    forbidden = 0o022 if executable else 0o077
    if stat.S_IMODE(metadata.st_mode) & forbidden:
        raise BeadsProtectedRuntimeError(f"{label} permissions are not protected")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= MAX_CANONICAL_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_CANONICAL_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > MAX_CANONICAL_BYTES or (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
        raise BeadsProtectedRuntimeError(f"{label} is oversized or changed while read")
    return bytes(data)


def _ensure_private_directory(path: Path, label: str, *, create: bool = False) -> None:
    if not path.is_absolute():
        raise BeadsProtectedRuntimeError(f"{label} must be absolute")
    if create and not path.exists():
        path.mkdir(mode=0o700)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 1:
        raise BeadsProtectedRuntimeError(f"{label} must be a non-symlink directory")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise BeadsProtectedRuntimeError(f"{label} must be broker-owned and mode 0700 or stricter")


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
        _ensure_private_directory(self.root, "protected root")
        if self.key_path.parent != self.root or not self.key_path.is_absolute():
            raise BeadsProtectedRuntimeError("HMAC key must be a direct protected-root child")
        self.key = _private_regular(self.key_path, "Beads protected-runtime HMAC key")
        if len(self.key) < 32 or len(self.key) > 4096:
            raise BeadsProtectedRuntimeError("Beads HMAC key must contain 32..4096 bytes")
        namespace = self.root / REPOSITORY_NAMESPACE
        if not namespace.exists():
            namespace.mkdir(mode=0o700)
        _ensure_private_directory(namespace, "Beads authority namespace")
        self.repository = namespace / repository_digest.removeprefix("sha256:")
        if not self.repository.exists():
            self.repository.mkdir(mode=0o700)
        _ensure_private_directory(self.repository, "Beads repository authority namespace")
        self.lock_path = self.repository / "repository.lock"

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
        for part in parts:
            current = _safe_join(current, part)
            if not current.exists():
                current.mkdir(mode=0o700)
            _ensure_private_directory(current, "protected record directory")
        return current

    def read_json(self, path: Path, label: str) -> dict[str, Any]:
        raw = _private_regular(path, label)
        try:
            value = json.loads(raw, parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise BeadsProtectedRuntimeError(f"{label} contains malformed JSON") from exc
        if not isinstance(value, dict) or canonical_bytes(value) != raw:
            raise BeadsProtectedRuntimeError(f"{label} is not exact canonical JSON")
        return value

    def write_immutable(self, path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
        encoded = canonical_bytes(value)
        if path.exists():
            if _private_regular(path, "existing protected record") != encoded:
                raise BeadsProtectedRuntimeError("immutable protected record collision")
            return
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def replace_current(self, path: Path, value: Mapping[str, Any], expected_full_digest: str | None) -> str:
        encoded = canonical_bytes(value)
        current_digest: str | None = None
        if path.exists():
            current_digest = sha256(_private_regular(path, "current protected record"))
        if current_digest != expected_full_digest:
            raise BeadsStaleAuthorityError("current protected authority predecessor changed")
        descriptor, temporary_name = tempfile.mkstemp(prefix=".current.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, encoded)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return sha256(encoded)


class _RepositoryLock:
    def __init__(self, store: _Store) -> None:
        self.store = store
        self.descriptor: int | None = None

    def __enter__(self) -> _Store:
        self.descriptor = os.open(
            self.store.lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
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


def _journal_record(store: _Store, kind: str, record_digest: str, full_digest: str) -> None:
    payload = {
        "recordKind": kind,
        "recordSha256": record_digest,
        "recordFullBytesSha256": full_digest,
        "repositoryLocatorSha256": store.repository_digest,
    }
    envelope, _, journal_digest, _ = store.sign("beads-protected-journal-entry", payload)
    path = store.directory("journals", "history") / f"{journal_digest.removeprefix('sha256:')}.json"
    store.write_immutable(path, envelope)


def _verify_journal(store: _Store, kind: str, record_digest: str, full_digest: str) -> None:
    payload = {
        "recordKind": kind,
        "recordSha256": record_digest,
        "recordFullBytesSha256": full_digest,
        "repositoryLocatorSha256": store.repository_digest,
    }
    _, _, journal_digest, _ = store.sign("beads-protected-journal-entry", payload)
    path = store.directory("journals", "history") / f"{journal_digest.removeprefix('sha256:')}.json"
    if not path.exists():
        raise BeadsProtectedRuntimeError("protected record has no exact HMAC journal entry")
    envelope = store.read_json(path, "protected HMAC journal entry")
    body, _, observed, _ = store.verify(envelope, "beads-protected-journal-entry")
    if observed != journal_digest or any(body.get(key) != value for key, value in payload.items()):
        raise BeadsProtectedRuntimeError("protected HMAC journal entry mismatch")


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
    if not path.exists():
        raise BeadsProtectedRuntimeError(f"no current {kind} exists")
    envelope = store.read_json(path, f"current {kind}")
    body, auth, record_digest, full_digest = store.verify(envelope, kind)
    history = store.directory(category, "history") / f"{record_digest.removeprefix('sha256:')}.json"
    if not history.exists() or canonical_bytes(store.read_json(history, f"{kind} history")) != canonical_bytes(envelope):
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
    value = {
        "schemaVersion": 1,
        "capabilityRecordSha256": capability.record_sha256,
        "transactionIntentSha256": intent_digest,
    }
    if consumed.exists():
        existing = store.read_json(consumed, "capability consumption record")
        if existing != value:
            raise BeadsCapabilityConsumedError("capability was consumed by another transaction")
        return
    store.write_immutable(consumed, value)


def _expiry(payload: Mapping[str, Any]) -> None:
    value = payload.get("expiresAtUnix")
    if not isinstance(value, int) or isinstance(value, bool) or value <= int(time.time()) or value > int(time.time()) + 31_536_000:
        raise BeadsProtectedRuntimeError("protected capability expiry is absent, expired or beyond one year")


def _same_repository(store: _Store, payload: Mapping[str, Any]) -> None:
    if payload.get("repositoryLocatorSha256") != store.repository_digest:
        raise BeadsProtectedRuntimeError("protected record repository identity mismatch")


def _transaction_intent(store: _Store, operation: str, payload: Mapping[str, Any]) -> tuple[str, Path]:
    operation_id = sha256(canonical_bytes({"operation": operation, "request": payload})).removeprefix("sha256:")
    directory = store.directory("transactions", operation_id)
    intent = {
        "schemaVersion": 1,
        "operation": operation,
        "requestSha256": sha256(canonical_bytes(payload)),
        "operationId": operation_id,
    }
    path = directory / "intent.json"
    store.write_immutable(path, intent)
    if store.read_json(path, "transaction intent") != intent:
        raise BeadsProtectedRuntimeError("transaction intent recovery mismatch")
    return sha256(canonical_bytes(intent)), directory


def _transaction_receipt(store: _Store, directory: Path, operation: str, result: _WireRecord) -> None:
    store.write_immutable(
        directory / "receipt.json",
        {
            "schemaVersion": 1,
            "operation": operation,
            "resultRecordSha256": result.record_sha256,
            "resultFullBytesSha256": result.full_bytes_sha256,
        },
    )


def _resume_transaction_result(
    store: _Store,
    directory: Path,
    operation: str,
    type_name: str,
    kind: str,
    category: str,
) -> _WireRecord | None:
    receipt_path = directory / "receipt.json"
    if not receipt_path.exists():
        return None
    receipt = store.read_json(receipt_path, "transaction receipt")
    if receipt.get("operation") != operation:
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
    if not current_path.exists():
        return None
    envelope = store.read_json(current_path, f"current {kind} recovery")
    body, auth, record_digest, full_digest = store.verify(envelope, kind)
    if body.get("transactionIntentSha256") != intent_digest:
        return None
    result = _record_result(type_name, body, auth, record_digest, full_digest)
    history = store.directory(category, "history") / f"{record_digest.removeprefix('sha256:')}.json"
    if not history.exists() or canonical_bytes(store.read_json(history, f"{kind} recovery history")) != canonical_bytes(envelope):
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
        authority = _current_authority(store, require_active=True)
        intent_digest, directory = _transaction_intent(store, "prepare-atomic-claim", payload)
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
        prior = _load_record(store, "AtomicClaimLeaseV1", "atomic-claim-lease", "claims", payload["leaseRecordSha256"])
        _expiry(prior.payload)
        _same_repository(store, prior.payload)
        if prior.payload.get("claimState") != "prepared":
            raise BeadsStaleAuthorityError("atomic claim lease is not in prepared state")
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
        return _signed_record(store, "AtomicClaimLeaseV1", "atomic-claim-lease", result_payload, "claims")


def record_atomic_claim_receipt_v1(request: RecordAtomicClaimReceiptRequestV1) -> AtomicClaimReceiptV1:
    payload = _request(request, "RecordAtomicClaimReceiptRequestV1")
    _required(payload, "leaseRecordSha256", "readBackRevision", "readBackStatus", "claimIdentitySha256")
    store = _Store(payload)
    with store.locked():
        lease = _load_record(store, "AtomicClaimLeaseV1", "atomic-claim-lease", "claims", payload["leaseRecordSha256"])
        _same_repository(store, lease.payload)
        if lease.payload.get("claimState") != "claimed":
            raise BeadsStaleAuthorityError("claim receipt requires a successful claimed lease")
        if payload["readBackRevision"] != lease.payload.get("observedRevision") or payload["readBackStatus"] != lease.payload.get("observedStatus"):
            raise BeadsStaleAuthorityError("claim read-back no longer matches the atomic observation")
        _digest(payload["claimIdentitySha256"], "claimIdentitySha256")
        return _signed_record(
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
            },
            "claim-receipts",
        )


def _current_authority(store: _Store, *, require_active: bool) -> _WireRecord:
    result = _load_current(store, "BeadsAuthorityEpochStateV1", "beads-authority-epoch-state", "authority")
    _same_repository(store, result.payload)
    if require_active and result.payload.get("authorityState") != "active":
        raise BeadsProtectedRuntimeError("ordinary Beads authority is not active")
    return result


def authorize_claim_launch_v1(request: AuthorizeClaimLaunchRequestV1) -> LaunchAuthorizationV1:
    payload = _request(request, "AuthorizeClaimLaunchRequestV1")
    _required(payload, "claimReceiptRecordSha256", "launchNonce", "expiresAtUnix")
    _identifier(payload["launchNonce"], "launchNonce")
    _expiry(payload)
    store = _Store(payload)
    with store.locked():
        receipt = _load_record(store, "AtomicClaimReceiptV1", "atomic-claim-receipt", "claim-receipts", payload["claimReceiptRecordSha256"])
        authority = _current_authority(store, require_active=True)
        return _signed_record(
            store,
            "LaunchAuthorizationV1",
            "claim-launch-authorization",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "claimReceiptRecordSha256": receipt.record_sha256,
                "activeAuthorityRecordSha256": authority.record_sha256,
                "launchNonce": payload["launchNonce"],
                "expiresAtUnix": payload["expiresAtUnix"],
            },
            "claim-launch",
        )


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
        binding: dict[str, Any]
        if mutation_class == "ordinary":
            authority = _current_authority(store, require_active=True)
            binding = {"activeAuthorityRecordSha256": authority.record_sha256}
        else:
            _required(payload, "preparationLeaseRecordSha256", "preparationCommandIntentRecordSha256")
            lease = _load_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", payload["preparationLeaseRecordSha256"])
            command = _load_record(store, "BeadsPreparationCommandIntentV1", "beads-preparation-command-intent", "preparation-commands", payload["preparationCommandIntentRecordSha256"])
            if command.payload.get("leaseRecordSha256") != lease.record_sha256:
                raise BeadsProtectedRuntimeError("preparation mutation command/lease chain mismatch")
            if tuple(payload["commandArgv"]) != tuple(command.payload.get("argv", ())):
                raise BeadsProtectedRuntimeError("preparation mutation argv differs from authorized command intent")
            binding = {
                "preparationLeaseRecordSha256": lease.record_sha256,
                "preparationCommandIntentRecordSha256": command.record_sha256,
                **_preparation_sequence_fields(lease.payload),
            }
        intent_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "mutationClass": mutation_class,
            "mutationNonce": payload["mutationNonce"],
            "argv": payload["commandArgv"],
            "argvSha256": sha256(canonical_bytes(payload["commandArgv"])),
            "expiresAtUnix": payload["expiresAtUnix"],
            **binding,
        }
        return _signed_record(store, "BeadsMutationIntentV1", "beads-mutation-intent", intent_payload, "mutation-intents")


def finish_beads_mutation_v1(request: FinishBeadsMutationRequestV1) -> BeadsMutationResultV1:
    payload = _request(request, "FinishBeadsMutationRequestV1")
    _required(payload, "mutationClass", "mutationIntentRecordSha256", "exitCode", "stdoutSha256", "stderrSha256", "readBackSha256")
    store = _Store(payload)
    with store.locked():
        intent = _load_record(store, "BeadsMutationIntentV1", "beads-mutation-intent", "mutation-intents", payload["mutationIntentRecordSha256"])
        _expiry(intent.payload)
        if payload["mutationClass"] != intent.payload.get("mutationClass"):
            raise BeadsProtectedRuntimeError("mutation result class differs from the protected intent")
        for field in ("stdoutSha256", "stderrSha256", "readBackSha256"):
            _digest(payload[field], field)
        if not isinstance(payload["exitCode"], int) or isinstance(payload["exitCode"], bool):
            raise BeadsProtectedRuntimeError("exitCode must be an integer")
        result_payload = {
            **{key: value for key, value in intent.payload.items() if key not in {"kind", "schemaVersion"}},
            "mutationIntentRecordSha256": intent.record_sha256,
            "exitCode": payload["exitCode"],
            "stdoutSha256": payload["stdoutSha256"],
            "stderrSha256": payload["stderrSha256"],
            "readBackSha256": payload["readBackSha256"],
        }
        return _signed_record(store, "BeadsMutationResultV1", "beads-mutation-result", result_payload, "mutation-results")


def _capture_directory(path: Path, label: str) -> dict[str, Any]:
    if not path.is_absolute():
        raise BeadsProtectedRuntimeError(f"{label} path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        candidate = current / part
        metadata = os.lstat(candidate)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BeadsProtectedRuntimeError(f"{label} contains a symlink or non-directory")
        current = candidate
    metadata = os.lstat(path)
    return {
        "pathSha256": sha256(os.fsencode(str(path))),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "owner": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "linkCount": metadata.st_nlink,
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
    _required(locator, "repositoryPath", "databaseName", "verifiedReceiptRecordSha256")
    if locator.get("repositoryLocatorSha256") != repository_digest:
        raise BeadsProtectedRuntimeError("installed selector authority locator repository mismatch")
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
    if payload["preparationMode"] == "create":
        _required(payload, "createStageDatabasePath", "executablePath")
        path_bindings = {
            "createStageDatabasePath": str(payload["createStageDatabasePath"]),
            "executablePath": str(payload["executablePath"]),
        }
    else:
        _required(payload, "installedSelectorPath", "selectedStorePath", "doltRootPath", "executablePath")
        path_bindings = {
            "installedSelectorPath": str(payload["installedSelectorPath"]),
            "selectedStorePath": str(payload["selectedStorePath"]),
            "doltRootPath": str(payload["doltRootPath"]),
            "executablePath": str(payload["executablePath"]),
        }
    store = _Store(payload)
    with store.locked():
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
        authorization = _load_record(
            store,
            "BeadsPreparationAuthorizationV1",
            "beads-preparation-authorization",
            "preparation-authorizations",
            payload["authorizationRecordSha256"],
        )
        _expiry(authorization.payload)
        _same_repository(store, authorization.payload)
        intent_digest, directory = _transaction_intent(store, "begin-beads-preparation", payload)
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


def _expected_preparation_command(lease: _WireRecord, command_kind: str, argv: Sequence[Any]) -> None:
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
    else:
        allowed = ("binary-proof", "initialize", "status-config-write", "status-config-readback")
        ordinal = lease.payload.get("nextCommandOrdinal")
        if not isinstance(ordinal, int) or ordinal >= len(allowed) or command_kind != allowed[ordinal]:
            raise BeadsProtectedRuntimeError("create preparation command is absent, repeated or out of order")
        stage_path = lease.payload.get("createStageDatabasePath")
        if not isinstance(stage_path, str) or stage_path not in argv:
            raise BeadsProtectedRuntimeError("create preparation argv must carry only its exact stage path")


def advance_beads_preparation_v1(request: AdvanceBeadsPreparationRequestV1) -> BeadsPreparationStepV1:
    payload = _request(request, "AdvanceBeadsPreparationRequestV1")
    _required(payload, "leaseRecordSha256", "commandOrdinal", "commandKind", "argv", "outcome", "stdoutSha256", "stderrSha256")
    store = _Store(payload)
    with store.locked():
        lease = _load_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", payload["leaseRecordSha256"])
        _expiry(lease.payload)
        _same_repository(store, lease.payload)
        if payload["commandOrdinal"] != lease.payload.get("nextCommandOrdinal"):
            raise BeadsStaleAuthorityError("preparation command ordinal is stale or non-contiguous")
        if payload["outcome"] not in {"succeeded", "failed", "outcome-uncertain"}:
            raise BeadsProtectedRuntimeError("preparation command outcome is unknown")
        _expected_preparation_command(lease, str(payload["commandKind"]), payload["argv"])
        for field in ("stdoutSha256", "stderrSha256"):
            _digest(payload[field], field)
        command_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "leaseRecordSha256": lease.record_sha256,
            "commandOrdinal": payload["commandOrdinal"],
            "commandKind": payload["commandKind"],
            "argv": payload["argv"],
            "argvSha256": sha256(canonical_bytes(payload["argv"])),
            **_preparation_sequence_fields(lease.payload),
        }
        command = _signed_record(store, "BeadsPreparationCommandIntentV1", "beads-preparation-command-intent", command_payload, "preparation-commands")
        base_step_payload = {
            **command_payload,
            "commandIntentRecordSha256": command.record_sha256,
            "outcome": payload["outcome"],
            "stdoutSha256": payload["stdoutSha256"],
            "stderrSha256": payload["stderrSha256"],
        }
        if payload["outcome"] != "succeeded":
            return _signed_record(store, "BeadsPreparationStepV1", "beads-preparation-step", base_step_payload, "preparation-steps")
        successor_payload = {
            **{key: value for key, value in lease.payload.items() if key not in {"kind", "schemaVersion", "nextCommandOrdinal", "preparationState"}},
            "predecessorLeaseRecordSha256": lease.record_sha256,
            "lastCommandIntentRecordSha256": command.record_sha256,
            "nextCommandOrdinal": payload["commandOrdinal"] + 1,
            "preparationState": "commands-complete" if (
                lease.payload.get("preparationMode") == "reattest" or payload["commandOrdinal"] == 3
            ) else "leased",
        }
        successor = _signed_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", successor_payload, "preparation-leases")
        return _signed_record(
            store,
            "BeadsPreparationStepV1",
            "beads-preparation-step",
            {**base_step_payload, "successorLeaseRecordSha256": successor.record_sha256},
            "preparation-steps",
        )


def observe_beads_store_v1(request: ObserveBeadsStoreRequestV1) -> BeadsStoreObservationV1:
    payload = _request(request, "ObserveBeadsStoreRequestV1")
    _required(payload, "leaseRecordSha256", "observationPhase", "stateProjection")
    if payload["observationPhase"] not in {"pre", "post"} or not isinstance(payload["stateProjection"], Mapping):
        raise BeadsProtectedRuntimeError("store observation phase/projection is invalid")
    store = _Store(payload)
    with store.locked():
        lease = _load_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", payload["leaseRecordSha256"])
        state = _validate_json(payload["stateProjection"])
        state_digest = sha256(canonical_bytes({"kind": "beads-store-state-projection", "schemaVersion": 1, **state}))
        observation_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "leaseRecordSha256": lease.record_sha256,
            "observationPhase": payload["observationPhase"],
            "stateProjection": state,
            "storeStateSha256": state_digest,
            "acceptedConfigEnvelopeSha256": payload.get("acceptedConfigEnvelopeSha256"),
            "predecessorObservationRecordSha256": payload.get("predecessorObservationRecordSha256"),
            **_preparation_sequence_fields(lease.payload),
        }
        if payload["observationPhase"] == "pre":
            if observation_payload["acceptedConfigEnvelopeSha256"] is not None or observation_payload["predecessorObservationRecordSha256"] is not None:
                raise BeadsProtectedRuntimeError("pre observation forbids config output and predecessor")
        else:
            _digest(observation_payload["acceptedConfigEnvelopeSha256"], "acceptedConfigEnvelopeSha256")
            predecessor = _load_record(store, "BeadsStoreObservationV1", "beads-store-observation", "store-observations", observation_payload["predecessorObservationRecordSha256"])
            if predecessor.payload.get("observationPhase") != "pre" or predecessor.payload.get("storeStateSha256") != state_digest:
                raise BeadsProtectedRuntimeError("post observation physical state differs from pre observation")
        return _signed_record(store, "BeadsStoreObservationV1", "beads-store-observation", observation_payload, "store-observations")


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
    if pre.payload.get("leaseRecordSha256") != lease.record_sha256 or post.payload.get("leaseRecordSha256") != lease.record_sha256:
        raise BeadsProtectedRuntimeError("dynamic binding observation/lease mismatch")
    if pre.payload.get("observationPhase") != "pre" or post.payload.get("observationPhase") != "post":
        raise BeadsProtectedRuntimeError("dynamic binding observations are out of order")
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
        lease = _load_record(store, "BeadsPreparationLeaseV1", "beads-preparation-lease", "preparation-leases", payload["leaseRecordSha256"])
        if lease.payload.get("preparationState") != "commands-complete":
            raise BeadsProtectedRuntimeError("preparation cannot finish before its exact command sequence completes")
        pre = _load_record(store, "BeadsStoreObservationV1", "beads-store-observation", "store-observations", payload["preObservationRecordSha256"])
        post = _load_record(store, "BeadsStoreObservationV1", "beads-store-observation", "store-observations", payload["postObservationRecordSha256"])
        dynamic = derive_beads_status_profile_dynamic_bindings_v1(
            lease,
            pre,
            post,
            str(post.payload.get("acceptedConfigEnvelopeSha256")),
        )
        if canonical_bytes(dynamic.payload) != dynamic_bytes:
            raise BeadsProtectedRuntimeError("task-#2 dynamic binding bytes differ from task-#3 derivation")
        generation = 1
        current_path = store.directory("preparation-current") / "current.json"
        if current_path.exists():
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
                "resultStoredJournalHeadSha256": sha256(canonical_bytes({"lease": lease.record_sha256, "pre": pre.record_sha256, "post": post.record_sha256})),
                **_preparation_sequence_fields(lease.payload),
            },
            "preparation-results",
        )
        pointer_payload = {
            "repositoryLocatorSha256": store.repository_digest,
            "generation": generation,
            "predecessorCurrentFullBytesSha256": expected_current,
            "resultRecordSha256": prepared_record.record_sha256,
            "resultStoredJournalHeadSha256": prepared_record.payload["resultStoredJournalHeadSha256"],
            "statusProfileRecordSha256": status_record.record_sha256,
            "leaseRecordSha256": lease.record_sha256,
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
                "resultStoredJournalHeadSha256": prepared_record.payload["resultStoredJournalHeadSha256"],
                "statusProfileRecordSha256": status_record.record_sha256,
                **_preparation_sequence_fields(lease.payload),
            },
            "preparation-activation-receipts",
        )
        result_body = {
            **{key: value for key, value in prepared_record.payload.items() if key not in {"kind", "schemaVersion"}},
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


def _verify_preparation_pointer(store: _Store, pointer: _WireRecord, *, historical: bool) -> _WireRecord:
    result = _load_record(store, "FinishBeadsPreparationResultV1", "beads-preparation-result", "preparation-results", pointer.payload["resultRecordSha256"])
    activation_records = store.directory("preparation-activation-receipts", "history")
    matches: list[_WireRecord] = []
    for path in sorted(activation_records.glob("*.json")):
        envelope = store.read_json(path, "preparation activation receipt")
        body, auth, record_digest, full_digest = store.verify(envelope, "beads-preparation-activation-receipt")
        if body.get("pointerRecordSha256") == pointer.record_sha256:
            matches.append(_record_result("BeadsPreparationActivationReceiptV1", body, auth, record_digest, full_digest))
    if len(matches) != 1 or matches[0].payload.get("resultRecordSha256") != result.record_sha256:
        raise BeadsProtectedRuntimeError("preparation pointer has no unique exact activation receipt")
    verified_type = "VerifiedHistoricalBeadsPreparationV1" if historical else "VerifiedCurrentBeadsPreparationV1"
    verified_payload = {
        "repositoryLocatorSha256": store.repository_digest,
        "pointerRecordSha256": pointer.record_sha256,
        "pointerFullBytesSha256": pointer.full_bytes_sha256,
        "resultRecordSha256": result.record_sha256,
        "activationReceiptRecordSha256": matches[0].record_sha256,
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
    _required(payload, "bootstrapChangeKind", "adapterChangeKind", "remediationEvidenceSha256")
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
        _transaction_receipt(store, directory, "record-beads-change-plan-core", result)
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
            "candidate": payload.get("candidate"),
            **sequence,
        }
        return _signed_record(
            store,
            "BeadsAuthorityTransitionAuthorizationV1",
            "beads-authority-transition-authorization",
            authorization_payload,
            "authority-transition-authorizations",
        )


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
        current: _WireRecord | None = None
        try:
            current = _current_authority(store, require_active=False)
        except BeadsProtectedRuntimeError as exc:
            if "no current" not in str(exc):
                raise
        if (current.full_bytes_sha256 if current else None) != authorization.payload.get("expectedCurrentFullBytesSha256"):
            raise BeadsStaleAuthorityError("authority current changed after transition authorization")
        if expected_state is None:
            if current is not None and current.payload.get("authorityState") not in {"active", "pending", "revoked"}:
                raise BeadsProtectedRuntimeError("authority state is unknown")
        elif current is None or current.payload.get("authorityState") != expected_state:
            raise BeadsProtectedRuntimeError(f"{command} requires {expected_state} authority")
        intent_digest, directory = _transaction_intent(store, f"{command}-beads-authority", payload)
        _consume_capability(store, "authority-transition-authorizations", authorization, intent_digest)
        generation = 1 if current is None else _generation(current.payload.get("generation")) + 1
        _generation(generation)
        candidate = authorization.payload.get("candidate")
        if command in {"stage", "activate"}:
            if not isinstance(candidate, Mapping):
                raise BeadsProtectedRuntimeError(f"{command} requires an authority candidate")
            for field in ("preparationPointerRecordSha256", "adapterReleaseManifestRecordSha256", "runtimeApiManifestRecordSha256"):
                _digest(candidate.get(field), field)
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
        receipt = _signed_record(
            store,
            "BeadsAuthorityTransitionReceiptV1",
            "beads-authority-transition-receipt",
            {
                "repositoryLocatorSha256": store.repository_digest,
                "command": command,
                "authorizationRecordSha256": authorization.record_sha256,
                "authorityStateRecordSha256": state.record_sha256,
                "authorityStateFullBytesSha256": state.full_bytes_sha256,
                "predecessorCurrentFullBytesSha256": current.full_bytes_sha256 if current else None,
                "candidate": candidate,
                **_preparation_sequence_fields(authorization.payload),
            },
            "authority-transition-receipts",
        )
        _transaction_receipt(store, directory, f"{command}-beads-authority", receipt)
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
        _load_record(store, "BeadsAuthorityEpochStateV1", "beads-authority-epoch-state", "authority", receipt.payload["authorityStateRecordSha256"])
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
    if not isinstance(payload["runtimeTransactionAuthorityBinding"], Mapping):
        raise BeadsProtectedRuntimeError("runtime manifest requires a direct transaction authority binding")
    store = _Store(payload)
    with store.locked():
        authority = _current_authority(store, require_active=False)
        if authority.payload.get("authorityState") != "revoked":
            raise BeadsProtectedRuntimeError("runtime API manifest recording requires revoked authority")
        current_path = store.directory("runtime-api-manifests") / "current.json"
        current_digest = sha256(_private_regular(current_path, "current runtime manifest")) if current_path.exists() else None
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
                "runtimeTransactionAuthorityBinding": payload["runtimeTransactionAuthorityBinding"],
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
        _expiry(protected_capability.payload)
        authority = _current_authority(store, require_active=False)
        if authority.payload.get("authorityState") != "revoked" or authority.record_sha256 != protected_capability.payload.get("revokedAuthorityRecordSha256"):
            raise BeadsStaleAuthorityError("runtime manifest capability no longer binds current revoked authority")
        if protected_capability.payload.get("bootstrapRuntimeCoreSha256") != payload["bootstrapRuntimeCoreSha256"]:
            raise BeadsProtectedRuntimeError("runtime manifest bootstrap core differs from capability")
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
        _consume_capability(store, "runtime-api-manifest-capabilities", protected_capability, intent_digest)
        _fault("runtime-manifest-capability-consumed")
        current_path = store.directory("runtime-api-manifests") / "current.json"
        generation = 1
        if current_path.exists():
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
        current_path = store.directory("adapter-release-manifests") / "current.json"
        current_digest = sha256(_private_regular(current_path, "current adapter release manifest")) if current_path.exists() else None
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
    )
    for field in ("bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256", "adapterPayloadSha256", "releaseIdentitySha256"):
        _digest(payload[field], field)
    observations = payload["runtimeManifestObservations"]
    if not isinstance(observations, list) or len(observations) != 3:
        raise BeadsProtectedRuntimeError("adapter release requires exact A/B/C runtime manifest observations")
    for index, observation in enumerate(observations):
        if not isinstance(observation, Mapping):
            raise BeadsProtectedRuntimeError("runtime manifest observation is malformed")
        for field in ("bootstrapRuntimeCoreSha256", "adapterPayloadSha256", "remediationEvidenceSha256"):
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
        _expiry(protected_capability.payload)
        authority = _current_authority(store, require_active=False)
        if authority.payload.get("authorityState") != "revoked" or authority.record_sha256 != protected_capability.payload.get("revokedAuthorityRecordSha256"):
            raise BeadsStaleAuthorityError("adapter release capability no longer binds current revoked authority")
        for field in ("bootstrapRuntimeCoreSha256", "adapterReleaseCoreSha256", "runtimeApiManifestRecordSha256"):
            if protected_capability.payload.get(field) != payload[field]:
                raise BeadsProtectedRuntimeError(f"adapter release capability {field} mismatch")
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
        _consume_capability(store, "adapter-release-manifest-capabilities", protected_capability, intent_digest)
        _fault("adapter-release-capability-consumed")
        current_path = store.directory("adapter-release-manifests") / "current.json"
        generation = 1
        if current_path.exists():
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
