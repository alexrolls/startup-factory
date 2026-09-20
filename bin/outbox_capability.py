#!/usr/bin/env python3
"""Mint and verify short-lived producer capabilities for the tracker outbox.

Signing secrets remain broker-side. Launched workers receive only a non-secret
locator for their generation-bound publication supervisor. A real OS sandbox
must keep broker and lifecycle state unreadable and unwritable while allowing
only connect access to that one socket; Unix modes alone are not a same-UID
isolation boundary.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


CAPABILITY_ID = re.compile(r"cap-[0-9a-f]{32}")
SIGNATURE = re.compile(r"hmac-sha256:[0-9a-f]{64}")
BODY_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ROLE = re.compile(r"[a-z0-9-]{2,80}")
DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_TRANSPORT_REQUEST_BYTES = 192 * 1024
MAX_TRANSPORT_RESPONSE_BYTES = 16 * 1024
TRANSPORT_TIMEOUT_SECONDS = 10
_AUTHORITY_LOCK_OWNERS: set[tuple[str, int]] = set()

# The worker-authored artifact envelope is intentionally closed.  Broker-owned
# delivery state is added only after the immutable producer package has been
# admitted and copied into protected Git-common state.
OUTBOX_PRODUCER_FIELDS = {
    "schemaVersion",
    "id",
    "team",
    "featureId",
    "taskId",
    "attempt",
    "actor",
    "marker",
    "bodyPath",
    "targetStatus",
    "phase",
    "createdAt",
}
OUTBOX_CAPABILITY_FIELD = "producerCapability"
OUTBOX_BROKER_FIELDS = {
    "brokerSchemaVersion",
    "deliveryId",
    "brokerAssignedAt",
    "sourceEntryPath",
    "sourceEntrySha256",
    "stagedBodyPath",
    "stagedBodySha256",
    "publishBodyPath",
    "publishBodySha256",
    "reviewBinding",
    "brokerPhase",
}
WORKER_CONTROL_FIELDS = {
    "schemaVersion", "id", "team", "featureId", "taskId", "attempt", "actor",
    "marker", "targetStatus", "createdAt", "expiresAt", "action", "targetRole",
    "observedLifecycleCreatedAt", "observedTaskRevision", "observedTaskStatus",
    "observedExecutionSha256", "observedClaimSha256", "priorNudgeControlId",
    "reasonCode", "controlBodySha256",
}
LINEAGE_MIGRATION_FIELDS = {
    "schemaVersion", "id", "team", "featureId", "taskId", "taskKey", "actor",
    "authorizationTaskId", "authorizationTaskRevision", "authorizationTaskStatus",
    "contractRegistrySha256", "contractEntrySha256", "marker", "createdAt",
    "expiresAt", "observedLifecycleCreatedAt", "observedTaskRevision",
    "observedTaskStatus", "observedExecutionSha256", "observedClaimSha256",
    "branch", "worktree", "head", "packetPath", "packetSha256",
    "packetJsonPath", "packetJsonSha256", "reportPath", "reportSha256",
    "controlBodySha256",
}


class CapabilityError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CapabilityError("JSON object contains duplicate key %s" % key)
        value[key] = item
    return value


def strict_json(raw: bytes | str, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CapabilityError("invalid %s" % label) from exc


def _safe_text(value: Any, label: str, maximum: int = 1024) -> str:
    text = str(value or "")
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise CapabilityError("invalid %s" % label)
    return text


def _repo(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise CapabilityError("canonical repository path must be absolute")
    try:
        lexical = Path(os.path.abspath(candidate))
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CapabilityError("canonical repository is unavailable: %s" % exc) from exc
    if lexical != resolved or not resolved.is_dir():
        raise CapabilityError("canonical repository must be a non-symlink directory")
    try:
        top = subprocess.run(
            ["git", "-C", str(resolved), "rev-parse", "--show-toplevel"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CapabilityError("canonical repository is not a Git worktree") from exc
    if Path(top).resolve() != resolved:
        raise CapabilityError("canonical repository does not equal its Git toplevel")
    return resolved


def git_common_dir(repository: str | Path) -> Path:
    repo = _repo(repository)
    try:
        raw = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--git-common-dir"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CapabilityError("cannot resolve Git common directory") from exc
    common = Path(raw)
    if not common.is_absolute():
        common = repo / common
    try:
        common = common.resolve(strict=True)
    except OSError as exc:
        raise CapabilityError("Git common directory is unavailable: %s" % exc) from exc
    if not common.is_dir():
        raise CapabilityError("Git common directory is not a directory")
    return common


def _protected_dir(path: Path) -> Path:
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise CapabilityError("broker capability state contains an unsafe path")
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise CapabilityError("broker capability state must be owner-only")
    else:
        path.mkdir(mode=0o700)
    return path


def state_directories(repository: str | Path) -> tuple[Path, Path, Path]:
    common = git_common_dir(repository)
    broker = _protected_dir(common / "startup-factory-broker")
    records = _protected_dir(broker / "outbox-capabilities")
    active = _protected_dir(broker / "outbox-active")
    revoked = _protected_dir(broker / "outbox-revoked")
    return records, active, revoked


def admission_directory(repository: str | Path) -> Path:
    """Return the protected durable-admission receipt directory."""
    common = git_common_dir(repository)
    broker = _protected_dir(common / "startup-factory-broker")
    return _protected_dir(broker / "outbox-admissions")


def delivery_directory(
    repository: str | Path, workspace: str | Path, team: str, feature: str
) -> Path:
    """Return protected broker storage for one exact team/feature workspace.

    The opaque scope name avoids placing tracker identifiers in filesystem
    paths.  This location is outside every linked worktree and is deliberately
    inaccessible to a correctly configured worker sandbox.
    """
    repo = _repo(repository)
    workspace_path = Path(workspace)
    if not workspace_path.is_absolute():
        raise CapabilityError("canonical workspace path must be absolute")
    workspace_real = Path(os.path.realpath(workspace_path))
    if workspace_real != workspace_path or not workspace_real.is_dir():
        raise CapabilityError("canonical workspace must be a non-symlink directory")
    _safe_text(team, "team", 63)
    _safe_text(feature, "featureId")
    common = git_common_dir(repo)
    broker = _protected_dir(common / "startup-factory-broker")
    root = _protected_dir(broker / "outbox-deliveries")
    scope = hashlib.sha256(
        _canonical(
            {
                "repository": str(repo),
                "workspace": str(workspace_real),
                "team": team,
                "featureId": feature,
            }
        )
    ).hexdigest()
    return _protected_dir(root / scope)


def producer_envelope(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Project the complete immutable producer-authored envelope.

    Broker progression fields are permitted only as one complete closed set.
    Their values are never covered by producer authority; they live in
    protected state and are separately checked at the effect boundary.
    """
    if not isinstance(entry, dict):
        raise CapabilityError("producer entry must be an object")
    fields = set(entry)
    broker_present = bool(fields & OUTBOX_BROKER_FIELDS)
    signed_fields = OUTBOX_PRODUCER_FIELDS | {OUTBOX_CAPABILITY_FIELD}
    if broker_present:
        if fields != signed_fields | OUTBOX_BROKER_FIELDS:
            raise CapabilityError("broker delivery has unexpected or missing fields")
        if entry.get("brokerSchemaVersion") != 1:
            raise CapabilityError("unsupported broker delivery schema")
    elif fields != OUTBOX_PRODUCER_FIELDS and fields != signed_fields:
        raise CapabilityError("producer entry has unexpected or missing fields")

    projected = {name: entry.get(name) for name in OUTBOX_PRODUCER_FIELDS}
    if entry.get("schemaVersion") != 1 or entry.get("phase") != "pending":
        raise CapabilityError("producer entry has an unsupported schema or phase")
    for name, maximum in (
        ("id", 128),
        ("team", 63),
        ("featureId", 1024),
        ("taskId", 1024),
        ("actor", 80),
        ("marker", 80),
        ("bodyPath", 4096),
        ("createdAt", 128),
    ):
        _safe_text(projected.get(name), "entry %s" % name, maximum)
    if not ROLE.fullmatch(str(projected["actor"])):
        raise CapabilityError("invalid entry actor")
    if not re.fullmatch(r"[a-z0-9-]{2,80}", str(projected["marker"])):
        raise CapabilityError("invalid entry marker")
    attempt = projected.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise CapabilityError("entry attempt must be a positive integer")
    target = projected.get("targetStatus")
    if target is not None:
        _safe_text(target, "entry targetStatus", 128)
    body_path = Path(str(projected["bodyPath"]))
    if not body_path.is_absolute() or Path(os.path.abspath(body_path)) != body_path:
        raise CapabilityError("producer body path must be absolute and normalized")
    return projected


def control_envelope(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Validate one of the two closed broker-control producer schemas."""

    if not isinstance(entry, dict):
        raise CapabilityError("control entry must be an object")
    fields = set(entry) - {OUTBOX_CAPABILITY_FIELD}
    if fields == WORKER_CONTROL_FIELDS:
        marker = "worker-control"
        identifier = r"control-[0-9a-f]{32}"
    elif fields == LINEAGE_MIGRATION_FIELDS:
        marker = "lineage-migration"
        identifier = r"control-[0-9a-f]{32}"
    else:
        raise CapabilityError("control entry has unexpected or missing fields")
    projected = {name: entry.get(name) for name in fields}
    if projected.get("schemaVersion") != 1 or projected.get("marker") != marker:
        raise CapabilityError("control entry has an unsupported schema or marker")
    if not re.fullmatch(identifier, str(projected.get("id") or "")):
        raise CapabilityError("control entry has an invalid identity")
    for name, maximum in (
        ("team", 63), ("featureId", 1024), ("taskId", 1024), ("actor", 80),
    ):
        _safe_text(projected.get(name), "control %s" % name, maximum)
    if not ROLE.fullmatch(str(projected["actor"])):
        raise CapabilityError("invalid control actor")
    for name in ("createdAt", "expiresAt"):
        value = projected.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise CapabilityError("control entry has an invalid %s" % name)
    return projected


def _entry_for_signature(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return every producer-authored field, excluding only the signature."""
    if (set(entry) & OUTBOX_BROKER_FIELDS) or {"bodyPath", "phase"}.intersection(entry):
        return producer_envelope(entry)
    return control_envelope(entry)


@contextmanager
def authority_lock(repository: str | Path):
    common = git_common_dir(repository)
    broker = _protected_dir(common / "startup-factory-broker")
    path = broker / "outbox-authority.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CapabilityError("cannot open capability identity lock") from exc
    try:
        info = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or named.st_dev != info.st_dev
            or named.st_ino != info.st_ino
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise CapabilityError("capability authority lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        owner = (str(common), threading.get_ident())
        if owner in _AUTHORITY_LOCK_OWNERS:
            raise CapabilityError("capability authority lock is not reentrant")
        _AUTHORITY_LOCK_OWNERS.add(owner)
        try:
            yield
        finally:
            _AUTHORITY_LOCK_OWNERS.discard(owner)
    except OSError as exc:
        raise CapabilityError("capability authority lock failed") from exc
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def require_authority_lock(repository: str | Path) -> None:
    """Reject a broker-locked fast path unless this thread owns that lock."""

    common = git_common_dir(repository)
    if (str(common), threading.get_ident()) not in _AUTHORITY_LOCK_OWNERS:
        raise CapabilityError("broker-locked verification requires the authority lock")


def _write_exclusive(path: Path, content: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CapabilityError("cannot open broker state directory") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise CapabilityError("cannot persist broker state directory") from exc
    finally:
        os.close(descriptor)


def _replace_owner_only(path: Path, content: bytes) -> None:
    temporary = path.with_name(".%s.tmp.%s.%s" % (path.name, os.getpid(), secrets.token_hex(8)))
    try:
        _write_exclusive(temporary, content)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _revocation_tombstone(revoked: Path, capability_id: str) -> Path:
    """Path of the durable marker proving one capability was explicitly revoked.

    Revocation and supersession both clear a capability's active pointer, so the
    pointer alone cannot distinguish them once any later mint recreates it.  The
    tombstone records the revoked identity itself, which no subsequent mint can
    reproduce: capability ids are unique per mint.
    """
    return revoked / (capability_id + ".revoked")


def _record_revocation(revoked: Path, capability_id: str) -> None:
    if not CAPABILITY_ID.fullmatch(capability_id):
        raise CapabilityError("cannot revoke an invalid capability identity")
    _replace_owner_only(
        _revocation_tombstone(revoked, capability_id),
        (capability_id + "\n").encode("ascii"),
    )


def _revoke_matching_records(records: Path, revoked: Path, matches) -> None:
    """Tombstone every capability ever minted for the identity being revoked.

    An active pointer names only the newest capability, so revoking through it
    would miss earlier ones that a relaunch had already superseded -- exactly
    the capabilities most likely to be holding an undrained artifact. Records
    are immutable and never deleted, so they are the complete set. A capability
    minted after this call gets a fresh id that no tombstone names, which is
    what lets a revoke-then-relaunch restart keep working.
    """
    try:
        entries = sorted(records.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise CapabilityError("cannot enumerate capability records: %s" % exc) from exc
    for path in entries:
        if not path.name.endswith(".json"):
            continue
        # An individual unreadable record must not abort the revocation.  This
        # directory is append-only for the life of the repository, so one
        # truncated record -- what a crash during mint() leaves behind -- would
        # otherwise permanently break every revoke, and with it the
        # revoke-then-relaunch restart path for every role and team sharing the
        # repository.  Skipping is safe rather than lenient: verification reads
        # the same record through the same helper, so a record that cannot be
        # read here cannot authenticate anything there either.
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                continue
            record = json.loads(_read_protected(path, "capability record"))
        except (CapabilityError, OSError, UnicodeError, ValueError):
            continue
        if not isinstance(record, dict):
            continue
        capability_id = record.get("id")
        if not isinstance(capability_id, str) or path.name != capability_id + ".json":
            continue
        if matches(record):
            _record_revocation(revoked, capability_id)


def _is_revoked(revoked: Path, capability_id: str) -> bool:
    """Report whether an explicit revocation tombstone exists.

    Any unreadable, non-regular, group/world-accessible, or mismatched
    tombstone is treated as a revocation: a capability whose revocation
    evidence cannot be trusted must not publish.
    """
    path = _revocation_tombstone(revoked, capability_id)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CapabilityError("cannot inspect capability revocation: %s" % exc) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise CapabilityError("capability revocation must be a non-symlink regular file")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise CapabilityError("capability revocation must be owner-only")
    return True


def _active_key(record: Dict[str, Any]) -> str:
    # One pointer represents one logical publication lane.  Task relaunches
    # may change role, attempt, and process instance, but they must still fence
    # every predecessor for that task.  Gate lanes are stable per concrete
    # review role.  Process-generation values belong in the immutable record,
    # never in the pointer identity.
    identity = {
        "repository": record["canonicalRepo"],
        "workspace": record["canonicalWorkspace"],
        "team": record["team"],
        "featureId": record["featureId"],
        "executionKind": record["executionKind"],
    }
    if record["executionKind"] == "task":
        identity["taskId"] = record["taskId"]
    elif record["executionKind"] == "gate":
        identity["role"] = record["role"]
    else:
        raise CapabilityError("invalid capability execution kind")
    return hashlib.sha256(_canonical(identity)).hexdigest()


def mint(
    repository: str,
    workspace: str,
    team: str,
    feature: str,
    role: str,
    execution_kind: str,
    task: str,
    attempt: int,
    instance: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> Dict[str, Any]:
    repo = _repo(repository)
    workspace_path = Path(workspace)
    if not workspace_path.is_absolute():
        raise CapabilityError("canonical workspace path must be absolute")
    workspace_real = Path(os.path.realpath(workspace_path))
    if workspace_real != workspace_path or not workspace_real.is_dir():
        raise CapabilityError("canonical workspace must be a non-symlink directory")
    try:
        if os.path.commonpath([str(repo), str(workspace_real)]) != str(repo):
            raise CapabilityError("canonical workspace escapes canonical repository")
    except ValueError as exc:
        raise CapabilityError("canonical workspace escapes canonical repository") from exc
    _safe_text(team, "team", 63)
    _safe_text(feature, "featureId")
    if not ROLE.fullmatch(role):
        raise CapabilityError("invalid capability role")
    if execution_kind not in {"gate", "task"}:
        raise CapabilityError("invalid execution kind")
    _safe_text(task, "taskId")
    _safe_text(instance, "instance", 256)
    if isinstance(attempt, bool) or attempt < 0:
        raise CapabilityError("invalid capability attempt")
    if execution_kind == "gate" and (task != "-" or attempt != 0):
        raise CapabilityError("gate capability must use task '-' and attempt 0")
    if execution_kind == "task" and attempt < 1:
        raise CapabilityError("task capability attempt must be positive")
    if ttl_seconds < 60 or ttl_seconds > 7 * 24 * 60 * 60:
        raise CapabilityError("capability TTL must be between 60 seconds and 7 days")

    records, active, _revoked = state_directories(repo)
    issued = int(time.time())
    capability_id = "cap-" + secrets.token_hex(16)
    secret = secrets.token_hex(32)
    record: Dict[str, Any] = {
        "schemaVersion": 1,
        "id": capability_id,
        "secret": secret,
        "canonicalRepo": str(repo),
        "canonicalWorkspace": str(workspace_real),
        "team": team,
        "featureId": feature,
        "role": role,
        "executionKind": execution_kind,
        "taskId": task,
        "attempt": attempt,
        "instance": instance,
        "issuedAt": issued,
        "expiresAt": issued + ttl_seconds,
        "issuedAtUtc": datetime.fromtimestamp(issued, timezone.utc).isoformat(timespec="seconds"),
    }
    record_path = records / (capability_id + ".json")
    active_path = active / (_active_key(record) + ".id")
    with authority_lock(repo):
        # The immutable record and the pointer that makes it authoritative are
        # one broker transaction.  No verifier can observe an active id before
        # its durable record, and no concurrent mint can interleave between
        # record publication and lane supersession.
        _write_exclusive(record_path, _canonical(record) + b"\n")
        _fsync_directory(records)
        _replace_owner_only(active_path, (capability_id + "\n").encode("ascii"))
        _fsync_directory(active)
    return {
        "id": capability_id,
        "secret": secret,
        "instance": instance,
        "expiresAt": record["expiresAt"],
    }


def signed_material(
    entry: Dict[str, Any], capability: Dict[str, Any], body_digest: str, actor: str
) -> Dict[str, Any]:
    envelope = _entry_for_signature(entry)
    return {
        "schemaVersion": 1,
        "capabilityId": capability["id"],
        "capabilityInstance": capability["instance"],
        "capabilityExpiresAt": capability["expiresAt"],
        "entrySha256": "sha256:" + hashlib.sha256(_canonical(envelope)).hexdigest(),
        "actor": actor,
        "bodySha256": body_digest,
    }


def sign_entry(
    entry: Dict[str, Any], body: bytes, capability_id: str, secret: str,
    instance: str, expires_at: int,
) -> Dict[str, Any]:
    if not CAPABILITY_ID.fullmatch(capability_id):
        raise CapabilityError("invalid producer capability id")
    if not re.fullmatch(r"[0-9a-f]{64}", secret):
        raise CapabilityError("invalid producer capability secret")
    _safe_text(instance, "capability instance", 256)
    if isinstance(expires_at, bool) or expires_at <= 0:
        raise CapabilityError("invalid producer capability expiry")
    body_digest = "sha256:" + hashlib.sha256(body).hexdigest()
    capability: Dict[str, Any] = {
        "schemaVersion": 1,
        "id": capability_id,
        "instance": instance,
        "expiresAt": expires_at,
        "bodySha256": body_digest,
    }
    material = signed_material(entry, capability, body_digest, str(entry.get("actor") or ""))
    capability["signature"] = "hmac-sha256:" + hmac.new(
        bytes.fromhex(secret), _canonical(material), hashlib.sha256
    ).hexdigest()
    return capability


def _admission_binding(
    record: Dict[str, Any], entry: Dict[str, Any], capability: Dict[str, Any],
    body_digest: str,
) -> Dict[str, Any]:
    role = str(record.get("role") or "")
    signed = signed_material(entry, capability, body_digest, role)
    return {
        "schemaVersion": 1,
        "capabilityId": record["id"],
        "capabilityInstance": record["instance"],
        "capabilityExpiresAt": record["expiresAt"],
        "canonicalRepo": record["canonicalRepo"],
        "canonicalWorkspace": record["canonicalWorkspace"],
        "team": record["team"],
        "featureId": record["featureId"],
        "executionKind": record["executionKind"],
        "role": role,
        "taskId": record["taskId"],
        "attempt": record["attempt"],
        "entryId": entry.get("id"),
        "entryMaterialSha256": "sha256:" + hashlib.sha256(
            _canonical(signed)
        ).hexdigest(),
        "bodySha256": body_digest,
        "signature": capability.get("signature"),
    }


def _admission_path(
    repository: str | Path, binding: Dict[str, Any]
) -> Path:
    digest = hashlib.sha256(_canonical(binding)).hexdigest()
    return admission_directory(repository) / ("admission-" + digest + ".json")


def _store_admission(
    repository: str | Path,
    record: Dict[str, Any],
    entry: Dict[str, Any],
    capability: Dict[str, Any],
    body_digest: str,
) -> None:
    """Durably admit one exact signed producer package under authority_lock."""
    binding = _admission_binding(record, entry, capability, body_digest)
    path = _admission_path(repository, binding)
    admitted_at = int(time.time())
    if admitted_at < int(record["issuedAt"]) or admitted_at >= int(record["expiresAt"]):
        raise CapabilityError("producer capability cannot admit after expiry")
    receipt = {**binding, "admittedAt": admitted_at}
    try:
        _write_exclusive(path, _canonical(receipt) + b"\n")
        _fsync_directory(path.parent)
        return
    except FileExistsError:
        # A transport retry for the same immutable package is idempotent.  The
        # existing receipt must still be the exact protected object we expect.
        pass
    try:
        existing = json.loads(_read_protected(path, "publication admission"))
    except (UnicodeError, ValueError) as exc:
        raise CapabilityError("invalid publication admission") from exc
    admitted = existing.get("admittedAt") if isinstance(existing, dict) else None
    if (
        not isinstance(existing, dict)
        or set(existing) != set(binding) | {"admittedAt"}
        or any(existing.get(name) != value for name, value in binding.items())
        or isinstance(admitted, bool)
        or not isinstance(admitted, int)
        or admitted < int(record["issuedAt"])
        or admitted >= int(record["expiresAt"])
    ):
        raise CapabilityError("publication admission identity mismatch")


def _has_exact_admission(
    repository: str | Path,
    record: Dict[str, Any],
    entry: Dict[str, Any],
    capability: Dict[str, Any],
    body_digest: str,
) -> bool:
    binding = _admission_binding(record, entry, capability, body_digest)
    path = _admission_path(repository, binding)
    try:
        value = json.loads(_read_protected(path, "publication admission"))
    except CapabilityError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return False
        raise
    except (UnicodeError, ValueError) as exc:
        raise CapabilityError("invalid publication admission") from exc
    admitted = value.get("admittedAt") if isinstance(value, dict) else None
    return bool(
        isinstance(value, dict)
        and set(value) == set(binding) | {"admittedAt"}
        and all(value.get(name) == expected for name, expected in binding.items())
        and isinstance(admitted, int)
        and not isinstance(admitted, bool)
        and int(record["issuedAt"]) <= admitted < int(record["expiresAt"])
    )


def request_signature(
    locator: str, entry: Dict[str, Any], body: bytes
) -> Dict[str, Any]:
    """Ask the launch supervisor to sign one exact producer entry.

    The locator is deliberately non-secret.  Authentication comes from the
    supervisor's kernel peer-generation check and its protected capability
    record, never from a bearer value in the worker environment.
    """
    if not isinstance(locator, str) or not locator.startswith("/"):
        raise CapabilityError("publication transport locator must be absolute")
    if len(os.fsencode(locator)) >= 100:
        raise CapabilityError("publication transport locator is too long")
    if not isinstance(body, bytes) or not body or len(body) > 65536:
        raise CapabilityError("publication body must contain 1..65536 bytes")
    if entry.get("producerCapability") is not None:
        raise CapabilityError("publication request is already signed")
    request = {
        "schemaVersion": 1,
        "entry": entry,
        "bodyHex": body.hex(),
    }
    payload = _canonical(request)
    if len(payload) > MAX_TRANSPORT_REQUEST_BYTES:
        raise CapabilityError("publication transport request is too large")
    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        deadline = time.monotonic() + TRANSPORT_TIMEOUT_SECONDS
        try:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect(locator)
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.sendall(struct.pack("!I", len(payload)) + payload)
            connection.shutdown(socket.SHUT_WR)
            header = _receive_exact(connection, 4, deadline)
            size = struct.unpack("!I", header)[0]
            if size <= 0 or size > MAX_TRANSPORT_RESPONSE_BYTES:
                raise CapabilityError("publication transport response has an invalid size")
            response = strict_json(
                _receive_exact(connection, size, deadline),
                "publication transport response",
            )
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            trailing, ancillary, _flags, _address = connection.recvmsg(1, 256)
            if trailing or ancillary:
                raise CapabilityError("publication transport response has trailing data")
        finally:
            connection.close()
    except CapabilityError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise CapabilityError("publication transport request failed") from exc
    if not isinstance(response, dict) or set(response) != {
        "schemaVersion",
        "producerCapability",
    }:
        raise CapabilityError("publication transport returned an invalid response")
    if response.get("schemaVersion") != 1:
        raise CapabilityError("publication transport returned an unsupported response")
    capability = response.get("producerCapability")
    if not isinstance(capability, dict):
        raise CapabilityError("publication transport omitted the producer capability")
    return capability


def _receive_exact(connection: socket.socket, size: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CapabilityError("publication transport exceeded its frame deadline")
        connection.settimeout(remaining)
        block, ancillary, _flags, _address = connection.recvmsg(
            size - len(result), 256
        )
        if ancillary:
            raise CapabilityError("publication transport sent ancillary data")
        if not block:
            raise CapabilityError("publication transport closed an incomplete frame")
        result.extend(block)
    return bytes(result)


def active_record(
    repository: str,
    workspace: str,
    capability_id: str,
    *,
    authority_locked: bool = False,
) -> Dict[str, Any]:
    """Load one exact, unexpired, non-superseded broker capability record."""
    if not CAPABILITY_ID.fullmatch(capability_id):
        raise CapabilityError("invalid producer capability handle")
    repo = _repo(repository)
    workspace_real = Path(os.path.realpath(workspace))
    records, active, revoked = state_directories(repo)
    raw = _read_protected(records / (capability_id + ".json"), "capability record")
    try:
        record = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise CapabilityError("invalid capability record") from exc
    required = {
        "schemaVersion", "id", "secret", "canonicalRepo", "canonicalWorkspace",
        "team", "featureId", "role", "executionKind", "taskId", "attempt",
        "instance", "issuedAt", "expiresAt", "issuedAtUtc",
    }
    if not isinstance(record, dict) or set(record) != required or record.get("schemaVersion") != 1:
        raise CapabilityError("invalid capability record schema")
    if record.get("id") != capability_id:
        raise CapabilityError("capability record identity mismatch")
    if record.get("canonicalRepo") != str(repo) or record.get("canonicalWorkspace") != str(workspace_real):
        raise CapabilityError("producer capability is bound to another canonical workspace")
    if authority_locked:
        require_authority_lock(repo)
    lock = nullcontext() if authority_locked else authority_lock(repo)
    with lock:
        if _is_revoked(revoked, capability_id):
            raise CapabilityError("producer capability was revoked")
        pointer = _read_protected(
            active / (_active_key(record) + ".id"), "active capability", 256
        )
        try:
            active_id = pointer.decode("ascii", errors="strict").strip()
        except UnicodeError as exc:
            raise CapabilityError("active capability identity is not ASCII") from exc
        if not CAPABILITY_ID.fullmatch(active_id):
            raise CapabilityError("active capability identity is invalid")
        if not hmac.compare_digest(active_id, capability_id):
            raise CapabilityError("producer capability was superseded")
        expires_at = record.get("expiresAt")
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            raise CapabilityError("invalid capability expiry")
        if expires_at <= int(time.time()):
            raise CapabilityError("producer capability expired")
    return record


def sign_active_entry(
    repository: str,
    workspace: str,
    capability_id: str,
    entry: Dict[str, Any],
    body: bytes,
) -> Dict[str, Any]:
    """Atomically sign and durably admit one exact current-generation package."""
    # The supervisor is an artifact-publication boundary, not a generic HMAC
    # oracle.  Reject incomplete, legacy, or extensible dictionaries before
    # consulting capability state so every durable admission binds the closed
    # producer schema (including phase, bodyPath, and targetStatus).
    if {"bodyPath", "phase"}.intersection(entry):
        producer_envelope(entry)
    else:
        control_envelope(entry)
    repo = _repo(repository)
    with authority_lock(repo):
        record = active_record(
            str(repo), workspace, capability_id, authority_locked=True
        )
        if (
            record.get("team") != entry.get("team")
            or record.get("featureId") != entry.get("featureId")
        ):
            raise CapabilityError("producer capability is bound to another team/feature")
        if record.get("role") != entry.get("actor"):
            raise CapabilityError("claimed actor does not match the producer capability")
        if record.get("executionKind") == "task":
            if (
                record.get("taskId") != entry.get("taskId")
                or record.get("attempt") != entry.get("attempt")
            ):
                raise CapabilityError("task capability is bound to another task/attempt")
        elif record.get("executionKind") != "gate":
            raise CapabilityError("invalid capability execution kind")
        capability = sign_entry(
            entry,
            body,
            capability_id,
            str(record["secret"]),
            str(record["instance"]),
            int(record["expiresAt"]),
        )
        _store_admission(
            repo, record, entry, capability, str(capability["bodySha256"])
        )
        return capability


def revoke_exact(
    repository: str,
    workspace: str,
    capability_id: str,
) -> int:
    """Fence one exact launch without ever removing a successor pointer."""
    if not CAPABILITY_ID.fullmatch(capability_id):
        raise CapabilityError("invalid producer capability handle")
    repo = _repo(repository)
    workspace_real = Path(os.path.realpath(workspace))
    records, active, revoked = state_directories(repo)
    try:
        record = json.loads(
            _read_protected(records / (capability_id + ".json"), "capability record")
        )
    except (UnicodeError, ValueError) as exc:
        raise CapabilityError("invalid capability record") from exc
    if not isinstance(record, dict) or record.get("id") != capability_id:
        raise CapabilityError("capability record identity mismatch")
    if record.get("canonicalWorkspace") != str(workspace_real):
        raise CapabilityError("producer capability is bound to another canonical workspace")
    pointer = active / (_active_key(record) + ".id")
    with authority_lock(repo):
        _record_revocation(revoked, capability_id)
        try:
            raw = _read_protected(pointer, "active capability", 256)
        except CapabilityError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                return 0
            raise
        try:
            active_id = raw.decode("ascii", errors="strict").strip()
        except UnicodeError as exc:
            raise CapabilityError("active capability identity is not ASCII") from exc
        if not CAPABILITY_ID.fullmatch(active_id):
            raise CapabilityError("active capability identity is invalid")
        if not hmac.compare_digest(active_id, capability_id):
            return 0
        pointer.unlink()
        return 1


def _read_protected(path: Path, label: str, maximum: int = 65536) -> bytes:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise CapabilityError("%s must be a non-symlink regular file" % label)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise CapabilityError("%s must be owner-only" % label)
        if info.st_size <= 0 or info.st_size > maximum:
            raise CapabilityError("invalid %s size" % label)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            return os.read(descriptor, maximum + 1)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise CapabilityError("cannot read %s: %s" % (label, exc)) from exc


def _verify_entry(
    repository: str,
    workspace: str,
    entry: Dict[str, Any],
    producer_body_digest: str,
    *,
    require_active: bool,
    authority_locked: bool = False,
) -> Dict[str, Any]:
    capability = entry.get("producerCapability")
    if not isinstance(capability, dict):
        raise CapabilityError("launched-role capability is absent")
    if set(capability) != {
        "schemaVersion", "id", "instance", "expiresAt", "bodySha256", "signature"
    }:
        raise CapabilityError("producer capability has unexpected or missing fields")
    if capability.get("schemaVersion") != 1:
        raise CapabilityError("unsupported producer capability schema")
    capability_id = str(capability.get("id") or "")
    if not CAPABILITY_ID.fullmatch(capability_id):
        raise CapabilityError("invalid producer capability id")
    if not BODY_DIGEST.fullmatch(str(producer_body_digest or "")):
        raise CapabilityError("invalid producer body digest")
    if capability.get("bodySha256") != producer_body_digest:
        raise CapabilityError("producer body digest does not match its capability")
    signature = str(capability.get("signature") or "")
    if not SIGNATURE.fullmatch(signature):
        raise CapabilityError("invalid producer capability signature")

    repo = _repo(repository)
    if authority_locked:
        require_authority_lock(repo)
    workspace_real = Path(os.path.realpath(workspace))
    records, active, revoked = state_directories(repo)
    raw = _read_protected(records / (capability_id + ".json"), "capability record")
    try:
        record = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise CapabilityError("invalid capability record") from exc
    required = {
        "schemaVersion", "id", "secret", "canonicalRepo", "canonicalWorkspace",
        "team", "featureId", "role", "executionKind", "taskId", "attempt",
        "instance", "issuedAt", "expiresAt", "issuedAtUtc",
    }
    if not isinstance(record, dict) or set(record) != required or record.get("schemaVersion") != 1:
        raise CapabilityError("invalid capability record schema")
    if record.get("id") != capability_id:
        raise CapabilityError("capability record identity mismatch")
    if capability.get("expiresAt") != record.get("expiresAt"):
        raise CapabilityError("producer capability expiry mismatch")
    if capability.get("instance") != record.get("instance"):
        raise CapabilityError("producer capability instance mismatch")
    if record.get("canonicalRepo") != str(repo) or record.get("canonicalWorkspace") != str(workspace_real):
        raise CapabilityError("producer capability is bound to another canonical workspace")
    if record.get("team") != entry.get("team") or record.get("featureId") != entry.get("featureId"):
        raise CapabilityError("producer capability is bound to another team/feature")
    role = str(record.get("role") or "")
    if not ROLE.fullmatch(role):
        raise CapabilityError("invalid role in capability record")
    if entry.get("actor") != role:
        raise CapabilityError("claimed actor does not match the verified capability role")
    kind = record.get("executionKind")
    if kind not in {"gate", "task"}:
        raise CapabilityError("invalid capability execution kind")
    if kind == "task":
        if record.get("taskId") != entry.get("taskId") or record.get("attempt") != entry.get("attempt"):
            raise CapabilityError("task capability is bound to another task/attempt")
    expected = signed_material(entry, capability, producer_body_digest, role)
    try:
        secret = bytes.fromhex(str(record.get("secret") or ""))
    except ValueError as exc:
        raise CapabilityError("invalid verifier secret") from exc
    observed = "hmac-sha256:" + hmac.new(secret, _canonical(expected), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(observed, signature):
        raise CapabilityError("producer capability signature mismatch")
    admission_recovery = False
    if require_active:
        # Mint/revoke, signing admission, hold mutations, and the tracker effect
        # share one lock.  A current generation may proceed directly.  Once it
        # is fenced, only the exact immutable package that the broker durably
        # admitted before that fence may recover; stale workers cannot create a
        # new admission because they no longer reach sign_active_entry.
        lock = nullcontext() if authority_locked else authority_lock(repo)
        with lock:
            inactive_reason: str | None = None
            if _is_revoked(revoked, capability_id):
                inactive_reason = "producer capability was revoked"
            else:
                try:
                    pointer = _read_protected(
                        active / (_active_key(record) + ".id"),
                        "active capability",
                        256,
                    )
                except CapabilityError as exc:
                    if isinstance(exc.__cause__, FileNotFoundError):
                        inactive_reason = "producer capability is not active"
                    else:
                        raise
                else:
                    try:
                        active_id = pointer.decode("ascii", errors="strict").strip()
                    except UnicodeError as exc:
                        raise CapabilityError(
                            "active capability identity is not ASCII"
                        ) from exc
                    if not CAPABILITY_ID.fullmatch(active_id):
                        raise CapabilityError("active capability identity is invalid")
                    if not hmac.compare_digest(active_id, capability_id):
                        inactive_reason = "producer capability was superseded"
                    elif (
                        isinstance(record.get("expiresAt"), bool)
                        or int(record.get("expiresAt", 0)) <= int(time.time())
                    ):
                        inactive_reason = "producer capability expired"
            if inactive_reason is not None:
                if not _has_exact_admission(
                    repo, record, entry, capability, producer_body_digest
                ):
                    raise CapabilityError(inactive_reason)
                admission_recovery = True
    return {
        "role": role,
        "executionKind": kind,
        "instance": record["instance"],
        "expiresAt": record["expiresAt"],
        # Internal callers use this only to distinguish a still-current retry
        # from the one bounded recovery allowed for a package durably admitted
        # before its generation was fenced.
        "admissionRecovery": admission_recovery,
    }


def verify_entry(
    repository: str,
    workspace: str,
    entry: Dict[str, Any],
    producer_body_digest: str,
    *,
    authority_locked: bool = False,
) -> Dict[str, Any]:
    """Verify a pending producer entry against its currently active capability."""
    return _verify_entry(
        repository,
        workspace,
        entry,
        producer_body_digest,
        require_active=True,
        authority_locked=authority_locked,
    )


def verify_published_entry(
    repository: str,
    workspace: str,
    entry: Dict[str, Any],
    producer_body_digest: str,
    *,
    authority_locked: bool = False,
) -> Dict[str, Any]:
    """Authenticate immutable published evidence after its capability expires.

    The protected capability record and HMAC remain durable audit authority;
    only pending writes require the active pointer and unexpired lease.
    """
    return _verify_entry(
        repository,
        workspace,
        entry,
        producer_body_digest,
        require_active=False,
        authority_locked=authority_locked,
    )


def _revoke_scope(repository: str, workspace: str, matches) -> int:
    repo = _repo(repository)
    workspace_path = Path(workspace)
    if not workspace_path.is_absolute():
        raise CapabilityError("canonical workspace path must be absolute")
    workspace_real = Path(os.path.realpath(workspace_path))
    if workspace_real != workspace_path or not workspace_real.is_dir():
        raise CapabilityError("canonical workspace must be a non-symlink directory")
    records, active, revoked_dir = state_directories(repo)
    with authority_lock(repo):
        scoped = lambda record: (
            record.get("canonicalRepo") == str(repo)
            and record.get("canonicalWorkspace") == str(workspace_real)
            and matches(record)
        )
        _revoke_matching_records(records, revoked_dir, scoped)
        revoked = 0
        for pointer in sorted(active.iterdir(), key=lambda item: item.name):
            try:
                info = pointer.lstat()
            except OSError as exc:
                raise CapabilityError(
                    "cannot inspect active capability pointer: %s" % exc
                ) from exc
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise CapabilityError(
                    "active capability pointer is not an owner-only regular file"
                )
            raw_id = _read_protected(pointer, "active capability", 256)
            try:
                capability_id = raw_id.decode("ascii", errors="strict").strip()
            except UnicodeError as exc:
                raise CapabilityError(
                    "active capability identity is not ASCII"
                ) from exc
            if not CAPABILITY_ID.fullmatch(capability_id):
                raise CapabilityError("active capability identity is invalid")
            try:
                record = json.loads(
                    _read_protected(
                        records / (capability_id + ".json"), "capability record"
                    )
                )
            except (UnicodeError, ValueError) as exc:
                raise CapabilityError("invalid capability record") from exc
            if not isinstance(record, dict) or record.get("id") != capability_id:
                raise CapabilityError("capability record identity mismatch")
            if pointer.name != _active_key(record) + ".id":
                raise CapabilityError("active capability pointer identity mismatch")
            if scoped(record):
                _record_revocation(revoked_dir, capability_id)
                pointer.unlink()
                revoked += 1
    return revoked


def revoke_task(repository: str, workspace: str, team: str, task: str) -> int:
    """Revoke every producer generation bound to one task."""
    _safe_text(team, "team", 63)
    _safe_text(task, "taskId")
    return _revoke_scope(
        repository,
        workspace,
        lambda record: (
            record.get("team") == team
            and record.get("executionKind") == "task"
            and record.get("taskId") == task
        ),
    )


def revoke_role(repository: str, workspace: str, team: str, role: str) -> int:
    """Revoke every gate generation for one exact concrete role."""
    _safe_text(team, "team", 63)
    if not ROLE.fullmatch(role):
        raise CapabilityError("invalid capability role")
    return _revoke_scope(
        repository,
        workspace,
        lambda record: (
            record.get("team") == team
            and record.get("executionKind") == "gate"
            and record.get("role") == role
        ),
    )


def revoke_team(repository: str, workspace: str, team: str) -> int:
    """Revoke every task and gate generation for one exact team workspace."""
    _safe_text(team, "team", 63)
    return _revoke_scope(
        repository,
        workspace,
        lambda record: record.get("team") == team,
    )


def locked_tracker_effect(
    repository: str,
    workspace: str,
    lifecycle_root: str,
    entry_path: str,
    delivery_id: str,
    body_digest: str,
    effect: list[str],
) -> int:
    """Linearize one tracker effect against authority fences and task holds."""
    if not effect or effect[0] not in {"comment-once", "state"}:
        raise CapabilityError("unsupported protected tracker effect")
    if (effect[0] == "comment-once" and len(effect) != 4) or (
        effect[0] == "state" and len(effect) != 3
    ):
        raise CapabilityError("protected tracker effect has invalid arguments")
    path = Path(entry_path)
    if not path.is_absolute():
        raise CapabilityError("protected tracker entry path must be absolute")
    try:
        raw = _read_protected(path, "protected broker delivery", 2 * 1024 * 1024)
        entry = strict_json(raw, "protected broker delivery")
    except (UnicodeError, ValueError) as exc:
        raise CapabilityError("invalid protected broker delivery") from exc
    if not isinstance(entry, dict):
        raise CapabilityError("protected tracker effect requires an object entry")
    producer_envelope(entry)
    for name in ("team", "featureId", "taskId", "marker"):
        _safe_text(entry.get(name), "entry %s" % name)
    if str(entry["taskId"]) != effect[1]:
        raise CapabilityError("protected tracker effect task does not match its entry")
    if not re.fullmatch(r"delivery-[0-9a-f]{32}", delivery_id or ""):
        raise CapabilityError("protected tracker effect has an invalid delivery identity")
    if entry.get("deliveryId") != delivery_id:
        raise CapabilityError("protected tracker effect delivery does not match its entry")
    expected_root = delivery_directory(
        repository, workspace, str(entry["team"]), str(entry["featureId"])
    )
    try:
        if path.resolve(strict=True) != path or path.parent != expected_root:
            raise CapabilityError("protected tracker entry escapes broker delivery state")
    except OSError as exc:
        raise CapabilityError("protected tracker entry is unavailable") from exc

    lifecycle = Path(lifecycle_root)
    try:
        lifecycle_info = lifecycle.lstat()
        lifecycle_resolved = lifecycle.resolve(strict=True)
    except OSError as exc:
        raise CapabilityError("protected lifecycle root is unavailable") from exc
    if (
        not lifecycle.is_absolute()
        or Path(os.path.normpath(str(lifecycle))) != lifecycle
        or lifecycle_resolved != lifecycle
        or stat.S_ISLNK(lifecycle_info.st_mode)
        or not stat.S_ISDIR(lifecycle_info.st_mode)
        or lifecycle_info.st_uid != os.geteuid()
        or stat.S_IMODE(lifecycle_info.st_mode) != 0o700
    ):
        raise CapabilityError("protected lifecycle root must be canonical owner-only state")
    tracker = Path(__file__).resolve().with_name("tracker-ops.sh")
    if not tracker.is_file() or tracker.is_symlink():
        raise CapabilityError("pinned tracker adapter entry point is unavailable")
    hold_checker = Path(__file__).resolve().with_name("task-hold.py")
    if not hold_checker.is_file() or hold_checker.is_symlink():
        raise CapabilityError("pinned task-hold checker is unavailable")
    with authority_lock(repository):
        if entry.get("producerCapability") is not None:
            _verify_entry(
                repository,
                workspace,
                entry,
                body_digest,
                require_active=True,
                authority_locked=True,
            )
        elif body_digest != "-":
            raise CapabilityError("unsigned tracker effect has a producer digest")

        def exact_body(path_value: Any, digest_value: Any, label: str) -> Path:
            if not isinstance(path_value, str) or not BODY_DIGEST.fullmatch(
                str(digest_value or "")
            ):
                raise CapabilityError("%s binding is incomplete" % label)
            body_path = Path(path_value)
            try:
                if (
                    not body_path.is_absolute()
                    or Path(os.path.abspath(body_path)) != body_path
                    or body_path.resolve(strict=True) != body_path
                    or body_path.parent != expected_root
                ):
                    raise CapabilityError("%s escapes protected delivery state" % label)
                before = body_path.lstat()
                if (
                    stat.S_ISLNK(before.st_mode)
                    or not stat.S_ISREG(before.st_mode)
                    or not 0 < before.st_size <= 65536
                ):
                    raise CapabilityError("%s is unsafe" % label)
                descriptor = os.open(
                    body_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    opened = os.fstat(descriptor)
                    content = bytearray()
                    while len(content) <= 65536:
                        block = os.read(descriptor, 65537 - len(content))
                        if not block:
                            break
                        content.extend(block)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as exc:
                raise CapabilityError("cannot securely read %s" % label) from exc
            if (
                len(content) != opened.st_size
                or (opened.st_dev, opened.st_ino, opened.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
                or (after.st_dev, after.st_ino, after.st_size)
                != (opened.st_dev, opened.st_ino, opened.st_size)
                or "sha256:" + hashlib.sha256(content).hexdigest() != digest_value
            ):
                raise CapabilityError("%s changed or failed digest verification" % label)
            return body_path

        staged_path = exact_body(
            entry.get("stagedBodyPath"), entry.get("stagedBodySha256"), "staged body"
        )
        publish_path = exact_body(
            entry.get("publishBodyPath"), entry.get("publishBodySha256"), "publish body"
        )
        if effect[0] == "comment-once":
            if effect[2] != delivery_id or Path(effect[3]) != publish_path:
                raise CapabilityError("comment effect does not match protected delivery binding")
        elif entry.get("targetStatus") != effect[2]:
            raise CapabilityError("state effect does not match protected target status")
        try:
            hold_environment = os.environ.copy()
            hold_environment["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = str(lifecycle)
            hold = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(hold_checker),
                    "check",
                    "--repo",
                    str(_repo(repository)),
                    "--workspace",
                    str(Path(workspace).resolve(strict=True)),
                    "--team",
                    str(entry["team"]),
                    "--feature",
                    str(entry["featureId"]),
                    "--task",
                    str(entry["taskId"]),
                    "--marker",
                    str(entry["marker"]),
                ],
                check=False,
                env=hold_environment,
            )
            if hold.returncode != 0:
                return hold.returncode
            tracker_environment = os.environ.copy()
            tracker_environment.pop("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT", None)
            # Broker filesystem authority must never cross into the
            # credentialed adapter process; only already-open, exact effect
            # arguments do.
            result = subprocess.run(
                [str(tracker), *effect], check=False, env=tracker_environment
            )
        except OSError as exc:
            raise CapabilityError("protected tracker effect could not start") from exc
        return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    mint_parser = subparsers.add_parser("mint")
    mint_parser.add_argument("--repo", required=True)
    mint_parser.add_argument("--workspace", required=True)
    mint_parser.add_argument("--team", required=True)
    mint_parser.add_argument("--feature", required=True)
    mint_parser.add_argument("--role", required=True)
    mint_parser.add_argument("--kind", choices=("gate", "task"), required=True)
    mint_parser.add_argument("--task", required=True)
    mint_parser.add_argument("--attempt", type=int, required=True)
    mint_parser.add_argument("--instance", required=True)
    mint_parser.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    mint_parser.add_argument("--descriptor-only", action="store_true")
    revoke_parser = subparsers.add_parser("revoke-task")
    revoke_parser.add_argument("--repo", required=True)
    revoke_parser.add_argument("--workspace", required=True)
    revoke_parser.add_argument("--team", required=True)
    revoke_parser.add_argument("--task", required=True)
    revoke_exact_parser = subparsers.add_parser("revoke-exact")
    revoke_exact_parser.add_argument("--repo", required=True)
    revoke_exact_parser.add_argument("--workspace", required=True)
    revoke_exact_parser.add_argument("--handle", required=True)
    revoke_role_parser = subparsers.add_parser("revoke-role")
    revoke_role_parser.add_argument("--repo", required=True)
    revoke_role_parser.add_argument("--workspace", required=True)
    revoke_role_parser.add_argument("--team", required=True)
    revoke_role_parser.add_argument("--role", required=True)
    revoke_team_parser = subparsers.add_parser("revoke-team")
    revoke_team_parser.add_argument("--repo", required=True)
    revoke_team_parser.add_argument("--workspace", required=True)
    revoke_team_parser.add_argument("--team", required=True)
    delivery_root_parser = subparsers.add_parser("delivery-root")
    delivery_root_parser.add_argument("--repo", required=True)
    delivery_root_parser.add_argument("--workspace", required=True)
    delivery_root_parser.add_argument("--team", required=True)
    delivery_root_parser.add_argument("--feature", required=True)
    effect_parser = subparsers.add_parser("locked-tracker-effect")
    effect_parser.add_argument("--repo", required=True)
    effect_parser.add_argument("--workspace", required=True)
    effect_parser.add_argument("--lifecycle-root", required=True)
    effect_parser.add_argument("--entry", required=True)
    effect_parser.add_argument("--delivery-id", required=True)
    effect_parser.add_argument("--body-digest", required=True)
    effect_parser.add_argument("effect", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.command == "mint":
            result = mint(
                args.repo, args.workspace, args.team, args.feature, args.role,
                args.kind, args.task, args.attempt, args.instance, args.ttl,
            )
            if args.descriptor_only:
                result = {
                    "id": result["id"],
                    "instance": result["instance"],
                    "expiresAt": result["expiresAt"],
                }
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "revoke-task":
            count = revoke_task(args.repo, args.workspace, args.team, args.task)
            print(json.dumps({"revoked": count}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "revoke-exact":
            count = revoke_exact(args.repo, args.workspace, args.handle)
            print(json.dumps({"revoked": count}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "revoke-role":
            count = revoke_role(args.repo, args.workspace, args.team, args.role)
            print(json.dumps({"revoked": count}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "revoke-team":
            count = revoke_team(args.repo, args.workspace, args.team)
            print(json.dumps({"revoked": count}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "delivery-root":
            print(
                delivery_directory(
                    args.repo, args.workspace, args.team, args.feature
                )
            )
            return 0
        if args.command == "locked-tracker-effect":
            effect = args.effect[1:] if args.effect[:1] == ["--"] else args.effect
            return locked_tracker_effect(
                args.repo,
                args.workspace,
                args.lifecycle_root,
                args.entry,
                args.delivery_id,
                args.body_digest,
                effect,
            )
    except CapabilityError as exc:
        print("outbox-capability: %s" % exc, file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
