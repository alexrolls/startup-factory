#!/usr/bin/env python3
"""Authenticated Team Lead requests for deterministic worker lifecycle control."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from outbox_capability import (
    CapabilityError,
    sign_entry,
    verify_entry,
    verify_published_entry,
)


CONTROL_ID = re.compile(r"control-[0-9a-f]{32}")
ROLE = re.compile(r"[a-z0-9][a-z0-9-]{1,79}")
ACTIONS = {"nudge-task", "restart-task", "retire-role", "restart-role"}
REASONS = {
    "stale-live",
    "artifact-missing",
    "hung-tool",
    "superseded",
    "no-longer-needed",
}
MAX_REQUEST_BYTES = 64 * 1024
REQUEST_TTL_SECONDS = 5 * 60
MAX_CONTROL_REQUESTS_PER_PASS = 64
MAX_CONTROL_REQUEST_BYTES_PER_PASS = 1024 * 1024
FULL_RESULT_RETENTION = 256
CONSUMED_FILTER_BYTES = 32 * 1024
CONSUMED_FILTER_HASHES = 7
RESULT_KEYS = {
    "schemaVersion",
    "controlId",
    "operationSha256",
    "result",
    "detail",
    "processedAt",
    "auth",
}
REQUEST_KEYS = {
    "schemaVersion",
    "id",
    "team",
    "featureId",
    "taskId",
    "attempt",
    "actor",
    "marker",
    "targetStatus",
    "createdAt",
    "expiresAt",
    "action",
    "targetRole",
    "observedLifecycleCreatedAt",
    "observedTaskRevision",
    "observedTaskStatus",
    "observedExecutionSha256",
    "observedClaimSha256",
    "priorNudgeControlId",
    "reasonCode",
    "controlBodySha256",
    "producerCapability",
}
PROJECTION_KEYS = REQUEST_KEYS | {"result", "detail", "processedAt"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class ControlError(RuntimeError):
    pass


class ControlDeferred(ControlError):
    """A valid request whose policy grace has not elapsed yet."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def safe_text(value: Any, label: str, maximum: int = 1024) -> str:
    text = str(value or "")
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise ControlError(f"invalid {label}")
    return text


def safe_directory(path: str, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ControlError(f"{label} must be absolute")
    lexical = Path(os.path.abspath(candidate))
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ControlError(f"{label} is unavailable: {exc}") from exc
    if lexical != resolved or not resolved.is_dir():
        raise ControlError(f"{label} must be a non-symlink directory")
    return resolved


def private_directory(path: Path, label: str) -> Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
    ):
        raise ControlError(f"{label} must be an owned non-symlink directory")
    if stat.S_IMODE(info.st_mode) != 0o700:
        os.chmod(path, 0o700, follow_symlinks=False)
        info = path.lstat()
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise ControlError(f"{label} must have mode 0700")
    return path


def operation_digest(request: dict[str, Any]) -> str:
    operation = {
        key: request.get(key)
        for key in (
            "schemaVersion",
            "id",
            "team",
            "featureId",
            "taskId",
            "attempt",
            "action",
            "targetRole",
            "observedLifecycleCreatedAt",
            "observedTaskRevision",
            "observedTaskStatus",
            "observedExecutionSha256",
            "observedClaimSha256",
            "priorNudgeControlId",
            "reasonCode",
        )
    }
    return "sha256:" + hashlib.sha256(canonical(operation)).hexdigest()


def result_authority(
    lifecycle_root: Path, repository: Path
) -> tuple[Path, bytes]:
    root_info = lifecycle_root.lstat()
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or stat.S_IMODE(root_info.st_mode) != 0o700
        or root_info.st_uid not in {0, os.geteuid()}
    ):
        raise ControlError("protected lifecycle root must be an owned mode-0700 directory")
    try:
        common = Path(
            os.path.commonpath(
                (str(lifecycle_root.resolve(strict=True)), str(repository.resolve(strict=True)))
            )
        )
    except ValueError:
        common = Path()
    if common in {lifecycle_root.resolve(strict=True), repository.resolve(strict=True)}:
        raise ControlError("protected lifecycle root and agent repository must be disjoint")

    key_path = lifecycle_root / "record-auth.key"
    if not key_path.exists():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(key_path, flags, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                os.write(descriptor, secrets.token_bytes(32))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    key_info = key_path.lstat()
    if (
        stat.S_ISLNK(key_info.st_mode)
        or not stat.S_ISREG(key_info.st_mode)
        or stat.S_IMODE(key_info.st_mode) != 0o600
        or key_info.st_uid not in {0, os.geteuid()}
        or key_info.st_size != 32
    ):
        raise ControlError("protected lifecycle authentication key is unsafe")
    key = regular_bytes(key_path, "protected lifecycle authentication key", 32)
    if len(key) != 32:
        raise ControlError("protected lifecycle authentication key must contain 32 bytes")

    directory = lifecycle_root / "control-results"
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    directory_info = directory.lstat()
    if (
        stat.S_ISLNK(directory_info.st_mode)
        or not stat.S_ISDIR(directory_info.st_mode)
        or stat.S_IMODE(directory_info.st_mode) != 0o700
        or directory_info.st_uid not in {0, os.geteuid()}
    ):
        raise ControlError("protected control-result directory is unsafe")
    return directory, key


def protected_result_path(directory: Path, control_id: str) -> Path:
    if not CONTROL_ID.fullmatch(control_id):
        raise ControlError("control request has an invalid protected result identity")
    return directory / f"{control_id}.json"


def consumed_filter_path(directory: Path) -> Path:
    return directory / "consumed-ids.bloom"


def consumed_material(request: dict[str, Any]) -> bytes:
    # A retired control identity remains consumed even if an attacker presents
    # the same ID with different operation fields after its full receipt ages
    # out. Operation binding is retained in full receipts; the bounded filter
    # is deliberately stricter and fails every reuse of the ID closed.
    return str(request.get("id")).encode("utf-8")


def filter_indexes(material: bytes) -> list[int]:
    indexes = []
    bit_count = CONSUMED_FILTER_BYTES * 8
    for counter in range(CONSUMED_FILTER_HASHES):
        digest = hashlib.sha256(counter.to_bytes(2, "big") + material).digest()
        indexes.append(int.from_bytes(digest[:8], "big") % bit_count)
    return indexes


def load_consumed_filter(directory: Path, key: bytes) -> bytearray:
    path = consumed_filter_path(directory)
    if not path.exists() and not path.is_symlink():
        return bytearray(CONSUMED_FILTER_BYTES)
    value = strict_json(
        regular_bytes(path, "protected consumed-control filter", 2 * CONSUMED_FILTER_BYTES),
        "protected consumed-control filter",
    )
    if set(value) != {"schemaVersion", "algorithm", "bits", "auth"}:
        raise ControlError("protected consumed-control filter has an unexpected schema")
    if value.get("schemaVersion") != 1 or value.get("algorithm") != (
        f"bloom-control-id-sha256-{CONSUMED_FILTER_HASHES}-{CONSUMED_FILTER_BYTES}"
    ):
        raise ControlError("protected consumed-control filter parameters changed")
    supplied = str(value.get("auth") or "")
    unsigned = dict(value)
    unsigned.pop("auth", None)
    expected = "hmac-sha256:" + hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise ControlError("protected consumed-control filter authentication failed")
    try:
        bits = bytearray(base64.b64decode(str(value.get("bits") or ""), validate=True))
    except (ValueError, TypeError) as exc:
        raise ControlError("protected consumed-control filter is malformed") from exc
    if len(bits) != CONSUMED_FILTER_BYTES:
        raise ControlError("protected consumed-control filter has an invalid size")
    return bits


def store_consumed_filter(directory: Path, key: bytes, bits: bytearray) -> None:
    if len(bits) != CONSUMED_FILTER_BYTES:
        raise ControlError("internal consumed-control filter size mismatch")
    unsigned = {
        "schemaVersion": 1,
        "algorithm": f"bloom-control-id-sha256-{CONSUMED_FILTER_HASHES}-{CONSUMED_FILTER_BYTES}",
        "bits": base64.b64encode(bits).decode("ascii"),
    }
    value = {
        **unsigned,
        "auth": "hmac-sha256:"
        + hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest(),
    }
    path = consumed_filter_path(directory)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def consumed_filter_contains(directory: Path, key: bytes, request: dict[str, Any]) -> bool:
    bits = load_consumed_filter(directory, key)
    return all(
        bits[index // 8] & (1 << (index % 8))
        for index in filter_indexes(consumed_material(request))
    )


def load_result_envelope(path: Path, key: bytes) -> dict[str, Any]:
    envelope = strict_json(
        regular_bytes(path, "protected control result"), "protected control result"
    )
    if set(envelope) != RESULT_KEYS or envelope.get("schemaVersion") != 1:
        raise ControlError("protected control result has an unexpected schema")
    supplied = envelope.get("auth")
    if not isinstance(supplied, str) or not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", supplied):
        raise ControlError("protected control result has an invalid authenticator")
    unsigned = dict(envelope)
    del unsigned["auth"]
    expected = "hmac-sha256:" + hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise ControlError("protected control result authentication failed")
    if envelope.get("result") not in {"completed", "failed"}:
        raise ControlError("protected control result has an invalid verdict")
    if not isinstance(envelope.get("detail"), str) or not isinstance(
        envelope.get("processedAt"), str
    ):
        raise ControlError("protected control result has malformed detail")
    return envelope


def load_protected_result(
    path: Path, key: bytes, request: dict[str, Any]
) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        if consumed_filter_contains(path.parent, key, request):
            return {
                "schemaVersion": 1,
                "controlId": request["id"],
                "operationSha256": operation_digest(request),
                "result": "failed",
                "detail": "control identity was already consumed; full result expired from bounded retention",
                "processedAt": "1970-01-01T00:00:00+00:00",
                "auth": "archived-consumed-identity",
            }
        return None
    envelope = load_result_envelope(path, key)
    if envelope.get("controlId") != request.get("id"):
        raise ControlError("protected control result identity mismatch")
    if envelope.get("operationSha256") != operation_digest(request):
        raise ControlError("protected control result operation collision")
    return envelope


def acquire_result_retention_lock(directory: Path) -> int:
    lock_path = directory / ".retention.lock"
    lock_descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    lock_info = os.fstat(lock_descriptor)
    if (
        not stat.S_ISREG(lock_info.st_mode)
        or stat.S_IMODE(lock_info.st_mode) != 0o600
        or lock_info.st_uid not in {0, os.geteuid()}
    ):
        os.close(lock_descriptor)
        raise ControlError("protected result-retention lock is unsafe")
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
    return lock_descriptor


def compact_protected_results_locked(directory: Path, key: bytes) -> None:
    if FULL_RESULT_RETENTION < 1:
        raise ControlError("protected result retention must preserve a full result")
    results = []
    for path in directory.glob("control-*.json"):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ControlError("protected result retention found an unsafe entry")
        results.append((info.st_mtime_ns, path))
    excess = len(results) - FULL_RESULT_RETENTION + 1
    if excess <= 0:
        return
    bits = load_consumed_filter(directory, key)
    victims = sorted(results, key=lambda item: (item[0], item[1].name))[:excess]
    for _, path in victims:
        envelope = load_result_envelope(path, key)
        material = str(envelope["controlId"]).encode("utf-8")
        for index in filter_indexes(material):
            bits[index // 8] |= 1 << (index % 8)
    # The authenticated filter must reach stable storage before any full
    # result is removed. A crash can therefore duplicate storage, never forget
    # a consumed identity and replay its side effect.
    store_consumed_filter(directory, key, bits)
    for _, path in victims:
        path.unlink()
    directory_descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def compact_protected_results(directory: Path, key: bytes) -> None:
    """Reserve one full-result slot and archive overflow identities fail-closed."""

    lock_descriptor = acquire_result_retention_lock(directory)
    try:
        compact_protected_results_locked(directory, key)
    finally:
        os.close(lock_descriptor)


def store_protected_result(
    directory: Path,
    key: bytes,
    request: dict[str, Any],
    result: str,
    detail: str,
) -> dict[str, Any]:
    path = protected_result_path(directory, str(request["id"]))
    lock_descriptor = acquire_result_retention_lock(directory)
    try:
        existing = load_protected_result(path, key, request)
        if existing is not None:
            return existing
        compact_protected_results_locked(directory, key)
        unsigned: dict[str, Any] = {
            "schemaVersion": 1,
            "controlId": request["id"],
            "operationSha256": operation_digest(request),
            "result": result,
            "detail": detail,
            "processedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        envelope = dict(unsigned)
        envelope["auth"] = "hmac-sha256:" + hmac.new(
            key, canonical(unsigned), hashlib.sha256
        ).hexdigest()
        content = canonical(envelope) + b"\n"
        temporary = path.with_name(
            f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                pass
            directory_descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        recorded = load_protected_result(path, key, request)
        if recorded is None:
            raise ControlError("protected control result was not durably recorded")
        return recorded
    finally:
        os.close(lock_descriptor)


def regular_bytes(path: Path, label: str, maximum: int = MAX_REQUEST_BYTES) -> bytes:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ControlError(f"{label} must be a non-symlink regular file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise ControlError(f"{label} must contain 1..{maximum} bytes")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ControlError(f"{label} changed identity while being read")
            content = b""
            while len(content) <= maximum:
                block = os.read(descriptor, maximum + 1 - len(content))
                if not block:
                    break
                content += block
            if len(content) > maximum:
                raise ControlError(f"{label} exceeds {maximum} bytes")
            after = os.fstat(descriptor)
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
            ):
                raise ControlError(f"{label} changed while being read")
            return content
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ControlError(f"cannot read {label}: {exc}") from exc


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ControlError(f"{label} has duplicate field {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as exc:
        raise ControlError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ControlError(f"{label} must be a JSON object")
    return value


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def task_key(task: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", task).strip("-").lower()[:32] or "task"
    return f"{slug}-{hashlib.sha256(task.encode()).hexdigest()[:10]}"


def tracker_task(tasks: dict[str, Any], task_id: str) -> dict[str, Any]:
    matches = [
        item
        for item in tasks.get("tasks") or []
        if isinstance(item, dict) and str(item.get("taskId")) == task_id
    ]
    if len(matches) != 1:
        raise ControlError("controlled task is absent or duplicated in the fresh snapshot")
    task = matches[0]
    status = task.get("status")
    if not isinstance(status, str) or not status.strip():
        raise ControlError("controlled task has no concrete tracker status")
    revision = task.get("revision")
    if (
        isinstance(revision, bool)
        or not isinstance(revision, (str, int, float))
        or (isinstance(revision, float) and not math.isfinite(revision))
        or not str(revision).strip()
    ):
        raise ControlError("controlled task has no concrete tracker revision")
    return task


def bound_task_state(
    workspace: Path,
    tasks: dict[str, Any],
    team: str,
    feature: str,
    task_id: str,
) -> dict[str, Any]:
    """Return exact tracker/execution/claim observations for one current task."""

    task = tracker_task(tasks, task_id)
    key = task_key(task_id)

    execution_path = workspace / "executions" / f"{key}.json"
    execution_raw = regular_bytes(execution_path, "task execution", 1024 * 1024)
    execution_record = strict_json(execution_raw, "task execution")
    role = execution_record.get("role")
    attempt = execution_record.get("attempt")
    worktree = execution_record.get("worktree")
    expected_execution = {
        "schemaVersion": 1,
        "featureId": feature,
        "taskId": task_id,
        "taskKey": key,
    }
    if any(execution_record.get(name) != value for name, value in expected_execution.items()):
        raise ControlError("task execution identity mismatch")
    if not ROLE.fullmatch(str(role or "")) or type(attempt) is not int or attempt < 1:
        raise ControlError("task execution has an invalid concrete role/attempt")
    expected_worktree = workspace / "worktrees" / f"{role}#{attempt}-{key}"
    if (
        not isinstance(worktree, str)
        or Path(os.path.realpath(worktree)) != expected_worktree
    ):
        raise ControlError("task execution points outside its exact worktree slot")

    claim_path = workspace / "claims" / f"{key}.json"
    claim_raw = regular_bytes(claim_path, "task claim", 1024 * 1024)
    claim_record = strict_json(claim_raw, "task claim")
    claim_identity = {
        "schemaVersion": 1,
        "team": team,
        "featureId": feature,
        "taskId": task_id,
        "taskKey": key,
        "attempt": attempt,
        "role": role,
        "claimId": claim_record.get("claimId"),
        "targetStatus": task["status"],
    }
    if any(claim_record.get(name) != value for name, value in claim_identity.items()):
        raise ControlError("task claim does not match the fresh task/execution identity")
    claim_id = claim_identity["claimId"]
    if not isinstance(claim_id, str) or not claim_id:
        raise ControlError("task claim has no immutable claim identity")
    expected_claim_digest = sha256_bytes(canonical(claim_identity))
    if claim_record.get("claimDigest") != expected_claim_digest:
        raise ControlError("task claim digest is invalid")

    return {
        "task": task,
        "role": role,
        "attempt": attempt,
        "execution": execution_record,
        "claim": claim_record,
        "observedTaskRevision": task["revision"],
        "observedTaskStatus": task["status"],
        "observedExecutionSha256": sha256_bytes(execution_raw),
        "observedClaimSha256": sha256_bytes(claim_raw),
    }


def request_from_projection(value: dict[str, Any]) -> dict[str, Any]:
    if not set(value).issubset(PROJECTION_KEYS) or not REQUEST_KEYS.issubset(value):
        raise ControlError("control projection has an unexpected schema")
    request = {key: value[key] for key in REQUEST_KEYS}
    validate_shape(request)
    return request


def authenticate_request(
    request: dict[str, Any],
    *,
    repository: Path,
    workspace: Path,
    lead_role: str,
    require_active: bool,
) -> dict[str, Any]:
    body_digest = sha256_bytes(canonical(control_body(request)))
    try:
        verifier = verify_entry if require_active else verify_published_entry
        capability = verifier(str(repository), str(workspace), request, body_digest)
    except (CapabilityError, OSError, ValueError) as exc:
        raise ControlError(f"Team Lead capability rejected: {exc}") from exc
    if capability.get("executionKind") != "gate" or capability.get("role") != lead_role:
        raise ControlError("worker control requires the configured Team Lead gate capability")
    if request.get("actor") != lead_role:
        raise ControlError("control actor does not match the configured Team Lead")
    if require_active and request["expiresAt"] <= int(time.time()):
        raise ControlError("control request expired")
    return capability


def parse_time(raw: Any, label: str) -> datetime:
    if not isinstance(raw, str) or not raw.strip():
        raise ControlError(f"{label} is not an ISO-8601 timestamp")
    value = raw.strip().replace("Z", "+00:00")
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ControlError(f"{label} is not an ISO-8601 timestamp") from exc
    if result.tzinfo is None:
        raise ControlError(f"{label} has no timezone")
    return result.astimezone(timezone.utc)


def read_config_integer(path: Path, key: str, default: int, minimum: int, maximum: int) -> int:
    if not path.exists():
        return default
    raw = regular_bytes(path, "team configuration", 1024 * 1024).decode("utf-8")
    matches = []
    for line in raw.splitlines():
        if line.startswith(f"{key}="):
            value = line.split("=", 1)[1].split("#", 1)[0].strip().strip('"')
            matches.append(value)
    if len(matches) > 1:
        raise ControlError(f"team configuration repeats {key}")
    if not matches:
        return default
    try:
        result = int(matches[0])
    except ValueError as exc:
        raise ControlError(f"team configuration {key} is not an integer") from exc
    if not minimum <= result <= maximum:
        raise ControlError(
            f"team configuration {key} must be from {minimum} to {maximum}"
        )
    return result


def control_body(request: dict[str, Any]) -> dict[str, Any]:
    return {
        key: request.get(key)
        for key in (
            "schemaVersion",
            "id",
            "team",
            "featureId",
            "taskId",
            "attempt",
            "actor",
            "marker",
            "targetStatus",
            "createdAt",
            "expiresAt",
            "action",
            "targetRole",
            "observedLifecycleCreatedAt",
            "observedTaskRevision",
            "observedTaskStatus",
            "observedExecutionSha256",
            "observedClaimSha256",
            "priorNudgeControlId",
            "reasonCode",
        )
    }


def validate_shape(request: dict[str, Any]) -> None:
    if set(request) != REQUEST_KEYS or request.get("schemaVersion") != 1:
        raise ControlError("control request has an unexpected schema")
    if not CONTROL_ID.fullmatch(str(request.get("id") or "")):
        raise ControlError("control request has an invalid identity")
    action = request.get("action")
    if action not in ACTIONS or request.get("marker") != "worker-control":
        raise ControlError("control request has an invalid action/marker")
    if request.get("targetStatus") is not None:
        raise ControlError("control request cannot carry a status transition")
    if request.get("reasonCode") not in REASONS:
        raise ControlError("control request has an invalid reason code")
    task = request.get("taskId")
    role = request.get("targetRole")
    attempt = request.get("attempt")
    if action in {"nudge-task", "restart-task"}:
        safe_text(task, "task identity")
        if role is not None or type(attempt) is not int or attempt < 1:
            raise ControlError("task control requires one task and positive expected attempt")
        revision = request.get("observedTaskRevision")
        if (
            isinstance(revision, bool)
            or not isinstance(revision, (str, int, float))
            or (isinstance(revision, float) and not math.isfinite(revision))
            or not str(revision).strip()
        ):
            raise ControlError("task control requires a concrete tracker revision")
        safe_text(request.get("observedTaskStatus"), "observed task status", 128)
        for field in ("observedExecutionSha256", "observedClaimSha256"):
            if not DIGEST.fullmatch(str(request.get(field) or "")):
                raise ControlError(f"task control has an invalid {field}")
        prior_nudge = request.get("priorNudgeControlId")
        if action == "restart-task":
            if not CONTROL_ID.fullmatch(str(prior_nudge or "")):
                raise ControlError("restart-task requires a prior completed nudge identity")
        elif prior_nudge is not None:
            raise ControlError("nudge-task cannot carry prior nudge evidence")
    else:
        if task != "-" or attempt != 0 or not ROLE.fullmatch(str(role or "")):
            raise ControlError("role control requires one valid concrete role")
        for field in (
            "observedTaskRevision",
            "observedTaskStatus",
            "observedExecutionSha256",
            "observedClaimSha256",
            "priorNudgeControlId",
        ):
            if request.get(field) is not None:
                raise ControlError(f"role control cannot carry {field}")
    observed = request.get("observedLifecycleCreatedAt")
    if action in {"restart-task", "retire-role", "restart-role"}:
        safe_text(observed, "observed lifecycle creation time", 128)
    elif observed is not None:
        raise ControlError("nudge-task cannot carry lifecycle authority")
    created = request.get("createdAt")
    expires = request.get("expiresAt")
    if type(created) is not int or type(expires) is not int:
        raise ControlError("control request time fields must be integers")
    if expires <= created or expires - created > REQUEST_TTL_SECONDS:
        raise ControlError("control request has an invalid validity interval")
    body_digest = "sha256:" + hashlib.sha256(canonical(control_body(request))).hexdigest()
    if request.get("controlBodySha256") != body_digest:
        raise ControlError("control request body digest mismatch")


def discover_completed_nudge_projection(
    repository: Path,
    workspace: Path,
    team: str,
    feature: str,
    task: str,
    attempt: int,
    actor: str,
    requested_id: str | None,
    binding: dict[str, Any],
) -> str:
    if requested_id is not None and not CONTROL_ID.fullmatch(requested_id):
        raise ControlError("--nudge-control-id is invalid")
    done = workspace / "control-outbox" / "done"
    if not done.is_dir() or done.is_symlink():
        raise ControlError("restart-task requires a completed nudge projection")
    paths = (
        [done / f"{requested_id}.json"]
        if requested_id is not None
        else sorted(done.glob("control-*.json"))
    )
    candidates: list[tuple[datetime, str]] = []
    for path in paths:
        try:
            projection = strict_json(
                regular_bytes(path, "completed nudge projection"),
                "completed nudge projection",
            )
            request = request_from_projection(projection)
            if (
                projection.get("result") != "completed"
                or request.get("action") != "nudge-task"
                or request.get("team") != team
                or request.get("featureId") != feature
                or request.get("taskId") != task
                or request.get("attempt") != attempt
                or request.get("actor") != actor
                or request.get("observedTaskRevision")
                != binding["observedTaskRevision"]
                or request.get("observedTaskStatus") != binding["observedTaskStatus"]
                or request.get("observedExecutionSha256")
                != binding["observedExecutionSha256"]
                or request.get("observedClaimSha256")
                != binding["observedClaimSha256"]
            ):
                continue
            capability = authenticate_request(
                request,
                repository=repository,
                workspace=workspace,
                lead_role=actor,
                require_active=False,
            )
            if capability.get("role") != actor:
                continue
            candidates.append(
                (parse_time(projection.get("processedAt"), "nudge processedAt"), request["id"])
            )
        except (ControlError, OSError):
            if requested_id is not None:
                raise
            continue
    if not candidates:
        raise ControlError(
            "restart-task requires a signed completed nudge; run nudge-task first"
        )
    return max(candidates)[1]


def request_command(args: argparse.Namespace) -> int:
    repository = safe_directory(
        os.environ.get("STARTUP_FACTORY_CANONICAL_REPO", ""), "canonical repository"
    )
    workspace = safe_directory(
        os.environ.get("STARTUP_FACTORY_CANONICAL_WORKSPACE", ""),
        "canonical workspace",
    )
    if os.path.commonpath((str(repository), str(workspace))) != str(repository):
        raise ControlError("canonical workspace escapes canonical repository")
    team = safe_text(os.environ.get("STARTUP_FACTORY_TEAM"), "team", 63)
    feature = safe_text(os.environ.get("STARTUP_FACTORY_FEATURE_ID"), "feature identity")
    actor = safe_text(os.environ.get("STARTUP_FACTORY_ROLE"), "actor", 80)
    if os.environ.get("STARTUP_FACTORY_EXECUTION_KIND") != "gate":
        raise ControlError("worker control requires a launched gate-role capability")
    lead_role, _, _ = parse_preset(workspace, repository, team, feature)
    if actor != lead_role:
        raise ControlError("worker control requests require the configured Team Lead")
    binding: dict[str, Any] | None = None
    prior_nudge: str | None = None
    if args.action in {"nudge-task", "restart-task"}:
        if not args.task or args.role or not args.expected_attempt:
            raise ControlError("task control requires --task and --expected-attempt")
        task, attempt, role = safe_text(args.task, "task identity"), args.expected_attempt, None
        tasks = strict_json(
            regular_bytes(workspace / "tasks.json", "task snapshot", 64 * 1024 * 1024),
            "task snapshot",
        )
        if tasks.get("featureId") != feature or tasks.get("team") not in {None, team}:
            raise ControlError("task snapshot does not match the launched team/feature")
        binding = bound_task_state(workspace, tasks, team, feature, task)
        if binding["attempt"] != attempt:
            raise ControlError("--expected-attempt is stale")
        if args.action == "restart-task":
            prior_nudge = discover_completed_nudge_projection(
                repository,
                workspace,
                team,
                feature,
                task,
                attempt,
                actor,
                args.nudge_control_id,
                binding,
            )
        elif args.nudge_control_id is not None:
            raise ControlError("nudge-task does not accept --nudge-control-id")
    else:
        if not args.role or args.task or args.expected_attempt is not None:
            raise ControlError("role control requires --role only")
        if args.nudge_control_id is not None:
            raise ControlError("role control does not accept --nudge-control-id")
        if not ROLE.fullmatch(args.role):
            raise ControlError("invalid target role")
        task, attempt, role = "-", 0, args.role
    if args.action != "nudge-task" and not args.observed_created_at:
        raise ControlError("lifecycle-changing control requires --observed-created-at")
    if args.action == "nudge-task" and args.observed_created_at:
        raise ControlError("nudge-task does not accept --observed-created-at")
    now = int(time.time())
    identity = {
        "repository": str(repository),
        "workspace": str(workspace),
        "team": team,
        "featureId": feature,
        "action": args.action,
        "taskId": task,
        "attempt": attempt,
        "targetRole": role,
        "observedLifecycleCreatedAt": args.observed_created_at,
        "observedTaskRevision": binding["observedTaskRevision"] if binding else None,
        "observedTaskStatus": binding["observedTaskStatus"] if binding else None,
        "observedExecutionSha256": binding["observedExecutionSha256"] if binding else None,
        "observedClaimSha256": binding["observedClaimSha256"] if binding else None,
        "priorNudgeControlId": prior_nudge,
        "reasonCode": args.reason_code,
    }
    control_id = "control-" + hashlib.sha256(canonical(identity)).hexdigest()[:32]
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "id": control_id,
        "team": team,
        "featureId": feature,
        "taskId": task,
        "attempt": attempt,
        "actor": actor,
        "marker": "worker-control",
        "targetStatus": None,
        "createdAt": now,
        "expiresAt": now + REQUEST_TTL_SECONDS,
        "action": args.action,
        "targetRole": role,
        "observedLifecycleCreatedAt": args.observed_created_at,
        "observedTaskRevision": binding["observedTaskRevision"] if binding else None,
        "observedTaskStatus": binding["observedTaskStatus"] if binding else None,
        "observedExecutionSha256": binding["observedExecutionSha256"] if binding else None,
        "observedClaimSha256": binding["observedClaimSha256"] if binding else None,
        "priorNudgeControlId": prior_nudge,
        "reasonCode": args.reason_code,
    }
    outbox = private_directory(workspace / "control-outbox", "control outbox")
    for state in ("pending", "done", "failed"):
        private_directory(outbox / state, f"control outbox {state}")
    capability = {
        "id": os.environ.get("STARTUP_FACTORY_OUTBOX_CAPABILITY_ID", ""),
        "secret": os.environ.get("STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET", ""),
        "instance": os.environ.get("STARTUP_FACTORY_INSTANCE", ""),
        "expires": os.environ.get("STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT", ""),
    }
    if not all(capability.values()):
        raise ControlError("launched-role capability is incomplete")
    try:
        value["producerCapability"] = sign_entry(
            value,
            canonical(control_body(value)),
            capability["id"],
            capability["secret"],
            capability["instance"],
            int(capability["expires"]),
        )
    except (CapabilityError, ValueError) as exc:
        raise ControlError(f"cannot sign control request: {exc}") from exc
    value["controlBodySha256"] = sha256_bytes(canonical(control_body(value)))
    validate_shape(value)

    pending = outbox / "pending"
    target = pending / f"{control_id}.json"
    content = canonical(value) + b"\n"
    if target.exists() or target.is_symlink():
        prior = strict_json(
            regular_bytes(target, "existing pending control request"),
            "existing pending control request",
        )
        validate_shape(prior)
        authenticate_request(
            prior,
            repository=repository,
            workspace=workspace,
            lead_role=lead_role,
            require_active=True,
        )
        if prior.get("id") != control_id or operation_digest(prior) != operation_digest(value):
            raise ControlError("pending control identity belongs to a different operation")
        print(target)
        return 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError:
        if regular_bytes(target, "existing control request") != content:
            raise ControlError("control identity already exists with different bytes")
        print(target)
        return 0
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    print(target)
    return 0


def parse_preset(
    workspace: Path, repository: Path, team: str, feature: str
) -> tuple[str, str | None, str]:
    path = workspace / "preset.env"
    if not path.exists():
        probe = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().with_name("team-context.py")),
                "probe",
                "--repo",
                str(repository),
                "--workspace",
                str(workspace),
                "--team",
                team,
                "--feature",
                feature,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if probe.returncode == 3:
            return "team-lead", None, "integrator"
        if probe.returncode != 0:
            raise ControlError("could not inspect protected team preset authority")
    context_process = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve().with_name("team-context.py")),
            "verify",
            "--repo",
            str(repository),
            "--workspace",
            str(workspace),
            "--team",
            team,
            "--feature",
            feature,
            "--skill",
            str(Path(__file__).resolve().parent.parent),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if context_process.returncode != 0:
        raise ControlError("protected team preset authority is unavailable")
    try:
        context = json.loads(context_process.stdout)
    except ValueError as exc:
        raise ControlError("protected team preset authority is malformed") from exc
    values: dict[str, str] = {}
    for line in regular_bytes(path, "team preset", 64 * 1024).decode("utf-8").splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            raise ControlError(f"team preset repeats {key}")
        values[key] = value
    preset = str(context.get("preset") or "")
    if preset == "-":
        source_values = values
        selected_preset: str | None = None
    elif not re.fullmatch(r"[a-z0-9-]{2,63}", preset):
        raise ControlError("protected team preset has an invalid preset identity")
    else:
        team_file = Path(__file__).resolve().parent.parent / "teams" / f"{preset}.md"
        source_values = {}
        for line in regular_bytes(team_file, "protected team preset", 1024 * 1024).decode(
            "utf-8"
        ).splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in source_values:
                raise ControlError(f"protected team preset repeats {key}")
            source_values[key] = value.strip()
        selected_preset = preset
    source: dict[str, str] = {}
    for key in ("PROTOCOL_TEAM_LEAD", "PROTOCOL_INTEGRATOR"):
        if key in source_values:
            source[key] = source_values[key]
    if set(source) != {"PROTOCOL_TEAM_LEAD", "PROTOCOL_INTEGRATOR"}:
        raise ControlError("protected team preset lacks lifecycle role mappings")
    lead = source["PROTOCOL_TEAM_LEAD"]
    integrator = source["PROTOCOL_INTEGRATOR"]
    if not ROLE.fullmatch(lead) or not ROLE.fullmatch(integrator):
        raise ControlError("protected team preset has an invalid lifecycle role mapping")
    return lead, selected_preset, integrator


def execution(workspace: Path, task: str) -> dict[str, Any]:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", task).strip("-").lower()[:32] or "task"
    key = f"{slug}-{hashlib.sha256(task.encode()).hexdigest()[:10]}"
    path = workspace / "executions" / f"{key}.json"
    value = strict_json(regular_bytes(path, "task execution", 1024 * 1024), "task execution")
    if value.get("taskId") != task or value.get("taskKey") != key:
        raise ControlError("task execution identity mismatch")
    return value


def next_mailbox(workspace: Path, role: str) -> Path:
    mailbox_root = private_directory(workspace / "mailbox", "mailbox root")
    directory = private_directory(mailbox_root / role, "role mailbox")
    maximum = 0
    for path in directory.iterdir():
        match = re.fullmatch(r"([0-9]{3})-[a-z0-9-]+[.]md", path.name)
        if match:
            maximum = max(maximum, int(match.group(1)))
    if maximum >= 999:
        raise ControlError("mailbox sequence is exhausted")
    return directory / f"{maximum + 1:03d}-worker-control.md"


def write_result(source: Path, destination: Path, value: dict[str, Any]) -> None:
    result = dict(value)
    result.setdefault(
        "processedAt", datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    content = canonical(result) + b"\n"
    temporary = source.with_name(f".{source.name}.tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, source)
        os.replace(source, destination)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def require_completed_nudge(
    request: dict[str, Any],
    *,
    repository: Path,
    workspace: Path,
    lifecycle_root: Path,
    lead_role: str,
    grace_seconds: int,
) -> None:
    nudge_id = str(request.get("priorNudgeControlId") or "")
    if not CONTROL_ID.fullmatch(nudge_id):
        raise ControlError("restart-task has no valid prior nudge identity")
    path = workspace / "control-outbox" / "done" / f"{nudge_id}.json"
    projection = strict_json(
        regular_bytes(path, "completed nudge projection"),
        "completed nudge projection",
    )
    nudge = request_from_projection(projection)
    authenticate_request(
        nudge,
        repository=repository,
        workspace=workspace,
        lead_role=lead_role,
        require_active=False,
    )
    if (
        nudge.get("action") != "nudge-task"
        or nudge.get("team") != request.get("team")
        or nudge.get("featureId") != request.get("featureId")
        or nudge.get("taskId") != request.get("taskId")
        or nudge.get("attempt") != request.get("attempt")
        or nudge.get("observedTaskRevision")
        != request.get("observedTaskRevision")
        or nudge.get("observedTaskStatus") != request.get("observedTaskStatus")
        or nudge.get("observedExecutionSha256")
        != request.get("observedExecutionSha256")
        or nudge.get("observedClaimSha256") != request.get("observedClaimSha256")
    ):
        raise ControlError("completed nudge does not bind the same task attempt")
    result_directory, result_key = result_authority(lifecycle_root, repository)
    protected = load_protected_result(
        protected_result_path(result_directory, nudge_id), result_key, nudge
    )
    if protected is None or protected.get("result") != "completed":
        raise ControlError("restart-task requires protected completed nudge evidence")
    processed = parse_time(protected.get("processedAt"), "protected nudge processedAt")
    requested = datetime.fromtimestamp(request["createdAt"], timezone.utc)
    if processed > requested:
        raise ControlError("restart request predates its completed nudge evidence")
    elapsed = time.time() - processed.timestamp()
    if elapsed < grace_seconds:
        remaining = int(grace_seconds - elapsed + 0.999)
        raise ControlDeferred(f"nudge grace has {remaining}s remaining")


def issue_control_grant(
    *,
    launcher: Path,
    lifecycle_root: Path,
    repository: Path,
    request: dict[str, Any],
    target: str,
) -> None:
    grant = launcher.parent / "control-grant.py"
    if grant.is_symlink() or not grant.is_file():
        raise ControlError("protected control-grant issuer is unavailable")
    completed = subprocess.run(
        [
            sys.executable,
            str(grant),
            "issue",
            "--root",
            str(lifecycle_root),
            "--repo",
            str(repository),
            "--team",
            str(request["team"]),
            "--feature",
            str(request["featureId"]),
            "--action",
            str(request["action"]),
            "--target",
            target,
            "--attempt",
            str(request["attempt"] if request["action"] == "restart-task" else 0),
            "--generation",
            str(request.get("observedLifecycleCreatedAt") or "-"),
            "--control-id",
            str(request["id"]),
            "--reason",
            "authorized",
        ],
        cwd=repository,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        output = (completed.stdout or "").strip()[-2000:]
        raise ControlError(
            f"could not issue protected control grant ({completed.returncode}): {output}"
        )


def reconcile_one(
    request: dict[str, Any], *, repository: Path, workspace: Path, tasks: dict[str, Any],
    launcher: Path, lifecycle_root: Path, lead_role: str, preset: str | None,
    integrator_role: str, authenticated: bool = False, nudge_grace_seconds: int = 120,
) -> str:
    validate_shape(request)
    if request.get("team") != tasks.get("team", request.get("team")):
        raise ControlError("control request team does not match the runtime snapshot")
    if request.get("featureId") != tasks.get("featureId"):
        raise ControlError("control request feature does not match the fresh snapshot")
    if not authenticated:
        authenticate_request(
            request,
            repository=repository,
            workspace=workspace,
            lead_role=lead_role,
            require_active=True,
        )

    action = request["action"]
    environment = os.environ.copy()
    environment["STARTUP_FACTORY_CONTROL_BROKER"] = "1"
    environment["STARTUP_FACTORY_CONTROL_REASON"] = "authorized"
    environment["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = str(lifecycle_root)
    observed = request.get("observedLifecycleCreatedAt")
    if observed:
        environment["STARTUP_FACTORY_EXPECTED_LIFECYCLE_CREATED_AT"] = str(observed)
    command: list[str]
    if action in {"nudge-task", "restart-task"}:
        task_id = str(request["taskId"])
        task = tracker_task(tasks, task_id)
        for field, current in (
            ("observedTaskRevision", task["revision"]),
            ("observedTaskStatus", task["status"]),
        ):
            if request.get(field) != current:
                raise ControlError(f"control request {field} is stale")
        binding = bound_task_state(
            workspace,
            tasks,
            str(request["team"]),
            str(request["featureId"]),
            task_id,
        )
        for field in ("observedExecutionSha256", "observedClaimSha256"):
            if request.get(field) != binding[field]:
                raise ControlError(f"control request {field} is stale")
        if binding["attempt"] != request.get("attempt"):
            raise ControlError("control request expected attempt is stale")
        board_path = launcher.parent.parent / "config" / "statuses.config.json"
        board = strict_json(
            regular_bytes(board_path, "status board", 1024 * 1024), "status board"
        )
        working = {
            str(item.get("name"))
            for item in board.get("tasks", {}).get("statuses", [])
            if item.get("kind") == "working"
        }
        if len(working) != 1 or task.get("status") not in working:
            raise ControlError("task control requires the current configured working status")
        labels = {str(item).casefold() for item in task.get("labels") or []}
        try:
            ignored = {
                str(item).casefold()
                for item in json.loads(
                    os.environ.get("STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON", '["human-work"]')
                )
            }
        except (TypeError, ValueError) as exc:
            raise ControlError("ignored-label policy is invalid") from exc
        if labels & ignored:
            raise ControlError("human-owned or [Blocked] task cannot be nudged or restarted")
        hold = subprocess.run(
            [
                sys.executable,
                str(launcher.parent / "task-hold.py"),
                "check",
                "--repo", str(repository),
                "--workspace", str(workspace),
                "--team", str(request["team"]),
                "--feature", str(request["featureId"]),
                "--task", task_id,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if hold.returncode != 0:
            raise ControlError("held or human-owned task cannot be nudged or restarted")
        role = str(binding["role"])
        if action == "nudge-task":
            mailbox = next_mailbox(workspace, role)
            content = (
                f"From: {lead_role}\nRe: {task_id}\n---\n"
                "The expected assignment artifact is still missing. Publish the named "
                "[review-request], [andon], or context-request artifact before exiting.\n"
            )
            descriptor = os.open(
                mailbox,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            return f"nudged task {task_id} through {mailbox}"
        require_completed_nudge(
            request,
            repository=repository,
            workspace=workspace,
            lifecycle_root=lifecycle_root,
            lead_role=lead_role,
            grace_seconds=nudge_grace_seconds,
        )
        command = [
            str(launcher), "restart-task", request["team"], request["featureId"],
            task_id, str(request["attempt"]), request["id"],
        ]
        if preset:
            command.append(preset)
        issue_control_grant(
            launcher=launcher,
            lifecycle_root=lifecycle_root,
            repository=repository,
            request=request,
            target=task_id,
        )
    else:
        role = str(request["targetRole"])
        if role == integrator_role:
            raise ControlError("generic role control cannot target the integrator")
        if action == "retire-role" and role == lead_role:
            raise ControlError("bare role retirement cannot target the configured Team Lead")
        subcommand = "retire-role" if action == "retire-role" else "restart-role"
        if subcommand == "retire-role":
            command = [
                str(launcher), subcommand, request["team"], request["featureId"], role,
                str(request["observedLifecycleCreatedAt"]), request["id"],
            ]
        else:
            command = [
                str(launcher), subcommand, request["team"], request["featureId"],
                role, str(request["observedLifecycleCreatedAt"]), request["id"],
            ]
            if preset:
                command.append(preset)
        issue_control_grant(
            launcher=launcher,
            lifecycle_root=lifecycle_root,
            repository=repository,
            request=request,
            target=role,
        )
    completed = subprocess.run(
        command,
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )
    output = (completed.stdout or "").strip()[-2000:]
    if completed.returncode != 0:
        raise ControlError(
            f"protected launcher rejected {action} with exit {completed.returncode}: {output}"
        )
    return output or f"{action} completed"


def isolate_pending_entry(path: Path, failed: Path, detail: str) -> None:
    """Move one untrusted entry aside without reading or following its contents."""

    identity = hashlib.sha256(path.name.encode("utf-8", errors="surrogateescape")).hexdigest()[:32]
    destination = failed / f"rejected-{identity}.entry"
    if destination.exists() or destination.is_symlink():
        destination = failed / f"rejected-{identity}-{secrets.token_hex(8)}.entry"
    try:
        os.replace(path, destination)
    except OSError as exc:
        raise ControlError(f"cannot isolate unsafe pending control entry: {exc}") from exc

    reason = destination.with_suffix(destination.suffix + ".json")
    value = {
        "schemaVersion": 1,
        "entry": destination.name,
        "detail": detail[:2000],
        "rejectedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    temporary = reason.with_name(f".{reason.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, reason)
        parent = os.open(failed, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    print(f"worker-control: rejected {path.name}: {detail}", file=sys.stderr)


def bounded_pending_batch(pending: Path) -> tuple[list[Path], bool]:
    """Return at most one bounded pass without materializing an attacker-sized dir."""

    selected: list[Path] = []
    retained = False
    with os.scandir(pending) as entries:
        for entry in entries:
            if len(selected) >= MAX_CONTROL_REQUESTS_PER_PASS:
                retained = True
                break
            selected.append(Path(entry.path))
    return sorted(selected, key=lambda item: item.name), retained


def reconcile_command(args: argparse.Namespace) -> int:
    repository = safe_directory(args.repo, "canonical repository")
    workspace = safe_directory(args.workspace, "canonical workspace")
    lifecycle_root = safe_directory(args.lifecycle_root, "protected lifecycle root")
    launcher = Path(args.launcher)
    if not launcher.is_absolute() or launcher.is_symlink() or not launcher.is_file():
        raise ControlError("launcher must be an absolute non-symlink regular file")
    tasks = strict_json(regular_bytes(Path(args.tasks), "fresh task snapshot", 64 * 1024 * 1024), "fresh task snapshot")
    if tasks.get("featureId") != args.feature:
        raise ControlError("fresh task snapshot feature mismatch")
    if tasks.get("team") not in {None, args.team}:
        raise ControlError("fresh task snapshot team mismatch")
    lead_role, preset, integrator_role = parse_preset(
        workspace, repository, args.team, args.feature
    )
    result_directory, result_key = result_authority(lifecycle_root, repository)
    outbox = private_directory(workspace / "control-outbox", "control outbox")
    pending = private_directory(outbox / "pending", "control outbox pending")
    done = private_directory(outbox / "done", "control outbox done")
    failed = private_directory(outbox / "failed", "control outbox failed")
    nudge_grace_seconds = read_config_integer(
        launcher.parent.parent / "config" / "team.config.md",
        "STALE_NUDGE_GRACE_SECONDS",
        120,
        1,
        86400,
    )
    if (
        MAX_CONTROL_REQUESTS_PER_PASS < 1
        or MAX_CONTROL_REQUEST_BYTES_PER_PASS < MAX_REQUEST_BYTES
    ):
        raise ControlError("worker-control pass limits are internally inconsistent")
    processed = rejected = deferred = 0
    paths, retained = bounded_pending_batch(pending)
    request_bytes = 0
    for path in paths:
        if not re.fullmatch(r"control-[0-9a-f]{32}[.]json", path.name):
            isolate_pending_entry(
                path, failed, "control pending directory contains an unexpected entry"
            )
            rejected += 1
            continue
        try:
            try:
                request_info = path.lstat()
            except OSError as exc:
                raise ControlError(f"cannot inspect control request: {exc}") from exc
            if (
                stat.S_ISREG(request_info.st_mode)
                and 0 < request_info.st_size <= MAX_REQUEST_BYTES
                and request_bytes + request_info.st_size
                > MAX_CONTROL_REQUEST_BYTES_PER_PASS
            ):
                retained = True
                break
            remaining_bytes = MAX_CONTROL_REQUEST_BYTES_PER_PASS - request_bytes
            request_raw = regular_bytes(
                path,
                "control request",
                min(MAX_REQUEST_BYTES, remaining_bytes),
            )
            request_bytes += len(request_raw)
            request = strict_json(request_raw, "control request")
            validate_shape(request)
            if path.name != f"{request['id']}.json":
                raise ControlError("control request filename and identity mismatch")
            protected_path = protected_result_path(result_directory, request["id"])
            protected = load_protected_result(protected_path, result_key, request)
            authenticate_request(
                request,
                repository=repository,
                workspace=workspace,
                lead_role=lead_role,
                require_active=protected is None,
            )
            if protected is None:
                # Reserve protected result capacity before any lifecycle side
                # effect. Retention failure therefore fails closed while the
                # request is still pending and safe to retry.
                compact_protected_results(result_directory, result_key)
                protected = load_protected_result(protected_path, result_key, request)
            if protected is None:
                try:
                    detail = reconcile_one(
                        request,
                        repository=repository,
                        workspace=workspace,
                        tasks=tasks,
                        launcher=launcher,
                        lifecycle_root=lifecycle_root,
                        lead_role=lead_role,
                        preset=preset,
                        integrator_role=integrator_role,
                        authenticated=True,
                        nudge_grace_seconds=nudge_grace_seconds,
                    )
                    verdict = "completed"
                except ControlDeferred as exc:
                    print(f"worker-control: deferred {request['id']}: {exc}", file=sys.stderr)
                    deferred += 1
                    retained = True
                    continue
                except ControlError as exc:
                    detail = str(exc)
                    verdict = "failed"
                protected = store_protected_result(
                    result_directory, result_key, request, verdict, detail
                )
            result = {
                **request,
                "result": protected["result"],
                "detail": protected["detail"],
                "processedAt": protected["processedAt"],
            }
            destination = (
                done / path.name
                if protected["result"] == "completed"
                else failed / path.name
            )
        except ControlError as exc:
            isolate_pending_entry(path, failed, str(exc))
            rejected += 1
            continue
        write_result(path, destination, result)
        processed += 1
    print(
        json.dumps(
            {
                "deferred": deferred,
                "processed": processed,
                "rejected": rejected,
                "retained": retained,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    request = subparsers.add_parser("request")
    request.add_argument("--action", choices=sorted(ACTIONS), required=True)
    request.add_argument("--task")
    request.add_argument("--role")
    request.add_argument("--expected-attempt", type=int)
    request.add_argument("--observed-created-at")
    request.add_argument("--nudge-control-id")
    request.add_argument("--reason-code", choices=sorted(REASONS), required=True)
    request.set_defaults(func=request_command)
    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--repo", required=True)
    reconcile.add_argument("--workspace", required=True)
    reconcile.add_argument("--team", required=True)
    reconcile.add_argument("--feature", required=True)
    reconcile.add_argument("--tasks", required=True)
    reconcile.add_argument("--launcher", required=True)
    reconcile.add_argument("--lifecycle-root", required=True)
    reconcile.set_defaults(func=reconcile_command)
    return result


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ControlError, OSError, subprocess.SubprocessError) as exc:
        print(f"worker-control: {exc}", file=sys.stderr)
        raise SystemExit(1)
