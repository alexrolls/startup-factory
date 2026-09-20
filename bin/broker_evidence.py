#!/usr/bin/env python3
"""Protected HMAC receipts for tracker publications made by the broker."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
from outbox_capability import (  # noqa: E402
    CapabilityError,
    delivery_directory,
    producer_envelope,
    verify_published_entry,
)


DELIVERY_ID = re.compile(r"delivery-[0-9a-f]{32}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
CAPABILITY_ID = re.compile(r"cap-[0-9a-f]{32}")
ROLE = re.compile(r"[a-z0-9][a-z0-9-]{1,79}")
AUTH = re.compile(r"hmac-sha256:[0-9a-f]{64}")
REVIEW_PUBLICATION_MARKERS = frozenset(
    {
        "review-request",
        "review-approval",
        "team-lead-approval",
        "architecture-approval",
        "sceptical-architecture-approval",
        "security-approval",
    }
)
REVIEW_APPROVAL_MARKERS = REVIEW_PUBLICATION_MARKERS - {"review-request"}
REVIEW_PUBLICATION_FIELDS = frozenset(
    {
        "schemaVersion",
        "receiptKind",
        "repository",
        "workspace",
        "team",
        "featureId",
        "taskId",
        "entryId",
        "attempt",
        "marker",
        "deliveryId",
        "targetStatus",
        "producerRole",
        "executionKind",
        "capabilityId",
        "capabilityInstance",
        "capabilityExpiresAt",
        "producerCapabilitySha256",
        "producerBodySha256",
        "finalBodySha256",
        "trackerBodySha256",
        "reviewBinding",
        "publishedAtUnixNs",
    }
)
PUBLICATION_TRAILER = re.compile(r"(?mi)^[ \t]*delivery-id[ \t]*:[^\n]*$")


class EvidenceError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def safe_text(value: object, label: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EvidenceError("invalid %s" % label)
    if any(ord(character) < 32 for character in value):
        raise EvidenceError("invalid %s" % label)
    return value


def canonical_scope(repository: Path, workspace: Path) -> tuple[Path, Path]:
    if not repository.is_absolute() or not workspace.is_absolute():
        raise EvidenceError("repository and workspace must be absolute canonical paths")
    try:
        repo = repository.resolve(strict=True)
        work = workspace.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError("repository or workspace is unavailable: %s" % exc) from exc
    if repo != repository or work != workspace or not repo.is_dir() or not work.is_dir():
        raise EvidenceError("repository and workspace must be non-symlink directories")
    try:
        work.relative_to(repo)
    except ValueError as exc:
        raise EvidenceError("workspace must be inside the canonical repository") from exc
    return repo, work


def authority(repository: Path) -> tuple[Path, bytes] | None:
    raw = os.environ.get("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT")
    if not raw:
        return None
    root = Path(raw)
    try:
        resolved = root.resolve(strict=True)
        info = resolved.lstat()
    except OSError as exc:
        raise EvidenceError("broker authority root is unavailable: %s" % exc) from exc
    if (
        not root.is_absolute()
        or resolved != root
        or Path(os.path.normpath(str(root))) != root
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid not in {0, os.geteuid()}
    ):
        raise EvidenceError("broker authority root must be canonical private mode 0700")
    try:
        resolved.relative_to(repository.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise EvidenceError("broker authority root must be outside the agent repository")
    key_path = resolved / "record-auth.key"
    try:
        key_info = key_path.lstat()
        if (
            stat.S_ISLNK(key_info.st_mode)
            or not stat.S_ISREG(key_info.st_mode)
            or stat.S_IMODE(key_info.st_mode) != 0o600
            or key_info.st_size != 32
        ):
            raise EvidenceError("broker authority key is unsafe")
        fd = os.open(key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            key = os.read(fd, 33)
        finally:
            os.close(fd)
    except OSError as exc:
        raise EvidenceError("cannot read broker authority key: %s" % exc) from exc
    if len(key) != 32:
        raise EvidenceError("broker authority key must contain exactly 32 bytes")
    directory = resolved / "broker-publications"
    if directory.exists() or directory.is_symlink():
        directory_info = directory.lstat()
        if (
            stat.S_ISLNK(directory_info.st_mode)
            or not stat.S_ISDIR(directory_info.st_mode)
            or stat.S_IMODE(directory_info.st_mode) != 0o700
        ):
            raise EvidenceError("broker publication directory is unsafe")
    else:
        directory.mkdir(mode=0o700)
    return directory, key


def receipt_path(directory: Path, payload: dict) -> Path:
    identity = {
        name: payload[name]
        for name in ("repository", "workspace", "team", "featureId", "taskId", "deliveryId")
    }
    return directory / (hashlib.sha256(canonical(identity)).hexdigest() + ".json")


def read_regular_json(path: Path, label: str) -> dict:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
            raise EvidenceError("%s must be a bounded non-symlink regular file" % label)
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, ValueError) as exc:
        raise EvidenceError("invalid %s: %s" % (label, exc)) from exc
    if not isinstance(value, dict):
        raise EvidenceError("%s must be a JSON object" % label)
    return value


def read_regular_bytes(
    path: Path,
    label: str,
    *,
    maximum: int = 2 * 1024 * 1024,
    owner_only: bool = False,
) -> bytes:
    descriptor = -1
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise EvidenceError("%s must be a non-symlink regular file" % label)
        if info.st_size <= 0 or info.st_size > maximum:
            raise EvidenceError("invalid %s size" % label)
        if owner_only and (
            info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise EvidenceError("%s must be owner-only" % label)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
            or opened.st_size != info.st_size
        ):
            raise EvidenceError("%s changed while it was opened" % label)
        content = b""
        while len(content) <= maximum:
            block = os.read(descriptor, maximum + 1 - len(content))
            if not block:
                break
            content += block
        if len(content) != info.st_size or len(content) > maximum:
            raise EvidenceError("%s changed while it was read" % label)
        return content
    except OSError as exc:
        raise EvidenceError("cannot read %s: %s" % (label, exc)) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def authenticated_envelope(
    path: Path, key: bytes, *, strict_storage: bool = False
) -> tuple[dict, bytes]:
    raw = read_regular_bytes(
        path,
        "protected broker publication",
        maximum=2 * 1024 * 1024,
        owner_only=strict_storage,
    )
    try:
        envelope = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise EvidenceError("invalid protected broker publication: %s" % exc) from exc
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"payload", "auth"}
        or not isinstance(envelope.get("payload"), dict)
        or not AUTH.fullmatch(str(envelope.get("auth") or ""))
    ):
        raise EvidenceError("protected broker publication has an invalid envelope")
    unsigned = {"payload": envelope["payload"]}
    expected = "hmac-sha256:" + hmac.new(
        key, canonical(unsigned), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(str(envelope["auth"]), expected):
        raise EvidenceError("protected broker publication authentication failed")
    if strict_storage and raw != canonical(envelope) + b"\n":
        raise EvidenceError("protected broker publication is not canonically encoded")
    return envelope, raw


def body_digest(entry: dict) -> str:
    raw_path = entry.get("publishBodyPath") or entry.get("stagedBodyPath")
    if not isinstance(raw_path, str):
        raise EvidenceError("published entry has no final body path")
    path = Path(raw_path)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 65536:
            raise EvidenceError("published body is unsafe")
        body = path.read_bytes()
    except OSError as exc:
        raise EvidenceError("cannot read published body: %s" % exc) from exc
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    expected = entry.get("publishBodySha256") or entry.get("stagedBodySha256")
    if digest != expected:
        raise EvidenceError("published body digest mismatch")
    return digest


def review_binding(entry: dict, marker: str) -> dict:
    binding = entry.get("reviewBinding")
    if not isinstance(binding, dict):
        raise EvidenceError("review publication has no broker review binding")
    if marker == "review-request":
        if set(binding) != {"kind", "base", "head", "package"}:
            raise EvidenceError("review request binding has an invalid schema")
        if binding.get("kind") != marker:
            raise EvidenceError("review request binding kind mismatch")
        for name in ("base", "head"):
            if not re.fullmatch(r"[0-9a-f]{40}", str(binding.get(name) or "")):
                raise EvidenceError("review request binding has an invalid %s" % name)
        if not DIGEST.fullmatch(str(binding.get("package") or "")):
            raise EvidenceError("review request binding has an invalid package digest")
    else:
        if set(binding) != {"kind"} or binding.get("kind") != marker:
            raise EvidenceError("review approval binding has an invalid schema")
    # Detach the protected payload from the mutable entry object.
    return json.loads(canonical(binding))


def review_publish_body(
    entry: dict, repository: Path, workspace: Path, delivery: str
) -> tuple[str, str]:
    raw_path = entry.get("publishBodyPath")
    expected = entry.get("publishBodySha256")
    if not isinstance(raw_path, str) or not DIGEST.fullmatch(str(expected or "")):
        raise EvidenceError("review publication has no final publish body")
    path = Path(raw_path)
    try:
        staged = delivery_directory(
            repository,
            workspace,
            str(entry.get("team") or ""),
            str(entry.get("featureId") or ""),
        ).resolve(strict=True)
        lexical = Path(os.path.abspath(path))
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError("review publish body is unavailable: %s" % exc) from exc
    if (
        not path.is_absolute()
        or lexical != resolved
        or resolved.parent != staged
    ):
        raise EvidenceError("review publish body must be a canonical broker-staged file")
    raw = read_regular_bytes(resolved, "review publish body", maximum=65536)
    final_digest = sha256(raw)
    if final_digest != expected:
        raise EvidenceError("review publish body digest mismatch")
    try:
        # tracker-ops reads text with universal-newline translation and removes
        # terminal newlines before appending its idempotency trailer.
        body = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    except UnicodeError as exc:
        raise EvidenceError("review publish body must be UTF-8 text") from exc
    if not body:
        raise EvidenceError("review publish body is empty after tracker normalization")
    trailer = "delivery-id: " + delivery
    if trailer in body or PUBLICATION_TRAILER.search(body):
        raise EvidenceError("review publish body already contains a delivery trailer")
    tracker_body = body + "\n\n" + trailer
    return final_digest, sha256(tracker_body.encode("utf-8"))


def validate_review_payload(payload: dict, repository: Path, workspace: Path) -> None:
    if set(payload) != REVIEW_PUBLICATION_FIELDS:
        raise EvidenceError("protected review publication has an invalid payload schema")
    if payload.get("schemaVersion") != 2 or payload.get("receiptKind") != "review-publication":
        raise EvidenceError("protected review publication has an unsupported schema")
    if payload.get("repository") != str(repository) or payload.get("workspace") != str(workspace):
        raise EvidenceError("protected review publication scope mismatch")
    for name, maximum in (
        ("team", 128),
        ("featureId", 1024),
        ("taskId", 1024),
        ("entryId", 256),
        ("capabilityInstance", 256),
    ):
        safe_text(payload.get(name), name, maximum)
    marker = str(payload.get("marker") or "")
    if marker not in REVIEW_PUBLICATION_MARKERS:
        raise EvidenceError("protected review publication has an invalid marker")
    if not DELIVERY_ID.fullmatch(str(payload.get("deliveryId") or "")):
        raise EvidenceError("protected review publication has an invalid delivery identity")
    if not ROLE.fullmatch(str(payload.get("producerRole") or "")):
        raise EvidenceError("protected review publication has an invalid producer role")
    if not CAPABILITY_ID.fullmatch(str(payload.get("capabilityId") or "")):
        raise EvidenceError("protected review publication has an invalid capability identity")
    for name in (
        "producerCapabilitySha256",
        "producerBodySha256",
        "finalBodySha256",
        "trackerBodySha256",
    ):
        if not DIGEST.fullmatch(str(payload.get(name) or "")):
            raise EvidenceError("protected review publication has an invalid %s" % name)
    for name in ("attempt", "capabilityExpiresAt", "publishedAtUnixNs"):
        value = payload.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise EvidenceError("protected review publication has an invalid %s" % name)
    target = payload.get("targetStatus")
    if marker == "review-request":
        if payload.get("executionKind") != "task":
            raise EvidenceError("review request requires a task producer capability")
        safe_text(target, "review request target status", 128)
    else:
        if payload.get("executionKind") != "gate":
            raise EvidenceError("review approval requires a gate producer capability")
        if target is not None:
            raise EvidenceError("review approval must be comment-only")
    review_binding({"reviewBinding": payload.get("reviewBinding")}, marker)


def write_receipt(
    directory: Path,
    key: bytes,
    payload: dict,
    *,
    timestamp_field: str,
) -> dict:
    envelope = {"payload": payload}
    envelope["auth"] = "hmac-sha256:" + hmac.new(
        key, canonical(envelope), hashlib.sha256
    ).hexdigest()
    path = receipt_path(directory, payload)
    if path.exists() or path.is_symlink():
        existing, _raw = authenticated_envelope(
            path, key, strict_storage=payload.get("schemaVersion") == 2
        )
        old = dict(existing["payload"])
        new = dict(payload)
        old.pop(timestamp_field, None)
        new.pop(timestamp_field, None)
        if old != new:
            raise EvidenceError("protected broker publication identity collision")
        return existing
    temporary = path.with_name(".%s.tmp.%s.%s" % (path.name, os.getpid(), secrets.token_hex(8)))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(canonical(envelope) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return envelope


def review_publication_payload(
    repository: Path, workspace: Path, entry: dict
) -> dict:
    repo, work = canonical_scope(repository, workspace)
    try:
        producer_envelope(entry)
    except CapabilityError as exc:
        raise EvidenceError("broker delivery schema is invalid: %s" % exc) from exc
    delivery = str(entry.get("deliveryId") or "")
    marker = str(entry.get("marker") or "")
    if entry.get("brokerPhase") != "published" or not DELIVERY_ID.fullmatch(delivery):
        raise EvidenceError("broker entry is not a completed publication")
    if marker not in REVIEW_PUBLICATION_MARKERS:
        raise EvidenceError("broker entry is not a governed review publication")
    producer_digest = str(entry.get("stagedBodySha256") or "")
    if not DIGEST.fullmatch(producer_digest):
        raise EvidenceError("review publication has no producer body digest")
    try:
        verified = verify_published_entry(
            str(repo), str(work), entry, producer_digest
        )
    except (CapabilityError, OSError, ValueError) as exc:
        raise EvidenceError("review producer capability is invalid: %s" % exc) from exc
    expected_kind = "task" if marker == "review-request" else "gate"
    if verified.get("executionKind") != expected_kind:
        raise EvidenceError(
            "%s requires a %s producer capability" % (marker, expected_kind)
        )
    capability = entry.get("producerCapability")
    if not isinstance(capability, dict):
        # verify_published_entry currently rejects this first; retain an
        # explicit guard so the receipt constructor never hashes an odd value.
        raise EvidenceError("review producer capability is absent")
    final_digest, tracker_digest = review_publish_body(
        entry, repo, work, delivery
    )
    attempt = entry.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt <= 0:
        raise EvidenceError("review publication has an invalid task attempt")
    payload = {
        "schemaVersion": 2,
        "receiptKind": "review-publication",
        "repository": str(repo),
        "workspace": str(work),
        "team": entry.get("team"),
        "featureId": entry.get("featureId"),
        "taskId": entry.get("taskId"),
        "entryId": entry.get("id"),
        "attempt": attempt,
        "marker": marker,
        "deliveryId": delivery,
        "targetStatus": entry.get("targetStatus"),
        "producerRole": verified.get("role"),
        "executionKind": verified.get("executionKind"),
        "capabilityId": capability.get("id"),
        "capabilityInstance": verified.get("instance"),
        "capabilityExpiresAt": verified.get("expiresAt"),
        "producerCapabilitySha256": sha256(canonical(capability)),
        "producerBodySha256": producer_digest,
        "finalBodySha256": final_digest,
        "trackerBodySha256": tracker_digest,
        "reviewBinding": review_binding(entry, marker),
        "publishedAtUnixNs": time.time_ns(),
    }
    validate_review_payload(payload, repo, work)
    return payload


def record(repository: Path, workspace: Path, entry_path: Path) -> dict:
    entry = read_regular_json(entry_path, "published broker entry")
    try:
        producer_envelope(entry)
    except CapabilityError as exc:
        raise EvidenceError("broker delivery schema is invalid: %s" % exc) from exc
    marker = str(entry.get("marker") or "")
    configured = authority(repository)
    if configured is None:
        if marker in REVIEW_PUBLICATION_MARKERS:
            raise EvidenceError(
                "protected lifecycle authority is required for review publication"
            )
        return {"protected": False}
    directory, key = configured
    if marker in REVIEW_PUBLICATION_MARKERS:
        payload = review_publication_payload(repository, workspace, entry)
        return write_receipt(
            directory, key, payload, timestamp_field="publishedAtUnixNs"
        )
    delivery = str(entry.get("deliveryId") or "")
    if entry.get("brokerPhase") != "published" or not DELIVERY_ID.fullmatch(delivery):
        raise EvidenceError("broker entry is not a completed publication")
    final_digest = body_digest(entry)
    payload = {
        "schemaVersion": 1,
        "repository": str(repository.resolve(strict=True)),
        "workspace": str(workspace.resolve(strict=True)),
        "team": entry.get("team"),
        "featureId": entry.get("featureId"),
        "taskId": entry.get("taskId"),
        "marker": entry.get("marker"),
        "deliveryId": delivery,
        "targetStatus": entry.get("targetStatus"),
        "finalBodySha256": final_digest,
        "publishedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return write_receipt(directory, key, payload, timestamp_field="publishedAt")


def verify_review_publication(
    repository: Path,
    workspace: Path,
    *,
    team: str,
    feature: str,
    task: str,
    marker: str,
    delivery: str,
    target_status: object,
    tracker_body: str,
) -> dict:
    """Verify one exact tracker review artifact against protected broker state.

    The returned projection intentionally omits the HMAC while including a
    digest of the canonical receipt file. Consumers can bind that digest and
    every protected payload field into a larger approval-evidence digest.
    """
    repo, work = canonical_scope(repository, workspace)
    if marker not in REVIEW_PUBLICATION_MARKERS:
        raise EvidenceError("marker is not a governed review publication")
    if not DELIVERY_ID.fullmatch(delivery):
        raise EvidenceError("invalid review publication delivery identity")
    safe_text(team, "team", 128)
    safe_text(feature, "featureId", 1024)
    safe_text(task, "taskId", 1024)
    if not isinstance(tracker_body, str) or not tracker_body:
        raise EvidenceError("tracker review publication body must be non-empty text")
    configured = authority(repo)
    if configured is None:
        raise EvidenceError("protected lifecycle authority is unavailable")
    directory, key = configured
    identity = {
        "repository": str(repo),
        "workspace": str(work),
        "team": team,
        "featureId": feature,
        "taskId": task,
        "deliveryId": delivery,
    }
    path = directory / (hashlib.sha256(canonical(identity)).hexdigest() + ".json")
    envelope, raw = authenticated_envelope(path, key, strict_storage=True)
    payload = envelope["payload"]
    validate_review_payload(payload, repo, work)
    expected = {
        **identity,
        "schemaVersion": 2,
        "receiptKind": "review-publication",
        "marker": marker,
        "targetStatus": target_status,
        "trackerBodySha256": sha256(tracker_body.encode("utf-8")),
    }
    mismatched = [
        name for name, value in expected.items() if payload.get(name) != value
    ]
    if mismatched:
        raise EvidenceError(
            "protected review publication mismatch: %s" % ", ".join(mismatched)
        )
    return {**payload, "receiptSha256": sha256(raw)}


def require_review_authority(repository: Path, workspace: Path) -> None:
    repo, _work = canonical_scope(repository, workspace)
    if authority(repo) is None:
        raise EvidenceError("protected lifecycle authority is required for review publication")


def verify_delivery(
    repository: Path,
    workspace: Path,
    *,
    team: str,
    feature: str,
    task: str,
    marker: str,
    delivery: str,
    target_status: object,
    final_body_digest: str,
) -> bool:
    configured = authority(repository)
    if configured is None:
        return False
    directory, key = configured
    material = {
        "repository": str(repository.resolve(strict=True)),
        "workspace": str(workspace.resolve(strict=True)),
        "team": team,
        "featureId": feature,
        "taskId": task,
        "deliveryId": delivery,
    }
    path = directory / (hashlib.sha256(canonical(material)).hexdigest() + ".json")
    envelope = read_regular_json(path, "protected broker publication")
    if set(envelope) != {"payload", "auth"} or not isinstance(envelope.get("payload"), dict):
        return False
    supplied = str(envelope.get("auth") or "")
    unsigned = {"payload": envelope["payload"]}
    expected_auth = "hmac-sha256:" + hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected_auth):
        return False
    payload = envelope["payload"]
    expected = {
        **material,
        "schemaVersion": 1,
        "marker": marker,
        "targetStatus": target_status,
        "finalBodySha256": final_body_digest,
    }
    return all(payload.get(name) == value for name, value in expected.items())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--entry", type=Path)
    parser.add_argument("--preflight-review", action="store_true")
    args = parser.parse_args()
    try:
        if args.preflight_review == (args.entry is not None):
            raise EvidenceError("choose exactly one of --entry or --preflight-review")
        if args.preflight_review:
            require_review_authority(args.repo, args.workspace)
            print(json.dumps({"protected": True}, sort_keys=True))
        else:
            print(json.dumps(record(args.repo, args.workspace, args.entry), sort_keys=True))
        return 0
    except EvidenceError as exc:
        print("broker-evidence: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
