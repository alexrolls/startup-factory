#!/usr/bin/env python3
"""Mint and verify short-lived producer capabilities for the tracker outbox.

The signing secret is delivered only to one launched role process.  The broker
copy lives under the repository's Git common directory, outside every linked
task worktree.  A real OS sandbox must make that broker state unreadable to the
agent process; Unix modes alone are not a same-UID isolation boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


CAPABILITY_ID = re.compile(r"cap-[0-9a-f]{32}")
SIGNATURE = re.compile(r"hmac-sha256:[0-9a-f]{64}")
BODY_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ROLE = re.compile(r"[a-z0-9-]{2,80}")
DEFAULT_TTL_SECONDS = 24 * 60 * 60


class CapabilityError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


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
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise CapabilityError("cannot inspect capability record: %s" % exc) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise CapabilityError("capability record is not a regular file")
        try:
            record = json.loads(_read_protected(path, "capability record"))
        except (UnicodeError, ValueError) as exc:
            raise CapabilityError("invalid capability record") from exc
        if not isinstance(record, dict):
            raise CapabilityError("invalid capability record")
        capability_id = record.get("id")
        if not isinstance(capability_id, str) or path.name != capability_id + ".json":
            raise CapabilityError("capability record identity mismatch")
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
    identity = {
        "repository": record["canonicalRepo"],
        "workspace": record["canonicalWorkspace"],
        "team": record["team"],
        "featureId": record["featureId"],
        "role": record["role"],
        "executionKind": record["executionKind"],
        "taskId": record["taskId"],
        "attempt": record["attempt"],
        "instance": record["instance"],
    }
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
    _write_exclusive(record_path, _canonical(record) + b"\n")
    active_path = active / (_active_key(record) + ".id")
    _replace_owner_only(active_path, (capability_id + "\n").encode("ascii"))
    return {
        "id": capability_id,
        "secret": secret,
        "instance": instance,
        "expiresAt": record["expiresAt"],
    }


def signed_material(
    entry: Dict[str, Any], capability: Dict[str, Any], body_digest: str, actor: str
) -> Dict[str, Any]:
    return {
        "schemaVersion": 1,
        "capabilityId": capability["id"],
        "capabilityInstance": capability["instance"],
        "capabilityExpiresAt": capability["expiresAt"],
        "entrySchemaVersion": entry.get("schemaVersion"),
        "id": entry.get("id"),
        "team": entry.get("team"),
        "featureId": entry.get("featureId"),
        "taskId": entry.get("taskId"),
        "attempt": entry.get("attempt"),
        "actor": actor,
        "marker": entry.get("marker"),
        "targetStatus": entry.get("targetStatus"),
        "createdAt": entry.get("createdAt"),
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
    if require_active:
        # An explicit revocation always wins.  Supersession does not: a relaunch
        # replaces the active pointer of an equally-named instance, and the work
        # the previous boot already enqueued is still authentic, still signed by
        # a record that is still unexpired, and must still reach the board.
        if _is_revoked(revoked, capability_id):
            raise CapabilityError("producer capability was revoked")
        # The pointer must still exist and be readable.  A cleared pointer with
        # no tombstone is either a pre-tombstone revocation or a tampered state
        # directory; neither proves this capability survived, so fail closed.
        # Which id the pointer names no longer matters -- that only records
        # which boot minted last, and the unexpired lease below is the bound
        # that keeps a superseded producer from publishing indefinitely.
        _read_protected(
            active / (_active_key(record) + ".id"), "active capability", 256
        )
        now = int(time.time())
        if isinstance(record.get("expiresAt"), bool) or int(record.get("expiresAt", 0)) <= now:
            raise CapabilityError("producer capability expired")
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
    return {
        "role": role,
        "executionKind": kind,
        "instance": record["instance"],
        "expiresAt": record["expiresAt"],
    }


def verify_entry(
    repository: str,
    workspace: str,
    entry: Dict[str, Any],
    producer_body_digest: str,
) -> Dict[str, Any]:
    """Verify a pending producer entry against its currently active capability."""
    return _verify_entry(
        repository,
        workspace,
        entry,
        producer_body_digest,
        require_active=True,
    )


def verify_published_entry(
    repository: str,
    workspace: str,
    entry: Dict[str, Any],
    producer_body_digest: str,
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
    )


def revoke_task(repository: str, workspace: str, team: str, task: str) -> int:
    """Revoke every active producer capability bound to one task.

    Capability records remain immutable audit evidence.  Removing only their
    protected active pointers makes every previously signed or subsequently
    produced entry fail verification without affecting gate roles or sibling
    tasks.
    """
    repo = _repo(repository)
    workspace_path = Path(workspace)
    if not workspace_path.is_absolute():
        raise CapabilityError("canonical workspace path must be absolute")
    workspace_real = Path(os.path.realpath(workspace_path))
    if workspace_real != workspace_path or not workspace_real.is_dir():
        raise CapabilityError("canonical workspace must be a non-symlink directory")
    _safe_text(team, "team", 63)
    _safe_text(task, "taskId")

    records, active, revoked_dir = state_directories(repo)
    _revoke_matching_records(
        records,
        revoked_dir,
        lambda record: (
            record.get("canonicalRepo") == str(repo)
            and record.get("canonicalWorkspace") == str(workspace_real)
            and record.get("team") == team
            and record.get("executionKind") == "task"
            and record.get("taskId") == task
        ),
    )
    revoked = 0
    for pointer in sorted(active.iterdir(), key=lambda item: item.name):
        try:
            info = pointer.lstat()
        except OSError as exc:
            raise CapabilityError("cannot inspect active capability pointer: %s" % exc) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise CapabilityError("active capability pointer is not an owner-only regular file")
        raw_id = _read_protected(pointer, "active capability", 256)
        try:
            capability_id = raw_id.decode("ascii", errors="strict").strip()
        except UnicodeError as exc:
            raise CapabilityError("active capability identity is not ASCII") from exc
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
        if (
            record.get("canonicalRepo") == str(repo)
            and record.get("canonicalWorkspace") == str(workspace_real)
            and record.get("team") == team
            and record.get("executionKind") == "task"
            and record.get("taskId") == task
        ):
            _record_revocation(revoked_dir, capability_id)
            pointer.unlink()
            revoked += 1
    return revoked


def revoke_role(repository: str, workspace: str, team: str, role: str) -> int:
    """Revoke active gate capabilities for one exact concrete role."""
    repo = _repo(repository)
    workspace_path = Path(workspace)
    if not workspace_path.is_absolute():
        raise CapabilityError("canonical workspace path must be absolute")
    workspace_real = Path(os.path.realpath(workspace_path))
    if workspace_real != workspace_path or not workspace_real.is_dir():
        raise CapabilityError("canonical workspace must be a non-symlink directory")
    _safe_text(team, "team", 63)
    if not ROLE.fullmatch(role):
        raise CapabilityError("invalid capability role")

    records, active, revoked_dir = state_directories(repo)
    _revoke_matching_records(
        records,
        revoked_dir,
        lambda record: (
            record.get("canonicalRepo") == str(repo)
            and record.get("canonicalWorkspace") == str(workspace_real)
            and record.get("team") == team
            and record.get("executionKind") == "gate"
            and record.get("role") == role
        ),
    )
    revoked = 0
    for pointer in sorted(active.iterdir(), key=lambda item: item.name):
        try:
            info = pointer.lstat()
        except OSError as exc:
            raise CapabilityError("cannot inspect active capability pointer: %s" % exc) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise CapabilityError("active capability pointer is not an owner-only regular file")
        raw_id = _read_protected(pointer, "active capability", 256)
        try:
            capability_id = raw_id.decode("ascii", errors="strict").strip()
        except UnicodeError as exc:
            raise CapabilityError("active capability identity is not ASCII") from exc
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
        if (
            record.get("canonicalRepo") == str(repo)
            and record.get("canonicalWorkspace") == str(workspace_real)
            and record.get("team") == team
            and record.get("executionKind") == "gate"
            and record.get("role") == role
        ):
            _record_revocation(revoked_dir, capability_id)
            pointer.unlink()
            revoked += 1
    return revoked


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
    revoke_parser = subparsers.add_parser("revoke-task")
    revoke_parser.add_argument("--repo", required=True)
    revoke_parser.add_argument("--workspace", required=True)
    revoke_parser.add_argument("--team", required=True)
    revoke_parser.add_argument("--task", required=True)
    revoke_role_parser = subparsers.add_parser("revoke-role")
    revoke_role_parser.add_argument("--repo", required=True)
    revoke_role_parser.add_argument("--workspace", required=True)
    revoke_role_parser.add_argument("--team", required=True)
    revoke_role_parser.add_argument("--role", required=True)
    args = parser.parse_args()
    try:
        if args.command == "mint":
            result = mint(
                args.repo, args.workspace, args.team, args.feature, args.role,
                args.kind, args.task, args.attempt, args.instance, args.ttl,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "revoke-task":
            count = revoke_task(args.repo, args.workspace, args.team, args.task)
            print(json.dumps({"revoked": count}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "revoke-role":
            count = revoke_role(args.repo, args.workspace, args.team, args.role)
            print(json.dumps({"revoked": count}, sort_keys=True, separators=(",", ":")))
            return 0
    except CapabilityError as exc:
        print("outbox-capability: %s" % exc, file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
