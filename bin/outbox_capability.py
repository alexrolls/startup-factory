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


def state_directories(repository: str | Path) -> tuple[Path, Path]:
    common = git_common_dir(repository)
    broker = _protected_dir(common / "startup-factory-broker")
    records = _protected_dir(broker / "outbox-capabilities")
    active = _protected_dir(broker / "outbox-active")
    return records, active


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
    task_worktree: str | None = None,
    base_commit: str | None = None,
    runtime_manifest_digest: str | None = None,
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

    records, active = state_directories(repo)
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
    if any(value is not None for value in (task_worktree, base_commit, runtime_manifest_digest)):
        if execution_kind != "task" or not all((task_worktree, base_commit, runtime_manifest_digest)):
            raise CapabilityError("standalone task capability bindings must be complete")
        task_path = Path(str(task_worktree))
        if (
            not task_path.is_absolute()
            or task_path.is_symlink()
            or not (task_path / ".git").is_dir()
            or (task_path / ".git").is_symlink()
        ):
            raise CapabilityError("standalone task worktree must contain an independent .git directory")
        task_path = task_path.resolve(strict=True)
        info = task_path.stat()
        if not re.fullmatch(r"[0-9a-f]{40,64}", str(base_commit)):
            raise CapabilityError("invalid standalone task base commit")
        if not BODY_DIGEST.fullmatch(str(runtime_manifest_digest)):
            raise CapabilityError("invalid standalone runtime manifest digest")
        record.update(
            {
                "schemaVersion": 2,
                "taskWorktree": str(task_path),
                "taskWorktreeId": f"{info.st_dev}:{info.st_ino}",
                "baseCommit": str(base_commit),
                "runtimeManifestDigest": str(runtime_manifest_digest),
            }
        )
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
    records, active = state_directories(repo)
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
    if isinstance(record, dict) and record.get("schemaVersion") == 2:
        required.update({"taskWorktree", "taskWorktreeId", "baseCommit", "runtimeManifestDigest"})
    if not isinstance(record, dict) or set(record) != required or record.get("schemaVersion") not in {1, 2}:
        raise CapabilityError("invalid capability record schema")
    if record.get("id") != capability_id:
        raise CapabilityError("capability record identity mismatch")
    if require_active:
        active_id = _read_protected(
            active / (_active_key(record) + ".id"), "active capability", 256
        )
        if active_id.decode("ascii", errors="strict").strip() != capability_id:
            raise CapabilityError("producer capability was superseded by a newer launch")
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
    verified = {
        "role": role,
        "executionKind": kind,
        "instance": record["instance"],
        "expiresAt": record["expiresAt"],
    }
    if record.get("schemaVersion") == 2:
        task_path = Path(str(record["taskWorktree"]))
        try:
            info = task_path.stat()
        except OSError as exc:
            raise CapabilityError("standalone task worktree is unavailable") from exc
        if task_path.is_symlink() or f"{info.st_dev}:{info.st_ino}" != record["taskWorktreeId"]:
            raise CapabilityError("standalone task worktree identity changed")
        verified.update(
            {
                "taskWorktree": record["taskWorktree"],
                "baseCommit": record["baseCommit"],
                "runtimeManifestDigest": record["runtimeManifestDigest"],
            }
        )
    return verified


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

    records, active = state_directories(repo)
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

    records, active = state_directories(repo)
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
    mint_parser.add_argument("--task-worktree")
    mint_parser.add_argument("--base-commit")
    mint_parser.add_argument("--runtime-manifest-digest")
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
                args.task_worktree, args.base_commit, args.runtime_manifest_digest,
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
