#!/usr/bin/env python3
"""Protected per-target restart circuit breaker for the lifecycle broker."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PolicyError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError("protected restart timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise PolicyError("protected restart timestamp lacks a timezone")
    return parsed.astimezone(timezone.utc)


def authority(raw_root: str, raw_repo: str) -> tuple[Path, bytes]:
    root = Path(raw_root)
    repo = Path(raw_repo).resolve(strict=True)
    resolved = root.resolve(strict=True)
    info = resolved.lstat()
    if (
        not root.is_absolute()
        or root != resolved
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid not in {0, os.geteuid()}
    ):
        raise PolicyError("lifecycle root must be an owned canonical mode-0700 directory")
    try:
        resolved.relative_to(repo)
    except ValueError:
        pass
    else:
        raise PolicyError("lifecycle root must be outside the agent repository")
    key_path = resolved / "record-auth.key"
    key_info = key_path.lstat()
    if (
        stat.S_ISLNK(key_info.st_mode)
        or not stat.S_ISREG(key_info.st_mode)
        or stat.S_IMODE(key_info.st_mode) != 0o600
        or key_info.st_size != 32
    ):
        raise PolicyError("lifecycle authentication key is unsafe")
    descriptor = os.open(key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        key = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    if len(key) != 32:
        raise PolicyError("lifecycle authentication key must contain 32 bytes")
    directory = resolved / "restart-policies"
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    directory_info = directory.lstat()
    if (
        stat.S_ISLNK(directory_info.st_mode)
        or not stat.S_ISDIR(directory_info.st_mode)
        or stat.S_IMODE(directory_info.st_mode) != 0o700
    ):
        raise PolicyError("protected restart-policy directory is unsafe")
    return directory, key


def read_record(path: Path, key: bytes) -> dict[str, Any] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 65536
    ):
        raise PolicyError("protected restart-policy record is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"payload", "auth"}:
        raise PolicyError("protected restart-policy record has an invalid schema")
    payload = value.get("payload")
    supplied = str(value.get("auth") or "")
    if not isinstance(payload, dict) or not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", supplied):
        raise PolicyError("protected restart-policy record is malformed")
    expected = "hmac-sha256:" + hmac.new(
        key, canonical({"payload": payload}), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise PolicyError("protected restart-policy authentication failed")
    return payload


def write_record(path: Path, key: bytes, payload: dict[str, Any]) -> None:
    envelope = {"payload": payload}
    envelope["auth"] = "hmac-sha256:" + hmac.new(
        key, canonical(envelope), hashlib.sha256
    ).hexdigest()
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(canonical(envelope) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
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


def authorize(args: argparse.Namespace) -> dict[str, Any]:
    if not re.fullmatch(r"control-[0-9a-f]{32}", args.control_id):
        raise PolicyError("invalid control identity")
    if args.reason not in {"automatic", "authorized"}:
        raise PolicyError("restart reason must be automatic or authorized")
    if not 0 <= args.maximum <= 10 or not 0 <= args.backoff_seconds <= 3600:
        raise PolicyError("restart limits are outside their safe ranges")
    directory, key = authority(args.root, args.repo)
    identity = {
        "repository": str(Path(args.repo).resolve(strict=True)),
        "team": args.team,
        "featureId": args.feature,
        "category": args.category,
        "target": args.target,
    }
    digest = hashlib.sha256(canonical(identity)).hexdigest()
    path = directory / f"{digest}.json"
    lock_path = directory / f"{digest}.lock"
    lock_descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_info = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or stat.S_IMODE(lock_info.st_mode) != 0o600
            or lock_info.st_uid not in {0, os.geteuid()}
        ):
            raise PolicyError("protected restart-policy lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        existing = read_record(path, key)
        policy = existing or {
            "schemaVersion": 1,
            **identity,
            "automaticCount": 0,
            "authorizedCount": 0,
            "lastControlId": None,
            "lastReason": None,
            "lastAttempt": None,
            "lastGeneration": None,
            "lastRequestedAt": None,
            "completedControlId": None,
            "completedGeneration": None,
            "completedAt": None,
        }
        if any(policy.get(name) != value for name, value in identity.items()):
            raise PolicyError("protected restart-policy identity collision")
        generation = args.generation
        if policy.get("lastControlId") == args.control_id:
            if (
                policy.get("lastReason") != args.reason
                or policy.get("lastAttempt") != args.attempt
                or policy.get("lastGeneration") != generation
            ):
                raise PolicyError("restart control identity changed meaning")
            return {**policy, "replayed": True}
        current = policy[f"{args.reason}Count"]
        if type(current) is not int or current < 0 or current >= args.maximum:
            raise PolicyError(
                f"{args.reason} restart circuit breaker is open ({current}/{args.maximum})"
            )
        now = datetime.now(timezone.utc)
        if policy.get("lastRequestedAt"):
            elapsed = (now - timestamp(str(policy["lastRequestedAt"]))).total_seconds()
            if elapsed < args.backoff_seconds:
                raise PolicyError(
                    f"restart backoff has {int(args.backoff_seconds - elapsed + 0.999)}s remaining"
                )
        policy[f"{args.reason}Count"] = current + 1
        policy["lastControlId"] = args.control_id
        policy["lastReason"] = args.reason
        policy["lastAttempt"] = args.attempt
        policy["lastGeneration"] = generation
        policy["lastRequestedAt"] = now.isoformat(timespec="seconds").replace("+00:00", "Z")
        # Completion belongs to the current control. Clear the prior control's
        # receipt only when a distinct restart is actually authorized.
        policy["completedControlId"] = None
        policy["completedGeneration"] = None
        policy["completedAt"] = None
        write_record(path, key, policy)
        return {**policy, "replayed": False}
    finally:
        os.close(lock_descriptor)


def check(args: argparse.Namespace) -> dict[str, Any]:
    directory, key = authority(args.root, args.repo)
    identity = {
        "repository": str(Path(args.repo).resolve(strict=True)),
        "team": args.team,
        "featureId": args.feature,
        "category": args.category,
        "target": args.target,
    }
    digest = hashlib.sha256(canonical(identity)).hexdigest()
    policy = read_record(directory / f"{digest}.json", key)
    if policy is None:
        raise PolicyError("restart control is not prepared")
    if any(policy.get(name) != value for name, value in identity.items()):
        raise PolicyError("protected restart-policy identity collision")
    if (
        policy.get("lastControlId") != args.control_id
        or policy.get("lastReason") != args.reason
        or policy.get("lastAttempt") != args.attempt
        or policy.get("lastGeneration") != args.generation
    ):
        raise PolicyError("restart control does not match the protected policy")
    return policy


def complete(args: argparse.Namespace) -> dict[str, Any]:
    """Durably bind one authorized control to its single replacement generation."""

    replacement = str(args.replacement_generation or "")
    if (
        not replacement
        or len(replacement) > 1024
        or any(ord(char) < 32 for char in replacement)
        or replacement == args.generation
    ):
        raise PolicyError("replacement generation must be a distinct safe generation")
    directory, key = authority(args.root, args.repo)
    identity = {
        "repository": str(Path(args.repo).resolve(strict=True)),
        "team": args.team,
        "featureId": args.feature,
        "category": args.category,
        "target": args.target,
    }
    digest = hashlib.sha256(canonical(identity)).hexdigest()
    path = directory / f"{digest}.json"
    lock_path = directory / f"{digest}.lock"
    lock_descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_info = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or stat.S_IMODE(lock_info.st_mode) != 0o600
            or lock_info.st_uid not in {0, os.geteuid()}
        ):
            raise PolicyError("protected restart-policy lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        policy = read_record(path, key)
        if policy is None:
            raise PolicyError("restart control is not prepared")
        if any(policy.get(name) != value for name, value in identity.items()):
            raise PolicyError("protected restart-policy identity collision")
        if (
            policy.get("lastControlId") != args.control_id
            or policy.get("lastReason") != args.reason
            or policy.get("lastAttempt") != args.attempt
            or policy.get("lastGeneration") != args.generation
        ):
            raise PolicyError("restart control does not match the protected policy")
        completed_control = policy.get("completedControlId")
        completed_generation = policy.get("completedGeneration")
        if completed_control is not None:
            if completed_control != args.control_id or completed_generation != replacement:
                raise PolicyError("restart completion changed meaning")
            return {**policy, "replayed": True}
        now = datetime.now(timezone.utc)
        policy["completedControlId"] = args.control_id
        policy["completedGeneration"] = replacement
        policy["completedAt"] = now.isoformat(timespec="seconds").replace("+00:00", "Z")
        write_record(path, key, policy)
        return {**policy, "replayed": False}
    finally:
        os.close(lock_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("authorize", "check", "complete"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--team", required=True)
    parser.add_argument("--feature", required=True)
    parser.add_argument("--category", choices=("task", "gate"), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--control-id", required=True)
    parser.add_argument("--reason", choices=("automatic", "authorized"), required=True)
    parser.add_argument("--maximum", type=int)
    parser.add_argument("--backoff-seconds", type=int)
    parser.add_argument("--replacement-generation")
    args = parser.parse_args()
    for name, value in (("team", args.team), ("feature", args.feature), ("target", args.target)):
        if not value or len(value) > 1024 or any(ord(char) < 32 for char in value):
            raise PolicyError(f"invalid {name}")
    if not re.fullmatch(r"control-[0-9a-f]{32}", args.control_id):
        raise PolicyError("invalid control identity")
    if args.category == "task" and args.attempt < 1:
        raise PolicyError("task restart policy requires a positive attempt")
    if args.category == "gate" and args.attempt != 0:
        raise PolicyError("gate restart policy requires attempt 0")
    if args.command == "authorize":
        if args.maximum is None or args.backoff_seconds is None:
            raise PolicyError("authorize requires maximum and backoff")
        result = authorize(args)
    elif args.command == "complete":
        if args.replacement_generation is None:
            raise PolicyError("complete requires replacement generation")
        result = complete(args)
    else:
        result = check(args)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, PolicyError) as exc:
        print(f"restart-policy: {exc}", file=sys.stderr)
        raise SystemExit(1)
