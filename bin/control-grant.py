#!/usr/bin/env python3
"""Issue and verify lifecycle controls under protected broker authority."""

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class GrantError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def authority(raw_root: str, raw_repo: str) -> tuple[Path, bytes, str]:
    root = Path(raw_root)
    repo = str(Path(raw_repo).resolve(strict=True))
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
        raise GrantError("lifecycle root must be an owned canonical mode-0700 directory")
    try:
        resolved.relative_to(repo)
    except ValueError:
        pass
    else:
        raise GrantError("lifecycle root must be outside the agent repository")
    key_path = resolved / "record-auth.key"
    key_info = key_path.lstat()
    if (
        stat.S_ISLNK(key_info.st_mode)
        or not stat.S_ISREG(key_info.st_mode)
        or stat.S_IMODE(key_info.st_mode) != 0o600
        or key_info.st_uid not in {0, os.geteuid()}
        or key_info.st_size != 32
    ):
        raise GrantError("lifecycle authentication key is unsafe")
    descriptor = os.open(key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        key = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    if len(key) != 32:
        raise GrantError("lifecycle authentication key must contain 32 bytes")
    directory = resolved / "control-grants"
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
        raise GrantError("protected control-grant directory is unsafe")
    return directory, key, repo


def expected(args: argparse.Namespace, repo: str) -> dict[str, Any]:
    for name in ("team", "feature", "target", "generation"):
        value = str(getattr(args, name) or "")
        if not value or len(value) > 1024 or any(ord(char) < 32 for char in value):
            raise GrantError(f"invalid {name}")
    if not re.fullmatch(r"control-[0-9a-f]{32}", args.control_id):
        raise GrantError("invalid control identity")
    if args.action == "restart-task":
        if args.attempt < 1:
            raise GrantError("restart-task grant requires a positive attempt")
    elif args.attempt != 0:
        raise GrantError("role control grant requires attempt 0")
    return {
        "schemaVersion": 1,
        "repository": repo,
        "team": args.team,
        "featureId": args.feature,
        "action": args.action,
        "target": args.target,
        "attempt": args.attempt,
        "generation": args.generation,
        "controlId": args.control_id,
        "reason": args.reason,
    }


def read(path: Path, key: bytes) -> dict[str, Any]:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size <= 0
        or info.st_size > 65536
    ):
        raise GrantError("protected control grant is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"payload", "auth"}:
        raise GrantError("protected control grant has an invalid schema")
    payload, supplied = value.get("payload"), value.get("auth")
    if not isinstance(payload, dict) or not isinstance(supplied, str):
        raise GrantError("protected control grant is malformed")
    unsigned = {"payload": payload}
    expected_auth = "hmac-sha256:" + hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected_auth):
        raise GrantError("protected control grant authentication failed")
    return payload


def write(path: Path, key: bytes, payload: dict[str, Any]) -> None:
    unsigned = {"payload": payload}
    envelope = {
        **unsigned,
        "auth": "hmac-sha256:" + hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest(),
    }
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
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            pass
        parent = os.open(path.parent, os.O_RDONLY)
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("issue", "verify"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--team", required=True)
    parser.add_argument("--feature", required=True)
    parser.add_argument(
        "--action", choices=("restart-task", "retire-role", "restart-role"), required=True
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--control-id", required=True)
    parser.add_argument("--reason", choices=("automatic", "authorized"), required=True)
    args = parser.parse_args()
    directory, key, repo = authority(args.root, args.repo)
    desired = expected(args, repo)
    path = directory / f"{args.control_id}.json"
    if args.command == "issue":
        if not path.exists():
            write(
                path,
                key,
                {
                    **desired,
                    "issuedAt": datetime.now(timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                },
            )
    payload = read(path, key)
    if set(payload) != set(desired) | {"issuedAt"} or any(
        payload.get(name) != value for name, value in desired.items()
    ):
        raise GrantError("protected control grant does not match the requested operation")
    print(path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GrantError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"control-grant: {exc}", file=sys.stderr)
        raise SystemExit(1)
