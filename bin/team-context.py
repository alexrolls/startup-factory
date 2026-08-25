#!/usr/bin/env python3
"""Protect the selected team preset from agent-writable workspace changes."""

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
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from outbox_capability import CapabilityError, git_common_dir


TEAM = re.compile(r"[A-Za-z0-9._-]{1,63}")
PRESET = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")
POLICY_LINE = re.compile(rb"(?:REVIEW_MODE|REQUIRED_REVIEW_GATES|PROTOCOL_[A-Z_]+)=")


class ContextError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def protected_directory(path: Path) -> Path:
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ContextError("protected team-context directory is unsafe")
    return path


def protected_bytes(path: Path, label: str, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ContextError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o077
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise ContextError(f"{label} is not an owner-only bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise ContextError(f"{label} changed while it was opened")
        value = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if len(value) != before.st_size:
        raise ContextError(f"{label} changed while it was read")
    return value


def workspace_bytes(path: Path, label: str, maximum: int = 1024 * 1024) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ContextError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ContextError(f"{label} must be a non-symlink regular file")
    if before.st_size <= 0 or before.st_size > maximum:
        raise ContextError(f"{label} must contain 1..{maximum} bytes")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise ContextError(f"{label} changed while it was opened")
        value = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if len(value) != before.st_size:
        raise ContextError(f"{label} changed while it was read")
    return value


def canonical_paths(repository: str, workspace: str) -> tuple[Path, Path]:
    try:
        repo = Path(repository).resolve(strict=True)
        work = Path(workspace).resolve(strict=True)
    except OSError as exc:
        raise ContextError(f"team context path is unavailable: {exc}") from exc
    if not repo.is_dir() or not work.is_dir():
        raise ContextError("team context paths must be directories")
    if Path(os.path.abspath(repository)) != repo or Path(os.path.abspath(workspace)) != work:
        raise ContextError("team context paths must be canonical and symlink-free")
    try:
        if os.path.commonpath((str(repo), str(work))) != str(repo):
            raise ContextError("team workspace escapes the canonical repository")
    except ValueError as exc:
        raise ContextError("team workspace escapes the canonical repository") from exc
    return repo, work


def state(repository: Path) -> tuple[Path, Path]:
    try:
        broker = protected_directory(git_common_dir(repository) / "startup-factory-broker")
    except CapabilityError as exc:
        raise ContextError(str(exc)) from exc
    directory = protected_directory(broker / "team-contexts")
    key_path = broker / "team-context.key"
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
    key = protected_bytes(key_path, "team-context key", 32)
    if len(key) != 32:
        raise ContextError("team-context key is malformed")
    return directory, key_path


def identity(repository: Path, workspace: Path, team: str, feature: str) -> str:
    material = canonical(
        {
            "repository": str(repository),
            "workspace": str(workspace),
            "team": team,
            "featureId": feature,
        }
    )
    return hashlib.sha256(material).hexdigest()


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate_identity(team: str, feature: str, preset: str) -> None:
    if team in {".", ".."} or not TEAM.fullmatch(team):
        raise ContextError("invalid team identity")
    if not feature or len(feature) > 1024 or any(ord(char) < 32 for char in feature):
        raise ContextError("invalid feature identity")
    if preset != "-" and not PRESET.fullmatch(preset):
        raise ContextError("invalid preset identity")


def source_projection(skill: Path, preset: str) -> tuple[bytes | None, bytes | None]:
    if preset == "-":
        return None, None
    source_path = skill / "teams" / f"{preset}.md"
    source = workspace_bytes(source_path, "protected team preset")
    lines = [line for line in source.splitlines(keepends=True) if POLICY_LINE.match(line)]
    projection = f"PRESET={preset}\n".encode("utf-8") + b"".join(lines)
    if projection[-1:] != b"\n":
        projection += b"\n"
    return source, projection


def atomic_replace(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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


def issue(args: argparse.Namespace) -> int:
    repo, workspace = canonical_paths(args.repo, args.workspace)
    validate_identity(args.team, args.feature, args.preset)
    projection = workspace_bytes(workspace / "preset.env", "team preset projection")
    source, expected_projection = source_projection(Path(args.skill), args.preset)
    if expected_projection is not None and not hmac.compare_digest(projection, expected_projection):
        raise ContextError("team preset projection does not match the protected preset")
    directory, key_path = state(repo)
    key = protected_bytes(key_path, "team-context key", 32)
    payload = {
        "schemaVersion": 1,
        "repository": str(repo),
        "workspace": str(workspace),
        "team": args.team,
        "featureId": args.feature,
        "preset": args.preset,
        "projectionSha256": digest(projection),
        "sourceSha256": digest(source) if source is not None else "-",
    }
    value = {"payload": payload}
    value["auth"] = "hmac-sha256:" + hmac.new(key, canonical(value), hashlib.sha256).hexdigest()
    target = directory / (identity(repo, workspace, args.team, args.feature) + ".json")
    atomic_replace(target, canonical(value) + b"\n")
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


def verify(args: argparse.Namespace) -> int:
    repo, workspace = canonical_paths(args.repo, args.workspace)
    validate_identity(args.team, args.feature, args.expected_preset or "-")
    directory, key_path = state(repo)
    key = protected_bytes(key_path, "team-context key", 32)
    target = directory / (identity(repo, workspace, args.team, args.feature) + ".json")
    raw = protected_bytes(target, "team-context receipt", 64 * 1024)
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ContextError("team-context receipt is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"payload", "auth"}:
        raise ContextError("team-context receipt schema is invalid")
    observed = str(value.get("auth") or "")
    unsigned = {"payload": value.get("payload")}
    expected_auth = "hmac-sha256:" + hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(observed, expected_auth):
        raise ContextError("team-context receipt authentication failed")
    payload = value.get("payload")
    required = {
        "schemaVersion",
        "repository",
        "workspace",
        "team",
        "featureId",
        "preset",
        "projectionSha256",
        "sourceSha256",
    }
    if not isinstance(payload, dict) or set(payload) != required or payload.get("schemaVersion") != 1:
        raise ContextError("team-context payload schema is invalid")
    expected_identity = {
        "repository": str(repo),
        "workspace": str(workspace),
        "team": args.team,
        "featureId": args.feature,
    }
    for name, expected_value in expected_identity.items():
        if payload.get(name) != expected_value:
            raise ContextError(f"team-context {name} identity mismatch")
    preset = str(payload.get("preset") or "")
    validate_identity(args.team, args.feature, preset)
    if args.expected_preset is not None and preset != args.expected_preset:
        raise ContextError("team-context preset identity mismatch")
    projection = workspace_bytes(workspace / "preset.env", "team preset projection")
    if not hmac.compare_digest(str(payload.get("projectionSha256")), digest(projection)):
        raise ContextError("team preset projection changed after broker selection")
    source, expected_projection = source_projection(Path(args.skill), preset)
    if expected_projection is not None:
        if not hmac.compare_digest(projection, expected_projection):
            raise ContextError("team preset projection does not match the protected preset")
        if not hmac.compare_digest(str(payload.get("sourceSha256")), digest(source or b"")):
            raise ContextError("protected team preset changed after broker selection")
    elif payload.get("sourceSha256") != "-":
        raise ContextError("manual team-context source identity is invalid")
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


def probe(args: argparse.Namespace) -> int:
    repo, workspace = canonical_paths(args.repo, args.workspace)
    validate_identity(args.team, args.feature, "-")
    directory, _ = state(repo)
    target = directory / (identity(repo, workspace, args.team, args.feature) + ".json")
    try:
        protected_bytes(target, "team-context receipt", 64 * 1024)
    except ContextError as exc:
        if not target.exists() and not target.is_symlink():
            return 3
        raise exc
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    for name, handler in (("issue", issue), ("verify", verify)):
        child = commands.add_parser(name)
        child.add_argument("--repo", required=True)
        child.add_argument("--workspace", required=True)
        child.add_argument("--team", required=True)
        child.add_argument("--feature", required=True)
        child.add_argument("--skill", required=True)
        if name == "issue":
            child.add_argument("--preset", required=True)
        else:
            child.add_argument("--expected-preset")
        child.set_defaults(handler=handler)
    probe_parser = commands.add_parser("probe")
    probe_parser.add_argument("--repo", required=True)
    probe_parser.add_argument("--workspace", required=True)
    probe_parser.add_argument("--team", required=True)
    probe_parser.add_argument("--feature", required=True)
    probe_parser.set_defaults(handler=probe)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.handler(args))
    except (ContextError, OSError, ValueError) as exc:
        print(f"team-context: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
