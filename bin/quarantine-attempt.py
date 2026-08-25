#!/usr/bin/env python3
"""Inventory and receipt authority for dirty task-attempt quarantine.

The workspace manifest is an operator-facing projection only.  The authoritative
prepare/final receipts live beside the protected lifecycle records and are HMAC
authenticated with the lifecycle key.  A prepare receipt is durable before Git
moves the worktree, which lets a later invocation finish a move whose original
broker process exited between rename and finalization.
"""

from __future__ import annotations

import argparse
import base64
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


CONTROL_ID = re.compile(r"[A-Za-z0-9._:-]{1,160}")
ROLE = re.compile(r"[a-z0-9][a-z0-9-]{1,79}")
TEAM = re.compile(r"[A-Za-z0-9._-]{1,63}")
MAX_RECEIPT_BYTES = 256 * 1024 * 1024


class QuarantineError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def safe_text(value: str, label: str, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise QuarantineError(f"invalid {label}")
    return value


def normalized_absolute(path: str, label: str) -> Path:
    value = Path(path)
    if not value.is_absolute() or Path(os.path.normpath(path)) != value:
        raise QuarantineError(f"{label} must be an absolute normalized path")
    return value


def existing_directory(path: str, label: str) -> Path:
    value = normalized_absolute(path, label)
    try:
        resolved = value.resolve(strict=True)
        info = value.lstat()
    except OSError as exc:
        raise QuarantineError(f"{label} is unavailable: {exc}") from exc
    if resolved != value or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise QuarantineError(f"{label} must be a non-symlink directory")
    return value


def beneath(path: Path, parent: Path, label: str) -> None:
    try:
        if os.path.commonpath((str(path), str(parent))) != str(parent):
            raise QuarantineError(f"{label} escapes its protected workspace")
    except ValueError as exc:
        raise QuarantineError(f"{label} escapes its protected workspace") from exc


def private_directory(path: Path, label: str) -> Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    try:
        info = path.lstat()
    except OSError as exc:
        raise QuarantineError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise QuarantineError(f"{label} must be an owned mode-0700 directory")
    return path


def stable_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_regular(path: Path, label: str, maximum: int = MAX_RECEIPT_BYTES) -> bytes:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise QuarantineError(f"{label} must be a non-symlink regular file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise QuarantineError(f"{label} has an invalid size")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if stable_identity(opened) != stable_identity(before):
                raise QuarantineError(f"{label} changed identity while opening")
            content = bytearray()
            while len(content) <= maximum:
                block = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
            after = os.fstat(descriptor)
            if stable_identity(after) != stable_identity(opened):
                raise QuarantineError(f"{label} changed while being read")
            if len(content) > maximum:
                raise QuarantineError(f"{label} exceeds its size limit")
            return bytes(content)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise QuarantineError(f"cannot read {label}: {exc}") from exc


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QuarantineError(f"receipt repeats field {key}")
        result[key] = value
    return result


def parse_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=strict_object)
    except (UnicodeError, ValueError) as exc:
        raise QuarantineError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise QuarantineError(f"{label} must be a JSON object")
    return value


def authority(root_raw: str, repository: Path) -> tuple[Path, bytes]:
    root = existing_directory(root_raw, "protected lifecycle root")
    info = root.lstat()
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) != 0o700:
        raise QuarantineError("protected lifecycle root must be owned and mode 0700")
    try:
        common = Path(os.path.commonpath((str(root), str(repository))))
    except ValueError:
        common = Path()
    if common in {root, repository}:
        raise QuarantineError("protected lifecycle root and repository must be disjoint")

    key_path = root / "record-auth.key"
    key_info = key_path.lstat()
    if (
        stat.S_ISLNK(key_info.st_mode)
        or not stat.S_ISREG(key_info.st_mode)
        or key_info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(key_info.st_mode) != 0o600
        or key_info.st_size != 32
    ):
        raise QuarantineError("protected lifecycle authentication key is unsafe")
    key = read_regular(key_path, "protected lifecycle authentication key", 32)
    if len(key) != 32:
        raise QuarantineError("protected lifecycle authentication key is malformed")
    directory = private_directory(root / "quarantine-receipts", "quarantine receipt directory")
    return directory, key


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def inventory_tree(root: Path) -> dict[str, Any]:
    """Hash every directory entry and byte without following symlinks."""

    root = existing_directory(str(root), "quarantine worktree")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, flags)
    entries: list[dict[str, Any]] = []
    total_bytes = 0

    def walk(directory_fd: int, prefix: bytes) -> None:
        nonlocal total_bytes
        try:
            names = sorted((os.fsencode(name) for name in os.listdir(directory_fd)))
        except OSError as exc:
            raise QuarantineError(f"cannot enumerate quarantine worktree: {exc}") from exc
        for name in names:
            if name in {b".", b".."} or b"/" in name or b"\x00" in name:
                raise QuarantineError("worktree contains an unsafe directory entry")
            relative = name if not prefix else prefix + b"/" + name
            try:
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise QuarantineError("worktree changed while being inventoried") from exc
            mode = stat.S_IMODE(before.st_mode)
            if stat.S_ISREG(before.st_mode):
                file_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(file_fd)
                    if stable_identity(opened) != stable_identity(before):
                        raise QuarantineError("regular file changed identity during inventory")
                    digest = hashlib.sha256()
                    size = 0
                    while True:
                        block = os.read(file_fd, 1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                        size += len(block)
                    after = os.fstat(file_fd)
                    named_after = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (
                        stable_identity(after) != stable_identity(opened)
                        or (named_after.st_dev, named_after.st_ino)
                        != (opened.st_dev, opened.st_ino)
                        or size != opened.st_size
                    ):
                        raise QuarantineError("regular file changed during inventory")
                finally:
                    os.close(file_fd)
                entries.append(
                    {
                        "pathB64": b64(relative),
                        "kind": "file",
                        "mode": mode,
                        "size": size,
                        "sha256": "sha256:" + digest.hexdigest(),
                    }
                )
                total_bytes += size
            elif stat.S_ISDIR(before.st_mode):
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if stable_identity(opened) != stable_identity(before):
                        raise QuarantineError("directory changed identity during inventory")
                    entries.append(
                        {"pathB64": b64(relative), "kind": "directory", "mode": mode}
                    )
                    walk(child_fd, relative)
                    after = os.fstat(child_fd)
                    named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (
                        stable_identity(after) != stable_identity(opened)
                        or (named_after.st_dev, named_after.st_ino)
                        != (opened.st_dev, opened.st_ino)
                    ):
                        raise QuarantineError("directory changed during inventory")
                finally:
                    os.close(child_fd)
            elif stat.S_ISLNK(before.st_mode):
                target = os.readlink(name, dir_fd=directory_fd)
                target_bytes = os.fsencode(target)
                after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stable_identity(after) != stable_identity(before):
                    raise QuarantineError("symbolic link changed during inventory")
                entries.append(
                    {
                        "pathB64": b64(relative),
                        "kind": "symlink",
                        "mode": mode,
                        "size": len(target_bytes),
                        "sha256": "sha256:" + hashlib.sha256(target_bytes).hexdigest(),
                    }
                )
                total_bytes += len(target_bytes)
            else:
                raise QuarantineError(
                    "worktree contains a socket, device, FIFO, or other unsupported entry"
                )

    try:
        root_before = os.fstat(descriptor)
        walk(descriptor, b"")
        root_after = os.fstat(descriptor)
        named_after = root.lstat()
        if (
            stable_identity(root_after) != stable_identity(root_before)
            or (named_after.st_dev, named_after.st_ino)
            != (root_before.st_dev, root_before.st_ino)
        ):
            raise QuarantineError("worktree root changed during inventory")
    finally:
        os.close(descriptor)

    body = {
        "algorithm": "sha256-tree-v1",
        "rootMode": stat.S_IMODE(root_before.st_mode),
        "entries": entries,
    }
    return {
        **body,
        "entryCount": len(entries),
        "totalBytes": total_bytes,
        "treeSha256": "sha256:" + hashlib.sha256(canonical(body)).hexdigest(),
    }


def sign(value: dict[str, Any], key: bytes) -> dict[str, Any]:
    unsigned = dict(value)
    result = dict(unsigned)
    result["auth"] = "hmac-sha256:" + hmac.new(
        key, canonical(unsigned), hashlib.sha256
    ).hexdigest()
    return result


def verify_signed(value: dict[str, Any], key: bytes, kind: str) -> None:
    supplied = value.get("auth")
    if not isinstance(supplied, str) or not re.fullmatch(
        r"hmac-sha256:[0-9a-f]{64}", supplied
    ):
        raise QuarantineError(f"protected {kind} receipt has an invalid authenticator")
    unsigned = dict(value)
    del unsigned["auth"]
    expected = "hmac-sha256:" + hmac.new(
        key, canonical(unsigned), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise QuarantineError(f"protected {kind} receipt authentication failed")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def store_once(path: Path, value: dict[str, Any]) -> None:
    content = canonical(value) + b"\n"
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
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
        fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_receipt(path: Path, key: bytes, kind: str) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise QuarantineError(
            f"protected {kind} receipt must be an owned mode-0600 regular file"
        )
    value = parse_object(read_regular(path, f"protected {kind} receipt"), f"protected {kind} receipt")
    verify_signed(value, key, kind)
    if value.get("schemaVersion") != 1 or value.get("receiptKind") != kind:
        raise QuarantineError(f"protected {kind} receipt has an unexpected schema")
    return value


def operation_from(
    args: argparse.Namespace, repository: Path, workspace: Path, protected_root: Path
) -> dict[str, Any]:
    if not CONTROL_ID.fullmatch(args.control_id):
        raise QuarantineError("invalid quarantine control identity")
    if not ROLE.fullmatch(args.role):
        raise QuarantineError("invalid quarantine role")
    if args.team in {".", ".."} or not TEAM.fullmatch(args.team):
        raise QuarantineError("invalid team identity")
    safe_text(args.task, "task identity")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", args.task_key):
        raise QuarantineError("invalid task key")
    safe_text(args.branch, "quarantine branch", 255)
    safe_text(args.head, "Git head", 128)
    if args.attempt < 1:
        raise QuarantineError("quarantine attempt must be positive")
    source = normalized_absolute(args.source, "source worktree")
    destination = normalized_absolute(args.destination, "quarantine destination")
    beneath(source, workspace, "source worktree")
    repository_key = hashlib.sha256(str(repository).encode()).hexdigest()
    destination_parent = (
        protected_root / "quarantine-worktrees" / repository_key / args.team / args.task_key
    )
    beneath(destination, destination_parent, "quarantine destination")
    parent = existing_directory(str(destination.parent), "protected quarantine parent")
    if parent != destination_parent:
        raise QuarantineError("quarantine destination has an unexpected protected parent")
    parent_info = parent.lstat()
    if parent_info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(parent_info.st_mode) != 0o700:
        raise QuarantineError("protected quarantine parent must be owned and mode 0700")
    if source == destination:
        raise QuarantineError("source and quarantine destination must differ")
    return {
        "repository": str(repository),
        "workspace": str(workspace),
        "team": args.team,
        "taskId": args.task,
        "taskKey": args.task_key,
        "role": args.role,
        "attempt": args.attempt,
        "controlId": args.control_id,
        "branch": args.branch,
        "sourceWorktree": str(source),
        "quarantineWorktree": str(destination),
        "head": args.head,
    }


def receipt_paths(directory: Path, operation: dict[str, Any]) -> tuple[Path, Path]:
    identity = hashlib.sha256(canonical(operation)).hexdigest()
    return directory / f"{identity}.prepare.json", directory / f"{identity}.final.json"


def validate_prepare(
    value: dict[str, Any], operation: dict[str, Any], current: dict[str, Any] | None
) -> None:
    if set(value) != {
        "schemaVersion",
        "receiptKind",
        "operation",
        "inventory",
        "preparedAt",
        "auth",
    }:
        raise QuarantineError("protected prepare receipt has an unexpected schema")
    if value.get("operation") != operation:
        raise QuarantineError("protected prepare receipt operation mismatch")
    inventory = value.get("inventory")
    if not isinstance(inventory, dict) or inventory.get("algorithm") != "sha256-tree-v1":
        raise QuarantineError("protected prepare receipt inventory is malformed")
    if current is not None and current != inventory:
        raise QuarantineError("worktree bytes changed after quarantine prepare")


def validate_final(
    value: dict[str, Any], operation: dict[str, Any], prepare: dict[str, Any]
) -> None:
    if set(value) != {
        "schemaVersion",
        "receiptKind",
        "operation",
        "prepareSha256",
        "inventorySha256",
        "finalizedAt",
        "auth",
    }:
        raise QuarantineError("protected final receipt has an unexpected schema")
    if value.get("operation") != operation:
        raise QuarantineError("protected final receipt operation mismatch")
    if value.get("prepareSha256") != "sha256:" + hashlib.sha256(canonical(prepare)).hexdigest():
        raise QuarantineError("protected final receipt does not bind its prepare receipt")
    if value.get("inventorySha256") != prepare["inventory"].get("treeSha256"):
        raise QuarantineError("protected final receipt inventory mismatch")


def project_manifest(
    path: Path,
    operation: dict[str, Any],
    prepare: dict[str, Any],
    final: dict[str, Any],
    prepare_path: Path,
    final_path: Path,
) -> None:
    beneath(path, Path(operation["workspace"]), "quarantine manifest")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise QuarantineError("quarantine manifest parent must not be a symlink")
    inventory = prepare["inventory"]
    value = {
        "schemaVersion": 2,
        "team": operation["team"],
        "taskId": operation["taskId"],
        "taskKey": operation["taskKey"],
        "role": operation["role"],
        "attempt": operation["attempt"],
        "controlId": operation["controlId"],
        "branch": operation["branch"],
        "worktree": operation["quarantineWorktree"],
        "head": operation["head"],
        "treeSha256": inventory["treeSha256"],
        "entryCount": inventory["entryCount"],
        "totalBytes": inventory["totalBytes"],
        "prepareReceipt": str(prepare_path),
        "finalReceipt": str(final_path),
        "quarantinedAt": final["finalizedAt"],
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
            handle.write(canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def context(args: argparse.Namespace) -> tuple[dict[str, Any], Path, bytes, Path, Path]:
    repository = existing_directory(args.repo, "canonical repository")
    workspace = existing_directory(args.workspace, "canonical workspace")
    beneath(workspace, repository, "canonical workspace")
    directory, key = authority(args.root, repository)
    operation = operation_from(
        args, repository, workspace, existing_directory(args.root, "protected lifecycle root")
    )
    prepare_path, final_path = receipt_paths(directory, operation)
    return operation, directory, key, prepare_path, final_path


def destination_command(args: argparse.Namespace) -> int:
    repository = existing_directory(args.repo, "canonical repository")
    authority(args.root, repository)
    root = existing_directory(args.root, "protected lifecycle root")
    if args.team in {".", ".."} or not TEAM.fullmatch(args.team):
        raise QuarantineError("invalid team identity")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", args.task_key):
        raise QuarantineError("invalid task key")
    if args.attempt < 1:
        raise QuarantineError("quarantine attempt must be positive")
    if not re.fullmatch(r"[0-9a-f]{12}", args.suffix):
        raise QuarantineError("invalid quarantine suffix")
    repository_key = hashlib.sha256(str(repository).encode()).hexdigest()
    parent = root
    for name, label in (
        ("quarantine-worktrees", "quarantine worktree root"),
        (repository_key, "repository quarantine root"),
        (args.team, "team quarantine root"),
        (args.task_key, "task quarantine root"),
    ):
        parent = private_directory(parent / name, label)
    print(parent / f"attempt-{args.attempt}-{args.suffix}")
    return 0


def prepare_command(args: argparse.Namespace) -> int:
    operation, _, key, prepare_path, final_path = context(args)
    source = Path(operation["sourceWorktree"])
    if not source.exists() or source.is_symlink():
        raise QuarantineError("source worktree is absent before quarantine prepare")
    current = inventory_tree(source)
    prepare = load_receipt(prepare_path, key, "prepare")
    if prepare is None:
        prepare = sign(
            {
                "schemaVersion": 1,
                "receiptKind": "prepare",
                "operation": operation,
                "inventory": current,
                "preparedAt": utc_now(),
            },
            key,
        )
        store_once(prepare_path, prepare)
        prepare = load_receipt(prepare_path, key, "prepare")
        if prepare is None:
            raise QuarantineError("protected prepare receipt was not durably recorded")
    validate_prepare(prepare, operation, current)
    print(
        json.dumps(
            {
                "prepareReceipt": str(prepare_path),
                "finalReceipt": str(final_path),
                "treeSha256": current["treeSha256"],
                "entryCount": current["entryCount"],
                "totalBytes": current["totalBytes"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def finalize_command(args: argparse.Namespace) -> int:
    operation, _, key, prepare_path, final_path = context(args)
    prepare = load_receipt(prepare_path, key, "prepare")
    if prepare is None:
        raise QuarantineError("protected prepare receipt is absent; refusing orphan quarantine")
    validate_prepare(prepare, operation, None)
    destination = Path(operation["quarantineWorktree"])
    if not destination.exists() or destination.is_symlink():
        raise QuarantineError("quarantine destination is absent during finalization")
    current = inventory_tree(destination)
    validate_prepare(prepare, operation, current)
    final = load_receipt(final_path, key, "final")
    if final is None:
        final = sign(
            {
                "schemaVersion": 1,
                "receiptKind": "final",
                "operation": operation,
                "prepareSha256": "sha256:" + hashlib.sha256(canonical(prepare)).hexdigest(),
                "inventorySha256": current["treeSha256"],
                "finalizedAt": utc_now(),
            },
            key,
        )
        store_once(final_path, final)
        final = load_receipt(final_path, key, "final")
        if final is None:
            raise QuarantineError("protected final receipt was not durably recorded")
    validate_final(final, operation, prepare)
    if args.manifest:
        project_manifest(
            normalized_absolute(args.manifest, "quarantine manifest"),
            operation,
            prepare,
            final,
            prepare_path,
            final_path,
        )
    print(
        json.dumps(
            {
                "prepareReceipt": str(prepare_path),
                "finalReceipt": str(final_path),
                "treeSha256": current["treeSha256"],
                "entryCount": current["entryCount"],
                "totalBytes": current["totalBytes"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    destination = commands.add_parser("destination")
    destination.add_argument("--root", required=True)
    destination.add_argument("--repo", required=True)
    destination.add_argument("--team", required=True)
    destination.add_argument("--task-key", required=True)
    destination.add_argument("--attempt", required=True, type=int)
    destination.add_argument("--suffix", required=True)
    destination.set_defaults(handler=destination_command)
    for name, handler in (("prepare", prepare_command), ("finalize", finalize_command)):
        command = commands.add_parser(name)
        command.add_argument("--root", required=True)
        command.add_argument("--repo", required=True)
        command.add_argument("--workspace", required=True)
        command.add_argument("--team", required=True)
        command.add_argument("--task", required=True)
        command.add_argument("--task-key", required=True)
        command.add_argument("--role", required=True)
        command.add_argument("--attempt", required=True, type=int)
        command.add_argument("--control-id", required=True)
        command.add_argument("--branch", required=True)
        command.add_argument("--source", required=True)
        command.add_argument("--destination", required=True)
        command.add_argument("--head", required=True)
        command.add_argument("--manifest")
        command.set_defaults(handler=handler)
    return result


def main() -> int:
    args = parser().parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, QuarantineError) as exc:
        print(f"quarantine-attempt: {exc}", file=sys.stderr)
        raise SystemExit(1)
