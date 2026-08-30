#!/usr/bin/env python3
"""Promote capability-scoped agent output into the canonical broker queue."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterable


CAPABILITY = re.compile(r"cap-[0-9a-f]{32}\Z")
IDENTIFIER = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


class PromotionError(RuntimeError):
    pass


def pairs(rows: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        if key in result:
            raise PromotionError("duplicate JSON key")
        result[key] = value
    return result


def private_directory(path: Path, label: str) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise PromotionError(f"{label} path is not canonical")
    descriptor = open_directory(path, label)
    try:
        info = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise PromotionError(f"{label} is not a private directory")


def directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise PromotionError("secure descriptor-relative directory operations are unavailable")
    return os.O_RDONLY | nofollow | directory


def open_directory(path: Path, label: str) -> int:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise PromotionError(f"{label} path is not canonical")
    flags = directory_flags()
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            try:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                raise PromotionError(f"{label} path is unavailable") from exc
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise PromotionError(f"{label} path contains an unsafe component")
            child = os.open(part, flags, dir_fd=descriptor)
            after = os.fstat(child)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(child)
                raise PromotionError(f"{label} path component identity changed")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_file(path: Path, label: str, maximum: int = 65536) -> bytes:
    parent = open_directory(path.parent, label)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
    except OSError as exc:
        os.close(parent)
        raise PromotionError(f"{label} is unsafe") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size <= 0
            or info.st_size > maximum
        ):
            raise PromotionError(f"{label} is unsafe")
        content = bytearray()
        while len(content) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > maximum or len(content) != info.st_size:
            raise PromotionError(f"{label} is unsafe")
        return bytes(content)
    finally:
        os.close(descriptor)
        os.close(parent)


def path_present(path: Path, label: str) -> bool:
    parent = open_directory(path.parent, label)
    try:
        try:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(info.st_mode):
            raise PromotionError(f"{label} is unsafe")
        return True
    finally:
        os.close(parent)


def exclusive(path: Path, content: bytes) -> None:
    parent = open_directory(path.parent, "canonical queue")
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent,
        )
    except BaseException:
        os.close(parent)
        raise
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def promote(entry_path: Path, root: Path, pending: Path, bodies: Path, team: str, feature: str) -> Path:
    capability_dir = entry_path.parent
    if capability_dir.parent != root or CAPABILITY.fullmatch(capability_dir.name) is None:
        raise PromotionError("entry is outside a capability-scoped ingress")
    private_directory(capability_dir, "capability ingress")
    entry_content = read_file(entry_path, "ingress entry", 2 * 1024 * 1024)
    try:
        entry = json.loads(entry_content, object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as exc:
        raise PromotionError("ingress entry is malformed") from exc
    if not isinstance(entry, dict) or entry.get("schemaVersion") != 1:
        raise PromotionError("ingress entry schema is unsupported")
    identifier = str(entry.get("id") or "")
    if IDENTIFIER.fullmatch(identifier) is None:
        raise PromotionError("ingress entry id is invalid")
    capability = entry.get("producerCapability")
    if not isinstance(capability, dict) or capability.get("id") != capability_dir.name:
        raise PromotionError("ingress entry capability binding changed")
    if entry.get("team") != team or entry.get("featureId") != feature:
        raise PromotionError("ingress entry belongs to another team or feature")
    body_path = Path(str(entry.get("bodyPath") or ""))
    if body_path != capability_dir / f"{identifier}.md":
        raise PromotionError("ingress body path is not exact")
    body = read_file(body_path, "ingress body")
    destination_body = bodies / f"{identifier}.md"
    destination_entry = pending / f"{identifier}.json"
    rewritten = dict(entry)
    rewritten["bodyPath"] = str(destination_body)
    rewritten_content = (json.dumps(rewritten, indent=2, ensure_ascii=False) + "\n").encode()
    body_exists = path_present(destination_body, "promoted body")
    entry_exists = path_present(destination_entry, "promoted entry")
    if entry_exists and not body_exists:
        raise PromotionError("canonical queue contains an entry without its body")
    if body_exists:
        if read_file(destination_body, "promoted body") != body:
            raise PromotionError("canonical queue collision")
        if entry_exists:
            if read_file(destination_entry, "promoted entry", 2 * 1024 * 1024) != rewritten_content:
                raise PromotionError("canonical queue collision")
        else:
            exclusive(destination_entry, rewritten_content)
    else:
        exclusive(destination_body, body)
        exclusive(destination_entry, rewritten_content)
    promoted_path = entry_path.with_suffix(".promoted")
    if path_present(promoted_path, "promoted ingress marker"):
        raise PromotionError("promoted ingress marker already exists")
    capability_descriptor = open_directory(capability_dir, "capability ingress")
    try:
        os.replace(
            entry_path.name,
            promoted_path.name,
            src_dir_fd=capability_descriptor,
            dst_dir_fd=capability_descriptor,
        )
        os.fsync(capability_descriptor)
    finally:
        os.close(capability_descriptor)
    return destination_entry


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--pending", required=True)
    parser.add_argument("--bodies", required=True)
    parser.add_argument("--team", required=True)
    parser.add_argument("--feature", required=True)
    parser.add_argument("--entry")
    args = parser.parse_args()
    try:
        root, pending, bodies = map(Path, (args.root, args.pending, args.bodies))
        for path, label in ((root, "ingress root"), (pending, "pending queue"), (bodies, "body queue")):
            private_directory(path, label)
        if args.entry:
            entries = [Path(args.entry)]
        else:
            entries = sorted(root.glob("cap-*/*.json"))
        for entry in entries:
            print(promote(entry, root, pending, bodies, args.team, args.feature))
    except (OSError, PromotionError) as exc:
        print(f"promote-outbox-ingress: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
