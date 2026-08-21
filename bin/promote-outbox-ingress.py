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
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise PromotionError(f"{label} is not a private directory")


def read_file(path: Path, label: str, maximum: int = 65536) -> bytes:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size <= 0 or info.st_size > maximum:
        raise PromotionError(f"{label} is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        return os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)


def exclusive(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


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
    if destination_body.exists() or destination_entry.exists():
        if read_file(destination_body, "promoted body") != body or read_file(destination_entry, "promoted entry", 2 * 1024 * 1024) != rewritten_content:
            raise PromotionError("canonical queue collision")
    else:
        exclusive(destination_body, body)
        try:
            exclusive(destination_entry, rewritten_content)
        except BaseException:
            if destination_body.exists() and read_file(destination_body, "partial promoted body") == body:
                destination_body.unlink()
            raise
        for directory in (bodies, pending):
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    os.replace(entry_path, entry_path.with_suffix(".promoted"))
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
