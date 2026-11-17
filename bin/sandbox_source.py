#!/usr/bin/env python3
"""Finite Git-object source packages and a guest-only workspace initializer.

The host exporter reads only an explicit approved commit through a trusted raw
object reader and a required secret scanner. No Git configuration, hook, remote,
index, history, untracked path, or host pathname is included. The guest creates
an independent shallow repository; neither package nor guest acknowledgment
grants publication or integration authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unicodedata
import zlib
from typing import Callable

MAX_FILES = 4096
MAX_OBJECTS = 8192
MAX_ENTRIES = 8192
MAX_DIRECTORIES = 4096
MAX_PATH_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 40 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
_OID = re.compile(r"[0-9a-f]{40}\Z")
_HEX = re.compile(r"[0-9a-f]*\Z")
_RESERVED = {".git", ".teamwork", ".startup-factory", "startup-factory-broker", ".sf",
             ".startup-factory-control", ".sf-control"}


class SourceError(ValueError):
    pass


def object_id(kind: str, body: bytes) -> str:
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(body)).encode("ascii") + b"\0" + body, usedforsecurity=False).hexdigest()


def _oid(value: object) -> str:
    if type(value) is not str or not _OID.fullmatch(value):
        raise SourceError("source requires an exact SHA-1 Git object identity")
    return value


def _path(value: str) -> str:
    if not value or len(value.encode("utf-8")) > 1024 or unicodedata.normalize("NFC", value) != value:
        raise SourceError("source path is unsupported")
    parts = value.split("/")
    if len(parts) > 32 or any(not part or part in {".", ".."} or unicodedata.normalize("NFKC", part).casefold() in _RESERVED or part[-1:] in {".", " "} or ":" in part or "\\" in part or any(ord(c) < 32 or ord(c) == 127 or unicodedata.category(c) == "Cf" or 0xD800 <= ord(c) <= 0xDFFF for c in part) for part in parts):
        raise SourceError("source path is unsupported")
    return value


def _tree_entries(raw: bytes):
    offset = 0
    previous = None
    seen = set()
    while offset < len(raw):
        space = raw.find(b" ", offset)
        nul = raw.find(b"\0", space + 1)
        if space < 0 or nul < 0 or nul + 21 > len(raw):
            raise SourceError("invalid source tree object")
        mode = raw[offset:space]
        name = raw[space + 1:nul]
        if mode not in {b"40000", b"100644", b"100755"} or not name or b"/" in name or name in seen:
            raise SourceError("source symlinks, submodules, or tree entries are unsupported")
        order = name + (b"/" if mode == b"40000" else b"\0")
        if previous is not None and order <= previous:
            raise SourceError("source tree order is not canonical")
        previous = order
        seen.add(name)
        try:
            decoded = name.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise SourceError("source path encoding is unsupported") from exc
        yield mode.decode("ascii"), decoded, raw[nul + 1:nul + 21].hex()
        offset = nul + 21


def _commit_tree(raw: bytes) -> str:
    if not 0 < len(raw) <= 65536 or not raw.startswith(b"tree ") or b"\n\n" not in raw:
        raise SourceError("invalid source commit")
    try:
        return _oid(raw.split(b"\n", 1)[0][5:].decode("ascii"))
    except UnicodeError as exc:
        raise SourceError("invalid source commit tree") from exc


def _walk(base: str, obtain: Callable[[str, str], bytes]):
    objects: dict[str, tuple[str, bytes]] = {}
    object_bytes = 0
    files: dict[str, tuple[str, str, bytes]] = {}
    path_keys: dict[str, str] = {}
    source_bytes = 0
    entries = directories = path_bytes = 0

    def read(kind: str, oid: str) -> bytes:
        nonlocal object_bytes
        if oid in objects:
            if objects[oid][0] != kind:
                raise SourceError("source object kind collision")
            return objects[oid][1]
        raw = obtain(kind, _oid(oid))
        maximum = MAX_FILE_BYTES if kind == "blob" else MAX_METADATA_BYTES
        if type(raw) is not bytes or len(raw) > maximum or object_id(kind, raw) != oid:
            raise SourceError("source object is missing, changing, oversized, or invalid")
        objects[oid] = (kind, raw)
        object_bytes += len(raw)
        if len(objects) > MAX_OBJECTS or object_bytes > MAX_SOURCE_BYTES + MAX_METADATA_BYTES:
            raise SourceError("source object budget exhausted")
        return raw

    def visit(tree: str, prefix: str = "", depth: int = 0):
        nonlocal source_bytes, entries, directories, path_bytes
        if depth > 32:
            raise SourceError("source directory nesting exceeds its limit")
        for mode, name, oid in _tree_entries(read("tree", tree)):
            path = _path(prefix + name)
            # Git trees form a DAG. Unique-object and file limits do not bound
            # expansion of a shared subtree containing empty directories.
            entries += 1
            directories += mode == "40000"
            path_bytes += len(path.encode("utf-8"))
            if entries > MAX_ENTRIES or directories > MAX_DIRECTORIES or path_bytes > MAX_PATH_BYTES:
                raise SourceError("expanded source path budget exhausted")
            key = unicodedata.normalize("NFKC", path).casefold()
            if key in path_keys:
                raise SourceError("source has case or normalization collisions")
            path_keys[key] = path
            if mode == "40000":
                visit(oid, path + "/", depth + 1)
            else:
                content = read("blob", oid)
                if content.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                    raise SourceError("Git LFS hydration requires explicit source-transfer support")
                source_bytes += len(content)
                files[path] = (mode, oid, content)
                if len(files) > MAX_FILES or source_bytes > MAX_SOURCE_BYTES:
                    raise SourceError("source workspace budget exhausted")
    base = _oid(base)
    tree = _commit_tree(read("commit", base))
    visit(tree)
    return tree, objects, files


def build_source_package(base: str, read_object: Callable[[str, str], bytes], *, contains_secret: Callable[[str], bool]) -> bytes:
    """Export one approved finite tree; callbacks are trusted host primitives.

    Scanner positives abort the whole export. Source is never silently redacted
    or omitted. History beyond the shallow base is deliberately unavailable.
    """
    if not callable(read_object) or not callable(contains_secret):
        raise SourceError("source export requires a trusted object reader and secret scanner")
    tree, objects, _files = _walk(base, read_object)
    for _kind, raw in objects.values():
        views = [raw.decode("utf-8", errors="ignore")]
        # Common Unicode configuration files must not hide ASCII credentials
        # behind UTF-16/32 NUL bytes. This remains a high-confidence scanner,
        # not a proof that arbitrary binary/encoded source contains no secret.
        encoding = None
        if raw.startswith((b"\xff\xfe\0\0", b"\0\0\xfe\xff")):
            encoding = "utf-32"
        elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            encoding = "utf-16"
        if encoding is not None:
            try:
                views.append(raw.decode(encoding, errors="strict"))
            except UnicodeError as exc:
                raise SourceError("source has a malformed Unicode text encoding") from exc
        if any(contains_secret(view) is not False for view in views):
            raise SourceError("source export denied by its secret scanner")
    package = {"schemaVersion": 1, "baseCommit": base, "tree": tree,
               "objects": [{"kind": kind, "oid": oid, "bodyHex": raw.hex()}
                           for oid, (kind, raw) in sorted(objects.items())]}
    encoded = json.dumps(package, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_PACKAGE_BYTES:
        raise SourceError("source package exceeds its byte budget")
    return encoded


def parse_source_package(raw: bytes):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PACKAGE_BYTES:
        raise SourceError("source package exceeds its byte budget")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise SourceError("duplicate source package field")
            result[key] = value
        return result
    def constant(_value):
        raise SourceError("invalid source package number")
    try:
        package = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        if type(package) is not dict or set(package) != {"schemaVersion", "baseCommit", "tree", "objects"} or type(package["schemaVersion"]) is not int or package["schemaVersion"] != 1:
            raise SourceError("unsupported source package schema")
        records = package["objects"]
        if type(records) is not list or not 1 <= len(records) <= MAX_OBJECTS:
            raise SourceError("source object count exceeds its budget")
        objects = {}
        for record in records:
            if type(record) is not dict or set(record) != {"kind", "oid", "bodyHex"} or record["kind"] not in {"blob", "tree", "commit"}:
                raise SourceError("invalid source object record")
            oid = _oid(record["oid"])
            body = record["bodyHex"]
            if oid in objects or type(body) is not str or len(body) > MAX_FILE_BYTES * 2 or len(body) % 2 or not _HEX.fullmatch(body):
                raise SourceError("invalid source object bytes")
            objects[oid] = (record["kind"], bytes.fromhex(body))
        used = set()
        def obtain(kind, oid):
            actual_kind, body = objects[oid]
            if kind != actual_kind:
                raise SourceError("source object kind mismatch")
            used.add(oid)
            return body
        tree, accepted, files = _walk(package["baseCommit"], obtain)
        if _oid(package["tree"]) != tree or used != set(objects):
            raise SourceError("source tree identity or finite object set mismatch")
        return package["baseCommit"], tree, accepted, files
    except (ValueError, UnicodeError, KeyError, TypeError, RecursionError) as exc:
        raise SourceError("source package rejected") from exc


def initialize_agent_identity() -> None:
    """Guest root creates one locked worker identity distinct from image UID1000.

    The built-in shell image runs trusted init processes as UID1000. Reusing
    that identity for untrusted work would prevent whole-worker retirement.
    No account lookup, credential file or host account is imported here.
    """
    if os.geteuid() != 0:
        raise SourceError("guest worker identity requires root provisioning")
    directory = os.open("/etc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise SourceError("guest account directory is not protected")
        records = (("group", 2, "sf-agent:!:2000:", 4),
                   ("passwd", 2, "sf-agent:!:2000:2000:Startup Factory worker:/home/sf-agent:/bin/sh", 7))
        for name, id_field, line, count in records:
            descriptor = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or before.st_nlink != 1 or before.st_size > 65536:
                    raise SourceError("guest account file is unsafe")
                raw = os.read(descriptor, 65537)
                if len(raw) != before.st_size or raw and not raw.endswith(b"\n"):
                    raise SourceError("guest account file is incomplete")
                matches = []
                for item in raw.decode("utf-8", errors="strict").splitlines():
                    if not item or item.startswith("#"):
                        continue
                    fields = item.split(":")
                    if len(fields) != count or not fields[id_field].isdigit():
                        raise SourceError("guest account schema is unsupported")
                    if fields[0] == "sf-agent" or int(fields[id_field]) == 2000:
                        matches.append(item)
                if matches:
                    if matches != [line]:
                        raise SourceError("guest worker identity is already occupied")
                    continue
                os.lseek(descriptor, 0, os.SEEK_END)
                view = memoryview((line + "\n").encode())
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise SourceError("guest account write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(directory)
    finally:
        os.close(directory)


def initialize_guest(raw: bytes, destination: Path) -> dict:
    """Guest-only; exclusive workspace creation, regular files, no host paths."""
    base, tree, objects, files = parse_source_package(raw)
    destination = Path(destination)
    if not destination.is_absolute() or os.path.abspath(destination) != str(destination):
        raise SourceError("guest destination must be canonical and absolute")
    # The guest controller provisions a private parent. Never reuse/clean a
    # directory, follow an existing symlink, or restore a host .git directory.
    parent = destination.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise SourceError("guest workspace parent is not protected")
    destination.mkdir(mode=0o700)
    git_dir = destination / ".git"
    git_dir.mkdir(mode=0o700)
    (git_dir / "objects").mkdir(mode=0o700)
    (git_dir / "refs").mkdir(mode=0o700)
    def write(path: Path, content: bytes, mode=0o600):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        try:
            os.fchmod(descriptor, mode)
            offset = 0
            while offset < len(content):
                count = os.write(descriptor, content[offset:offset + 65536])
                if count <= 0:
                    raise SourceError("guest source write failed")
                offset += count
        finally:
            os.close(descriptor)
    for oid, (kind, content) in objects.items():
        parent_path = git_dir / "objects" / oid[:2]
        parent_path.mkdir(mode=0o700, exist_ok=True)
        object_bytes = kind.encode() + b" " + str(len(content)).encode() + b"\0" + content
        write(parent_path / oid[2:], zlib.compress(object_bytes))
    write(git_dir / "HEAD", (base + "\n").encode())
    write(git_dir / "shallow", (base + "\n").encode())
    write(git_dir / "config", b"[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nhooksPath = /dev/null\nfsmonitor = false\n")
    for name, (mode, _oid_value, content) in files.items():
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write(path, content, 0o700 if mode == "100755" else 0o600)
    environment = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
                   "GIT_ALLOW_PROTOCOL": "", "LANG": "C", "LC_ALL": "C"}
    result = subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                             "-C", str(destination), "read-tree", base], env=environment,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if result.returncode:
        raise SourceError("guest index initialization failed")
    return {"schemaVersion": 1, "baseCommit": base, "tree": tree, "files": len(files),
            "inputDigest": "sha256:" + hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest-only", action="store_true", required=True)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_PACKAGE_BYTES + 1)
        receipt = initialize_guest(raw, Path("/workspace/project"))
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print("guest source initialization failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
