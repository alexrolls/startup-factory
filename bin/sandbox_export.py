#!/usr/bin/env python3
"""Guest-only bounded regular-file export; the host independently verifies it.

No archive, guest Git configuration, commit, ref, or host pathname is exported.
Guest root can replace this helper, so its output is always untrusted data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_source import (  # noqa: E402
    MAX_FILES, MAX_FILE_BYTES, MAX_SOURCE_BYTES, MAX_PACKAGE_BYTES, SourceError,
    _path, object_id, parse_source_package,
)

MAX_CHANGES = 256
MAX_PACKET_BYTES = 36 * 1024 * 1024
MAX_EXPORT_ENTRIES = 8192


def _retire_agent_processes(uid: int) -> bool:
    """Signal current guest processes through kernel-held pidfds only."""
    live = False
    with os.scandir("/proc") as processes:
        for count, process in enumerate(processes, 1):
            if count > 4096:
                raise SourceError("guest process census exceeded its bound")
            if not process.name.isdecimal():
                continue
            descriptor = -1
            try:
                descriptor = os.pidfd_open(int(process.name), 0)
                status = os.open("/proc/" + process.name + "/status", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    raw = os.read(status, 8193)
                    if len(raw) > 8192:
                        raise SourceError("guest process status exceeded its bound")
                finally:
                    os.close(status)
                values = dict(line.split(b":", 1) for line in raw.splitlines() if b":" in line)
                owners = values.get(b"Uid", b"").split()
                state = values.get(b"State", b"").split()
                if owners == [str(uid).encode()] * 4 and state and state[0] not in {b"Z", b"X"}:
                    live = True
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except FileNotFoundError:
                pass
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
    return live


def quiesce_agent(uid: int, *, seconds: float = 5) -> None:
    """Guest root retires the entire agent UID before reading its final files.

    Process groups alone cannot contain a program that starts a new session.
    There is no persisted PID signaling or host process access here. Unsupported
    image/kernel APIs, an incomplete census or unretired processes deny export.
    """
    if os.geteuid() != 0 or type(uid) is not int or not 1 <= uid <= 65535 or not 0 < seconds <= 10 or not callable(getattr(os, "pidfd_open", None)) or not callable(getattr(signal, "pidfd_send_signal", None)):
        raise SourceError("root guest process retirement is unavailable")
    deadline, clean = time.monotonic() + seconds, 0
    while clean < 2:
        if time.monotonic() >= deadline:
            raise SourceError("guest processes did not retire before export")
        clean = 0 if _retire_agent_processes(uid) else clean + 1
        if clean < 2:
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)


def _tree(entries):
    root = {}
    for path, (mode, identifier) in entries.items():
        current = root
        parts = path.split("/")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = mode, identifier
    def build(directory):
        children = []
        for name, item in directory.items():
            if type(item) is dict:
                mode, identifier, suffix = "40000", build(item), b"/"
            else:
                mode, identifier = item
                suffix = b"\0"
            encoded = name.encode("utf-8")
            children.append((encoded + suffix, mode.encode() + b" " + encoded + b"\0" + bytes.fromhex(identifier)))
        return object_id("tree", b"".join(raw for _key, raw in sorted(children)))
    return build(root)


def export_workspace(workspace: Path, baseline: bytes, *, export_id: str, seconds: float = 30) -> dict:
    """Read one finite workspace without following or exporting filesystem links."""
    base, base_tree, _objects, approved = parse_source_package(baseline)
    if type(export_id) is not str or len(export_id) != 64 or any(char not in "0123456789abcdef" for char in export_id):
        raise SourceError("invalid export identity")
    if type(seconds) not in {int, float} or not 0 < seconds <= 120:
        raise SourceError("invalid export deadline")
    deadline = time.monotonic() + seconds
    workspace = Path(workspace)
    if not workspace.is_absolute() or str(workspace) != os.path.abspath(workspace):
        raise SourceError("invalid guest workspace")
    files, total, count = {}, 0, 0
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(workspace, flags)
    def visit(directory, prefix="", depth=0):
        nonlocal total, count
        if depth > 32:
            raise SourceError("export path depth exceeded")
        with os.scandir(directory) as children:
            for item in children:
                count += 1
                if count > MAX_EXPORT_ENTRIES or time.monotonic() >= deadline:
                    raise SourceError("export budget exhausted")
                if not prefix and item.name == ".git":
                    continue
                name = _path(prefix + item.name)
                before = os.stat(item.name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(before.st_mode):
                    child = os.open(item.name, flags, dir_fd=directory)
                    try:
                        if (before.st_dev, before.st_ino) != (os.fstat(child).st_dev, os.fstat(child).st_ino):
                            raise SourceError("export directory changed")
                        visit(child, name + "/", depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_FILE_BYTES:
                    leaf = os.open(item.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                    try:
                        opened = os.fstat(leaf)
                        if _stamp(opened) != _stamp(before):
                            raise SourceError("export file changed")
                        raw = bytearray()
                        while len(raw) <= MAX_FILE_BYTES:
                            block = os.read(leaf, min(65536, MAX_FILE_BYTES + 1 - len(raw)))
                            if not block:
                                break
                            raw.extend(block)
                            if time.monotonic() >= deadline:
                                raise SourceError("export deadline exceeded")
                        after = os.fstat(leaf)
                        named = os.stat(item.name, dir_fd=directory, follow_symlinks=False)
                        if _stamp(opened) != _stamp(after) or _stamp(after) != _stamp(named) or len(raw) != opened.st_size:
                            raise SourceError("export file changed")
                        total += len(raw)
                        if total > MAX_SOURCE_BYTES or len(files) >= MAX_FILES:
                            raise SourceError("export source budget exceeded")
                        files[name] = ("100755" if opened.st_mode & 0o111 else "100644", bytes(raw))
                    finally:
                        os.close(leaf)
                else:
                    raise SourceError("export only supports singly linked regular files")
    try:
        visit(descriptor)
    finally:
        os.close(descriptor)
    changes, blobs, entries = [], {}, {}
    for name in sorted(set(approved) | set(files)):
        if name not in files:
            changes.append({"operation": "delete", "path": name})
            continue
        mode, raw = files[name]
        identifier = object_id("blob", raw)
        entries[name] = mode, identifier
        if name in approved and (mode, identifier) == approved[name][:2]:
            continue
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        changes.append({"operation": "replace" if name in approved else "add", "path": name,
                        "mode": mode, "size": len(raw), "sha256": digest})
        blobs[digest] = raw.hex()
    if len(changes) > MAX_CHANGES:
        raise SourceError("export change count exceeded")
    result = {"schemaVersion": 1, "operation": "workspace.export",
              "manifest": {"schemaVersion": 1, "id": export_id, "baseCommit": base,
                           "resultingTree": _tree(entries), "changes": changes}, "blobs": blobs}
    if not changes and result["manifest"]["resultingTree"] != base_tree:
        raise SourceError("unchanged workspace tree differs")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest-only", action="store_true", required=True)
    parser.add_argument("--export-id", required=True)
    parser.add_argument("--quiesce-agent", type=int)
    args = parser.parse_args()
    try:
        if args.quiesce_agent is not None:
            quiesce_agent(args.quiesce_agent)
        with open("/opt/startup-factory/input.json", "rb") as source:
            baseline = source.read(MAX_PACKAGE_BYTES + 1)
        value = export_workspace(Path("/workspace/project"), baseline, export_id=args.export_id)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if not 0 < len(raw) <= MAX_PACKET_BYTES:
            raise SourceError("export packet exceeded its limit")
        output = memoryview(struct.pack("!I", len(raw)) + raw)
        while output:
            count = os.write(1, output[:65536])
            if count <= 0:
                raise SourceError("export output closed")
            output = output[count:]
        return 0
    except (OSError, ValueError):
        print("guest workspace export failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
