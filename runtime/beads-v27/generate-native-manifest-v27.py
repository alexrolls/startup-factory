#!/usr/bin/env python3
"""Generate the installed V27 manifest from compiled and source artifacts.

The command is intentionally root-only. It opens every input without following
symlinks, recomputes source and executable identities independently, and
atomically installs one root-owned canonical manifest in a pinned directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
REQUIRED_DIGEST_FIELDS = {
    "launcherSourceSha256",
    "launcherSha256",
    "supervisorSourceSha256",
    "supervisorSha256",
    "ociRuntimeSha256",
}


class ManifestGenerationError(RuntimeError):
    pass


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(descriptor, view[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise ManifestGenerationError("manifest write made no progress")
        offset += written


def _root_owned_bytes(path: Path, label: str, *, executable: bool) -> bytes:
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ManifestGenerationError(f"{label} path is not normalized absolute")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManifestGenerationError(f"cannot open {label} safely: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or mode & 0o022
            or (executable and not mode & 0o100)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_ARTIFACT_BYTES
        ):
            raise ManifestGenerationError(f"{label} identity/mode is unsafe")
        blocks = bytearray()
        while len(blocks) <= MAX_ARTIFACT_BYTES:
            try:
                block = os.read(descriptor, min(65_536, MAX_ARTIFACT_BYTES + 1 - len(blocks)))
            except InterruptedError:
                continue
            if not block:
                break
            blocks.extend(block)
        if len(blocks) != metadata.st_size:
            raise ManifestGenerationError(f"{label} changed or exceeded its bound")
        after = os.fstat(descriptor)
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_mode != metadata.st_mode
            or after.st_uid != metadata.st_uid
            or after.st_gid != metadata.st_gid
            or after.st_nlink != metadata.st_nlink
            or after.st_size != metadata.st_size
            or after.st_mtime_ns != metadata.st_mtime_ns
            or after.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise ManifestGenerationError(f"{label} identity changed during read")
        return bytes(blocks)
    finally:
        os.close(descriptor)


def _strict_template(raw: bytes) -> dict[str, Any]:
    duplicate = False

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicate
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                duplicate = True
            value[key] = item
        return value

    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestGenerationError("manifest template is malformed") from exc
    if duplicate or not isinstance(value, dict) or not REQUIRED_DIGEST_FIELDS <= set(value):
        raise ManifestGenerationError("manifest template is duplicate or incomplete")
    return value


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_manifest(
    template: bytes,
    *,
    launcher_source: bytes,
    launcher_binary: bytes,
    supervisor_source: bytes,
    supervisor_binary: bytes,
    oci_runtime_binary: bytes,
) -> bytes:
    value = _strict_template(template)
    value.update(
        {
            "launcherSourceSha256": _digest(launcher_source),
            "launcherSha256": _digest(launcher_binary),
            "supervisorSourceSha256": _digest(supervisor_source),
            "supervisorSha256": _digest(supervisor_binary),
            "ociRuntimeSha256": _digest(oci_runtime_binary),
        }
    )
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    if len(encoded) > 262_144:
        raise ManifestGenerationError("generated manifest exceeds its bound")
    return encoded


def _atomic_root_install(output: Path, payload: bytes) -> None:
    if not output.is_absolute() or str(output) != os.path.normpath(str(output)):
        raise ManifestGenerationError("manifest output path is not normalized absolute")
    parent = output.parent
    parent_fd = os.open(
        parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary = f".{output.name}.tmp.{os.getpid()}"
    descriptor = -1
    created = False
    try:
        parent_metadata = os.fstat(parent_fd)
        if parent_metadata.st_uid != 0 or stat.S_IMODE(parent_metadata.st_mode) & 0o022:
            raise ManifestGenerationError("manifest parent is not protected root-owned state")
        try:
            current = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != 0
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) & 0o022
        ):
            raise ManifestGenerationError("existing manifest output is substituted")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        created = True
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        installed = os.fstat(descriptor)
        if installed.st_uid != 0 or installed.st_nlink != 1:
            raise ManifestGenerationError("generated manifest ownership changed")
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, output.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        created = False
        os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--launcher-source", type=Path, required=True)
    parser.add_argument("--launcher-binary", type=Path, required=True)
    parser.add_argument("--supervisor-source", type=Path, required=True)
    parser.add_argument("--supervisor-binary", type=Path, required=True)
    parser.add_argument("--oci-runtime-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ManifestGenerationError("native manifest installation requires root")
    payload = build_manifest(
        _root_owned_bytes(args.template, "manifest template", executable=False),
        launcher_source=_root_owned_bytes(
            args.launcher_source, "launcher source", executable=False
        ),
        launcher_binary=_root_owned_bytes(
            args.launcher_binary, "launcher binary", executable=True
        ),
        supervisor_source=_root_owned_bytes(
            args.supervisor_source, "supervisor source", executable=False
        ),
        supervisor_binary=_root_owned_bytes(
            args.supervisor_binary, "supervisor binary", executable=True
        ),
        oci_runtime_binary=_root_owned_bytes(
            args.oci_runtime_binary, "OCI runtime binary", executable=True
        ),
    )
    _atomic_root_install(args.output, payload)
    print(_digest(payload))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManifestGenerationError as exc:
        raise SystemExit(f"native manifest generation failed closed: {exc}") from exc
