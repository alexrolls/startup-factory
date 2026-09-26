#!/usr/bin/env python3
"""Verify the exact canonical release set before artifact upload or publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Sequence


DIGEST = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024


class ReleaseArtifactError(RuntimeError):
    """The downloaded or locally built release set is incomplete or changed."""


def _directory(path: Path, *, label: str) -> Path:
    requested = path.expanduser().absolute()
    try:
        metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise ReleaseArtifactError(f"{label} is unavailable: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseArtifactError(f"{label} must be a non-symlink directory")
    return resolved


def _inventory(root: Path, expected: set[str], *, label: str) -> dict[str, Path]:
    actual: dict[str, Path] = {}
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise ReleaseArtifactError(f"cannot list {label}: {exc}") from exc
    for entry in entries:
        try:
            metadata = entry.lstat()
        except OSError as exc:
            raise ReleaseArtifactError(f"cannot inspect {label} entry: {entry.name}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReleaseArtifactError(f"{label} entry is not a regular file: {entry.name}")
        actual[entry.name] = entry
    if set(actual) != expected:
        missing = sorted(expected - set(actual))
        unexpected = sorted(set(actual) - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if unexpected:
            detail.append("unexpected " + ", ".join(unexpected))
        raise ReleaseArtifactError(f"{label} has the wrong exact inventory: {'; '.join(detail)}")
    return actual


def _hash(path: Path, *, label: str) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseArtifactError(f"cannot open {label}: {exc}") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        named_before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(named_before.st_mode)
            or (before.st_dev, before.st_ino) != (named_before.st_dev, named_before.st_ino)
        ):
            raise ReleaseArtifactError(f"{label} is not a stable regular file")
        if before.st_size > MAX_ARTIFACT_BYTES:
            raise ReleaseArtifactError(f"{label} exceeds {MAX_ARTIFACT_BYTES} bytes")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_ARTIFACT_BYTES:
                raise ReleaseArtifactError(f"{label} exceeds {MAX_ARTIFACT_BYTES} bytes")
            digest.update(chunk)
        after = os.fstat(descriptor)
        named_after = path.lstat()
        if (
            size != after.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        ):
            raise ReleaseArtifactError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def _read_small_regular(path: Path, *, label: str, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseArtifactError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        named_before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(named_before.st_mode)
            or (before.st_dev, before.st_ino) != (named_before.st_dev, named_before.st_ino)
            or before.st_size > limit
        ):
            raise ReleaseArtifactError(f"{label} is not a bounded stable regular file")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        named_after = path.lstat()
        if (
            len(payload) != after.st_size
            or len(payload) > limit
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        ):
            raise ReleaseArtifactError(f"{label} changed while it was read")
        return payload
    except OSError as exc:
        raise ReleaseArtifactError(f"cannot read {label}: {exc}") from exc
    finally:
        os.close(descriptor)


def verify_release_artifacts(
    *,
    version: str,
    expected_digest: str,
    distributions: Path,
    release_assets: Path,
) -> dict[str, object]:
    if VERSION.fullmatch(version) is None:
        raise ReleaseArtifactError("version must be stable numeric SemVer")
    if DIGEST.fullmatch(expected_digest) is None:
        raise ReleaseArtifactError("approved release-set digest is invalid")
    distribution_root = _directory(distributions, label="distribution directory")
    asset_root = _directory(release_assets, label="release-assets directory")
    wheel = f"startup_factory-{version}-py3-none-any.whl"
    sdist = f"startup_factory-{version}.tar.gz"
    bundle = f"startup-factory-{version}.tar.gz"
    sidecar = f"{bundle}.sha256"
    distribution_files = _inventory(
        distribution_root, {wheel, sdist}, label="distribution directory"
    )
    asset_files = _inventory(
        asset_root, {bundle, sidecar, wheel, sdist}, label="release-assets directory"
    )

    bundle_digest, bundle_size = _hash(asset_files[bundle], label="release bundle")
    wheel_digest, wheel_size = _hash(distribution_files[wheel], label="distribution wheel")
    sdist_digest, sdist_size = _hash(distribution_files[sdist], label="distribution sdist")
    asset_wheel_digest, asset_wheel_size = _hash(asset_files[wheel], label="release-assets wheel")
    asset_sdist_digest, asset_sdist_size = _hash(asset_files[sdist], label="release-assets sdist")
    if (wheel_digest, wheel_size) != (asset_wheel_digest, asset_wheel_size):
        raise ReleaseArtifactError("release-assets wheel does not match the tested distribution")
    if (sdist_digest, sdist_size) != (asset_sdist_digest, asset_sdist_size):
        raise ReleaseArtifactError("release-assets sdist does not match the tested distribution")

    sidecar_bytes = _read_small_regular(
        asset_files[sidecar], label="bundle checksum sidecar", limit=512
    )
    expected_sidecar = f"{bundle_digest}  {bundle}\n".encode("ascii")
    if sidecar_bytes != expected_sidecar:
        raise ReleaseArtifactError("bundle checksum sidecar does not match the exact bundle")

    artifacts = [
        {"kind": "bundle", "name": bundle, "sha256": bundle_digest},
        {"kind": "wheel", "name": wheel, "sha256": wheel_digest},
        {"kind": "sdist", "name": sdist, "sha256": sdist_digest},
    ]
    manifest = {"schemaVersion": 1, "artifacts": artifacts}
    calculated = hashlib.sha256(
        json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()
    if calculated != expected_digest:
        raise ReleaseArtifactError(
            f"rebuilt release set {calculated} does not match approved evidence {expected_digest}"
        )
    return {
        **manifest,
        "sha256": calculated,
        "sizes": {
            "bundle": bundle_size,
            "wheel": wheel_size,
            "sdist": sdist_size,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify exact Startup Factory release artifacts")
    parser.add_argument("--version", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--distributions", type=Path, required=True)
    parser.add_argument("--release-assets", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = verify_release_artifacts(
            version=arguments.version,
            expected_digest=arguments.expected_sha256,
            distributions=arguments.distributions,
            release_assets=arguments.release_assets,
        )
    except ReleaseArtifactError as exc:
        print(f"release-artifacts: {exc}", file=__import__("sys").stderr)
        return 2
    if arguments.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(f"Verified release set {result['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
