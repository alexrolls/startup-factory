#!/usr/bin/env python3
"""Load team policy only through a protected team-context receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.dont_write_bytecode = True


class TeamPolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class TeamPolicy:
    preset: str | None
    text: str


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def bounded_regular_bytes(path: Path, label: str, maximum: int = 1024 * 1024) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise TeamPolicyError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise TeamPolicyError(f"{label} must be a bounded non-symlink regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise TeamPolicyError(f"{label} changed while it was opened")
        value = b""
        while len(value) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(value)))
            if not block:
                break
            value += block
        after = os.fstat(descriptor)
        if (
            len(value) != opened.st_size
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise TeamPolicyError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    if len(value) > maximum:
        raise TeamPolicyError(f"{label} exceeds {maximum} bytes")
    return value


def canonical_directory(path: Path, label: str) -> Path:
    try:
        lexical = Path(os.path.abspath(path))
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except OSError as exc:
        raise TeamPolicyError(f"{label} is unavailable: {exc}") from exc
    if (
        lexical != resolved
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
    ):
        raise TeamPolicyError(f"{label} must be a canonical non-symlink directory")
    return resolved


def load_team_policy(
    repository: Path,
    workspace: Path,
    team: str,
    feature: str,
    skill: Path,
) -> TeamPolicy:
    repository = canonical_directory(repository, "repository")
    workspace = canonical_directory(workspace, "team workspace")
    skill = canonical_directory(skill, "Startup Factory root")
    projection = workspace / "preset.env"
    verifier = skill / "bin" / "team-context.py"
    if verifier.is_symlink() or not verifier.is_file():
        raise TeamPolicyError("protected team-context verifier is unavailable")
    identity_arguments = [
        "--repo",
        str(repository),
        "--workspace",
        str(workspace),
        "--team",
        team,
        "--feature",
        feature,
    ]
    probe = subprocess.run(
        [sys.executable, str(verifier), "probe", *identity_arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if probe.returncode == 3:
        if projection.exists() or projection.is_symlink():
            raise TeamPolicyError(
                "team preset projection exists without protected context authority"
            )
        # Historical direct/manual teams with neither a projection nor a
        # protected context use protocol role defaults and no preset gates.
        return TeamPolicy(None, "")
    if probe.returncode != 0:
        detail = (probe.stderr or probe.stdout).strip()[-1000:]
        raise TeamPolicyError(
            "protected team-context probe failed" + (f": {detail}" if detail else "")
        )
    completed = subprocess.run(
        [
            sys.executable,
            str(verifier),
            "verify",
            *identity_arguments,
            "--skill",
            str(skill),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-1000:]
        raise TeamPolicyError(
            "protected team-context verification failed"
            + (f": {detail}" if detail else "")
        )
    try:
        receipt = json.loads(completed.stdout)
    except (TypeError, ValueError) as exc:
        raise TeamPolicyError("protected team-context result is malformed") from exc
    preset = str(receipt.get("preset") or "") if isinstance(receipt, dict) else ""
    if preset == "-":
        raw = bounded_regular_bytes(projection, "authenticated manual team projection")
        if digest(raw) != receipt.get("projectionSha256"):
            raise TeamPolicyError("manual team projection changed after verification")
        source_preset: str | None = "-"
    else:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", preset):
            raise TeamPolicyError("protected team-context preset identity is invalid")
        raw = bounded_regular_bytes(
            skill / "teams" / f"{preset}.md", "protected team preset"
        )
        if digest(raw) != receipt.get("sourceSha256"):
            raise TeamPolicyError("protected team preset changed after verification")
        source_preset = preset
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise TeamPolicyError("trusted team policy is not UTF-8") from exc
    return TeamPolicy(source_preset, text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--team", required=True)
    parser.add_argument("--feature", required=True)
    parser.add_argument("--skill", required=True, type=Path)
    args = parser.parse_args()
    policy = load_team_policy(
        args.repo, args.workspace, args.team, args.feature, args.skill
    )
    sys.stdout.write(policy.text)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TeamPolicyError) as exc:
        print(f"team-policy: {exc}", file=sys.stderr)
        raise SystemExit(1)
