#!/usr/bin/env python3
"""Write presentation-only doctor evidence without following workspace links."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat


def write_result(args: argparse.Namespace) -> None:
    specification = importlib.util.spec_from_file_location(
        "teamwork_path", Path(__file__).with_name("teamwork-path.py")
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    repository = Path(args.repo).resolve(strict=True)
    destination = module.child(args.repo, args.workspace, "preflight/doctor-result.json")
    relative = destination.relative_to(repository)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(repository, flags)
    temporary = ".doctor-result-" + secrets.token_hex(16)
    try:
        for part in relative.parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        try:
            metadata = os.stat(relative.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("doctor result must be a non-symlink regular file")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        value = {
            "schemaVersion": 1,
            "authoritative": False,
            "status": args.status,
            "startedAt": args.started_at,
            "updatedAt": now,
            "completedAt": None if args.status == "running" else now,
            "preset": args.preset,
            "team": args.team,
            "featureId": args.feature,
            "verifiedCommands": args.verified_commands,
            "coveredRoles": args.covered_roles,
        }
        output = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=descriptor,
        )
        with os.fdopen(output, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, relative.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "workspace", "preset", "team", "feature", "started-at"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--status", choices=("running", "passed", "failed"), required=True)
    parser.add_argument("--verified-commands", type=int, default=0)
    parser.add_argument("--covered-roles", type=int, default=0)
    args = parser.parse_args()
    try:
        write_result(args)
    except (OSError, ValueError) as exc:
        parser.exit(1, "doctor-result: refusing unsafe diagnostic write: %s\n" % exc)


if __name__ == "__main__":
    main()
