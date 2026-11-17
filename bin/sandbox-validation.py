#!/usr/bin/env python3
"""Validate an exact staged Git tree in a fresh protected Docker Sandbox."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "bin"), str(ROOT / "src")]
from startup_factory_cli.config_values import read_config_file, value_for
from sandbox_validation import MAX_CHANGED_BYTES, parse_changed, run_validation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "workspace", "team", "feature", "tree"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--role", default="validator")
    parser.add_argument("--config", type=Path, default=ROOT / "config/team.config.md")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--command")
    modes.add_argument("--script")
    parser.add_argument("--changed-files", default="-")
    parser.add_argument("--workdir", default=".", help="repository-relative guest directory")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        parsed = read_config_file(args.config, label="team config")
        names = ("AGENT_EXECUTION_BACKEND", "AGENT_SANDBOX_ENFORCED", "AGENT_SANDBOX_DEPLOYMENT",
            "WORKTREE_SETUP", "VALIDATE_SCRIPT", "VALIDATE_BUILD", "VALIDATE_TEST", "VALIDATE_LINT", "VALIDATE_FORMAT")
        config = {name: value_for(parsed, name) for name in names}
        if args.changed_files == "-":
            raw = sys.stdin.buffer.read(MAX_CHANGED_BYTES + 1)
        else:
            descriptor = os.open(args.changed_files, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_CHANGED_BYTES:
                    raise ValueError("changed file input is unsafe")
                chunks = bytearray()
                while len(chunks) <= MAX_CHANGED_BYTES:
                    block = os.read(descriptor, min(65536, MAX_CHANGED_BYTES + 1 - len(chunks)))
                    if not block:
                        break
                    chunks.extend(block)
                raw = bytes(chunks)
            finally:
                os.close(descriptor)
        return run_validation(repository=Path(args.repo), workspace=Path(args.workspace),
            team=args.team, feature=args.feature, role=args.role, tree=args.tree, config=config,
            changed=parse_changed(raw), workdir=args.workdir, command=args.command, script=args.script)
    except Exception:
        print("sandbox-validation: refused or uncertain; inspect protected validation/controller state", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
