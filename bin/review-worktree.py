#!/usr/bin/env python3
"""Allocate a fresh detached working copy for one advisory or protected review.

Isolation is not reviewer authentication. Each invocation gets a new slot so
an unobserved harness worker can never share a replacement's working copy.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


_spec = importlib.util.spec_from_file_location(
    "teamwork_path", Path(__file__).with_name("teamwork-path.py")
)
paths = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(paths)

GIT_ENV = {
    "PATH": "/usr/bin:/bin",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C",
    "LC_ALL": "C",
}


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
         "-C", str(repo), *args],
        env=GIT_ENV, capture_output=True, text=True, timeout=60,
    )
    if result.returncode:
        raise ValueError("Git review-worktree operation failed; inspect repository state")
    return result.stdout.strip()


def create(repo_arg: str, workspace_arg: str, role: str, task_key: str, commit: str) -> dict:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", role):
        raise ValueError("unsafe reviewer role")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", task_key):
        raise ValueError("unsafe task key")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("review commit must be a full lowercase 40-hex object ID")
    repo = Path(repo_arg).resolve(strict=True)
    if git(repo, "rev-parse", "--show-toplevel") != str(repo):
        raise ValueError("repository must be its canonical Git top level")
    if git(repo, "rev-parse", "--verify", commit + "^{commit}") != commit:
        raise ValueError("review commit did not resolve exactly")
    parent = paths.child(str(repo), workspace_arg, "worktrees/reviews")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdtemp reserves an exclusive slot. Never reuse, reset, clean, or remove
    # an existing review: silence and filesystem mtimes cannot prove liveness.
    worktree = Path(tempfile.mkdtemp(
        prefix=f"{role}-{task_key}-{commit[:12]}-", dir=parent
    ))

    def directory_identity(path):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("review directory was replaced; inspect allocation before retrying")
        return info.st_dev, info.st_ino

    parent_identity = directory_identity(parent)
    slot_identity = directory_identity(worktree)

    def verify_slot():
        paths.child(str(repo), workspace_arg, str(worktree.relative_to(Path(workspace_arg))))
        if (directory_identity(parent), directory_identity(worktree)) != (parent_identity, slot_identity):
            raise ValueError("review directory identity changed during allocation")

    # Recheck component safety and identities across Git's path-based checkout.
    # A hostile same-user process still requires an OS sandbox; these checks
    # detect redirection, not a filesystem write-isolation boundary. On failure
    # preserve all residue: cleanup via a changed pathname could delete user data.
    verify_slot()
    git(repo, "worktree", "add", "--detach", str(worktree), commit)
    verify_slot()
    if git(worktree, "rev-parse", "HEAD") != commit:
        raise ValueError("review worktree is not pinned to the requested commit")
    if git(worktree, "branch", "--show-current"):
        raise ValueError("review worktree must be detached")
    if git(worktree, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"):
        raise ValueError("new review worktree is not clean; inspect checkout filters")
    verify_slot()
    return {"worktree": str(worktree), "reviewId": worktree.name, "commit": commit}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "workspace", "role", "task-key", "commit"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = create(args.repo, args.workspace, args.role, args.task_key, args.commit)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"review-worktree: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
