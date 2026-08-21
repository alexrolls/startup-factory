#!/usr/bin/env python3
"""Broker-owned standalone attempt clones and exact quarantine imports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import shutil
from pathlib import Path
from typing import Any


SAFE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
ROLE = re.compile(r"[a-z0-9-]{2,80}\Z")
COMMIT = re.compile(r"[0-9a-f]{40,64}\Z")
ALLOWED_CONFIG = {
    "core.repositoryformatversion",
    "core.filemode",
    "core.bare",
    "core.logallrefupdates",
    "core.ignorecase",
    "core.precomposeunicode",
    "core.symlinks",
    "core.hookspath",
    "core.fsmonitor",
    "user.name",
    "user.email",
}


class WorkspaceError(RuntimeError):
    pass


def _git(repo: Path, *argv: str, check: bool = True) -> str:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(repo), *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        timeout=60,
        check=False,
    )
    if check and result.returncode:
        raise WorkspaceError("Git operation failed closed")
    return result.stdout.strip()


def _safe(value: str, label: str, pattern: re.Pattern[str] = SAFE) -> str:
    if not pattern.fullmatch(value):
        raise WorkspaceError(f"unsafe {label}")
    return value


def protected_root(raw: str, repository: Path) -> Path:
    root = Path(raw)
    if not root.is_absolute() or Path(os.path.normpath(str(root))) != root:
        raise WorkspaceError("clone root must be an absolute normalized path")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            break
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise WorkspaceError("clone root contains a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise WorkspaceError("clone root contains a non-directory")
    repository = repository.resolve(strict=True)
    lexical = Path(os.path.abspath(root))
    try:
        lexical.relative_to(repository)
    except ValueError:
        pass
    else:
        raise WorkspaceError("clone root must be external to the canonical repository")
    if root.exists():
        info = root.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise WorkspaceError("clone root must be caller-owned and mode 0700")
    return root


def attempt_path(root: Path, team: str, role: str, attempt: int, task_key: str) -> Path:
    _safe(team, "team")
    _safe(role, "role", ROLE)
    _safe(task_key, "task key")
    if attempt < 1:
        raise WorkspaceError("attempt must be positive")
    return root / team / f"{role}#{attempt}-{task_key}"


def _mkdir_private(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


def create_attempt(
    repository: Path,
    root: Path,
    team: str,
    role: str,
    attempt: int,
    task_key: str,
    branch: str,
    base_ref: str,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    root = protected_root(str(root), repository)
    destination = attempt_path(root, team, role, attempt, task_key)
    _safe(branch.replace("/", "-"), "branch")
    _safe(base_ref.replace("/", "-"), "base ref")
    base = _git(repository, "rev-parse", "--verify", f"{base_ref}^{{commit}}")
    if not COMMIT.fullmatch(base):
        raise WorkspaceError("base ref did not resolve to a commit")
    if destination.exists() or destination.is_symlink():
        validation = validate_attempt(destination, branch, base)
        return {**validation, "created": False}
    _mkdir_private(destination.parent)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    result = subprocess.run(
        [
            "git", "-c", "core.hooksPath=/dev/null", "clone", "--no-local", "--no-hardlinks",
            "--no-tags", "--single-branch", "--branch", base_ref, "--no-checkout",
            str(repository), str(destination),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=120,
        check=False,
    )
    if result.returncode:
        raise WorkspaceError("standalone clone creation failed")
    try:
        _git(destination, "checkout", "-b", branch, base)
        _git(destination, "remote", "remove", "origin")
        if base_ref != branch:
            _git(destination, "branch", "-D", base_ref)
        _git(destination, "config", "core.hooksPath", "/dev/null")
        _git(destination, "config", "core.fsmonitor", "false")
        _git(destination, "config", "user.name", "Startup Factory Task")
        _git(destination, "config", "user.email", "task@startup-factory.invalid")
        validation = validate_attempt(destination, branch, base)
    except BaseException:
        # A newly created, not-yet-issued disposable attempt is the only removal scope.
        import shutil

        shutil.rmtree(destination)
        raise
    return {**validation, "created": True}


def _config(clone: Path) -> dict[str, list[str]]:
    result = subprocess.run(
        ["git", "-C", str(clone), "config", "--local", "--null", "--list"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode:
        raise WorkspaceError("cannot inspect standalone clone local Git config")
    raw = result.stdout
    values: dict[str, list[str]] = {}
    for record in raw.split("\0"):
        if not record:
            continue
        try:
            key, value = record.split("\n", 1)
        except ValueError as exc:
            raise WorkspaceError("standalone clone has malformed local Git config") from exc
        key = key.casefold()
        if key not in ALLOWED_CONFIG:
            raise WorkspaceError(f"standalone clone has unsafe Git config key: {key}")
        values.setdefault(key, []).append(value)
    if values.get("core.hookspath") != ["/dev/null"] or values.get("core.fsmonitor") != ["false"]:
        raise WorkspaceError("standalone clone Git safety config changed")
    return values


def validate_attempt(clone: Path, branch: str, base: str) -> dict[str, Any]:
    if not clone.is_absolute() or clone.is_symlink() or not clone.is_dir():
        raise WorkspaceError("standalone clone path is unsafe")
    clone = clone.resolve(strict=True)
    git_dir = clone / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise WorkspaceError("attempt must contain an independent .git directory")
    for relative in (
        "commondir", "shallow", "info/grafts", "objects/info/alternates", "objects/info/http-alternates",
    ):
        if os.path.lexists(git_dir / relative):
            raise WorkspaceError(f"hostile clone indirection is forbidden: {relative}")
    _config(clone)
    observed_branch = _git(clone, "branch", "--show-current")
    if observed_branch != branch:
        raise WorkspaceError("standalone clone branch mismatch")
    status = _git(clone, "status", "--porcelain=v1", "-uall")
    if status:
        raise WorkspaceError("standalone clone is dirty")
    head = _git(clone, "rev-parse", "HEAD")
    tree = _git(clone, "rev-parse", "HEAD^{tree}")
    if not COMMIT.fullmatch(head) or not COMMIT.fullmatch(tree):
        raise WorkspaceError("standalone clone head/tree is invalid")
    try:
        _git(clone, "merge-base", "--is-ancestor", base, head)
    except WorkspaceError as exc:
        raise WorkspaceError("standalone clone head is not a descendant of its bound base") from exc
    refs = [line for line in _git(clone, "for-each-ref", "--format=%(refname)").splitlines() if line]
    if refs != [f"refs/heads/{branch}"]:
        raise WorkspaceError("standalone clone contains unexpected refs")
    _git(clone, "fsck", "--full", "--no-dangling", "--strict")
    return {
        "schemaVersion": 1,
        "mode": "standalone-clone",
        "path": str(clone),
        "branch": branch,
        "baseCommit": base,
        "headCommit": head,
        "tree": tree,
        "gitDirectory": str(git_dir),
    }


def quarantine_import(
    repository: Path,
    clone: Path,
    branch: str,
    base: str,
    team: str,
    task_key: str,
    attempt: int,
    bundle_path: Path,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    validation = validate_attempt(clone, branch, base)
    bundle_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if bundle_path.is_symlink():
        raise WorkspaceError("quarantine bundle destination must not be a symlink")
    if not bundle_path.exists():
        _git(clone, "bundle", "create", str(bundle_path), branch, f"^{base}")
    info = bundle_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WorkspaceError("quarantine bundle is not a single-link regular file")
    _git(repository, "bundle", "verify", str(bundle_path))
    head = validation["headCommit"]
    ref_suffix = hashlib.sha256(f"{team}\0{task_key}\0{attempt}\0{head}".encode()).hexdigest()[:32]
    quarantine_ref = f"refs/startup-factory/quarantine/{ref_suffix}"
    existing = _git(repository, "rev-parse", "--verify", quarantine_ref, check=False)
    if existing and existing != head:
        raise WorkspaceError("quarantine ref collision")
    if not existing:
        _git(repository, "fetch", "--no-tags", "--no-write-fetch-head", str(bundle_path), f"refs/heads/{branch}:{quarantine_ref}")
    imported = _git(repository, "rev-parse", quarantine_ref)
    tree = _git(repository, "rev-parse", f"{quarantine_ref}^{{tree}}")
    if imported != head or tree != validation["tree"]:
        raise WorkspaceError("quarantine import commit/tree mismatch")
    bundle_digest = "sha256:" + hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    return {
        **validation,
        "quarantineRef": quarantine_ref,
        "bundlePath": str(bundle_path),
        "bundleSha256": bundle_digest,
    }


def retire_attempt(repository: Path, root: Path, clone: Path, branch: str) -> None:
    root = protected_root(str(root), repository)
    if not clone.is_absolute() or Path(os.path.abspath(clone)) != clone or clone.is_symlink():
        raise WorkspaceError("retired clone path is unsafe")
    clone = clone.resolve(strict=True)
    try:
        clone.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise WorkspaceError("retired clone escapes configured clone root") from exc
    if clone == root:
        raise WorkspaceError("refusing to retire the clone root")
    if not (clone / ".git").is_dir() or (clone / ".git").is_symlink():
        raise WorkspaceError("retired attempt is not a standalone clone")
    _config(clone)
    if _git(clone, "branch", "--show-current") != branch:
        raise WorkspaceError("retired attempt branch mismatch")
    if _git(clone, "status", "--porcelain=v1", "-uall"):
        raise WorkspaceError("dirty standalone attempt is preserved")
    shutil.rmtree(clone)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    path_parser = sub.add_parser("path")
    create_parser = sub.add_parser("create")
    validate_parser = sub.add_parser("validate")
    import_parser = sub.add_parser("import")
    retire_parser = sub.add_parser("retire")
    for selected in (path_parser, create_parser):
        selected.add_argument("--repo", required=True)
        selected.add_argument("--root", required=True)
        selected.add_argument("--team", required=True)
        selected.add_argument("--role", required=True)
        selected.add_argument("--attempt", type=int, required=True)
        selected.add_argument("--task-key", required=True)
    create_parser.add_argument("--branch", required=True)
    create_parser.add_argument("--base-ref", required=True)
    for selected in (validate_parser, import_parser):
        selected.add_argument("--clone", required=True)
        selected.add_argument("--branch", required=True)
        selected.add_argument("--base", required=True)
    import_parser.add_argument("--repo", required=True)
    import_parser.add_argument("--team", required=True)
    import_parser.add_argument("--task-key", required=True)
    import_parser.add_argument("--attempt", type=int, required=True)
    import_parser.add_argument("--bundle", required=True)
    retire_parser.add_argument("--repo", required=True)
    retire_parser.add_argument("--root", required=True)
    retire_parser.add_argument("--clone", required=True)
    retire_parser.add_argument("--branch", required=True)
    args = parser.parse_args()
    try:
        if args.command == "path":
            root = protected_root(args.root, Path(args.repo))
            print(attempt_path(root, args.team, args.role, args.attempt, args.task_key))
        elif args.command == "create":
            print(json.dumps(create_attempt(Path(args.repo), Path(args.root), args.team, args.role, args.attempt, args.task_key, args.branch, args.base_ref), sort_keys=True))
        elif args.command == "validate":
            print(json.dumps(validate_attempt(Path(args.clone), args.branch, args.base), sort_keys=True))
        elif args.command == "import":
            print(json.dumps(quarantine_import(Path(args.repo), Path(args.clone), args.branch, args.base, args.team, args.task_key, args.attempt, Path(args.bundle)), sort_keys=True))
        else:
            retire_attempt(Path(args.repo), Path(args.root), Path(args.clone), args.branch)
    except WorkspaceError as exc:
        print(f"standalone-workspace: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
