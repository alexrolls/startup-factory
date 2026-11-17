"""Materialize accepted raw blobs in a host task projection without checkout.

The task ref is already CAS imported. This copies only accepted regular files;
it never runs repository filters, hooks, setup, build commands, or Git checkout.
The caller holds task authority. A human edit, link or untracked file stops the
operation. Interrupted copies can resume only from exact old/accepted bytes.
"""
from __future__ import annotations
import contextlib
import hashlib
import os
from pathlib import Path
import re
import stat
from host_git import HostGit, HostGitError, open_directory, read_regular
from sandbox_acceptance import task_key
from sandbox_artifacts import validate_paths

MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024


def _parent(root: int, path: str, *, create=False) -> tuple[int, str]:
    parts = path.split("/")
    fd = os.dup(root)
    try:
        for part in parts[:-1]:
            if create:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, 0o700, dir_fd=fd)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            info = os.fstat(child)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                os.close(child)
                raise HostGitError("unsafe task projection directory")
            os.close(fd); fd = child
        result = fd; fd = -1
        return result, parts[-1]
    finally:
        if fd >= 0:
            os.close(fd)


def _metadata(git: HostGit, worktree: Path, fd: int, ref: str) -> Path:
    raw = read_regular(fd, ".git", 4096, private=False)
    prefix = b"gitdir: " + str(git.git_dir / "worktrees").encode() + b"/"
    if not raw.startswith(prefix) or not raw.endswith(b"\n"):
        raise HostGitError("task projection is not the canonical linked worktree")
    slot = raw[len(prefix):-1].decode("ascii", "strict")
    if not re.fullmatch(r"[A-Za-z0-9._#-]{1,200}", slot) or slot in {".", ".."}:
        raise HostGitError("unsupported linked worktree identity")
    path = git.git_dir / "worktrees" / slot
    metadata = open_directory(path)
    try:
        if (read_regular(metadata, "commondir", 64, private=False) != b"../..\n"
            or read_regular(metadata, "gitdir", 4096, private=False) != (str(worktree / ".git") + "\n").encode()
            or read_regular(metadata, "HEAD", 512, private=False) != ("ref: " + ref + "\n").encode()):
            raise HostGitError("linked worktree metadata differs from its assigned task")
    finally:
        os.close(metadata)
    return path


def _tree(git, commit):
    entries = git.entries(commit)
    validate_paths(entries)
    if len(entries) > 4096 or any(mode not in {"100644", "100755"} for mode, _ in entries.values()):
        raise HostGitError("unsupported task projection tree")
    result = {}; total = 0
    for path, (mode, identifier) in entries.items():
        body = git.read_blob(identifier, maximum=MAX_FILE)
        total += len(body)
        if total > MAX_TOTAL:
            raise HostGitError("task projection exceeds its byte budget")
        result[path] = (mode, body)
    return result


def materialize(git: HostGit, *, workspace: Path, team: str, task: str, role: str,
                attempt: int, base_commit: str, accepted_commit: str, staging: Path):
    git.assert_no_checkout_programs()
    ref = f"refs/heads/agent-task/{team}/{task_key(task)}"
    if git.read_ref(ref) != accepted_commit:
        raise HostGitError("task ref changed before materialization")
    worktree = workspace / "worktrees" / f"{role}#{attempt}-{task_key(task)}"
    root = open_directory(worktree)
    scratch = -1
    try:
        # The deployment requires one quota volume. Check before any removal;
        # cross-volume replace must never strand a partially copied tree.
        stage_parent = open_directory(staging.parent, private=True)
        try:
            if os.fstat(stage_parent).st_dev != os.fstat(root).st_dev:
                raise HostGitError("task projection and private staging must share the quota filesystem")
        finally:
            os.close(stage_parent)
        metadata = _metadata(git, worktree, root, ref)
        old, new = _tree(git, base_commit), _tree(git, accepted_commit)
        allowed = old.keys() | new.keys()
        allowed_dirs = {path.rsplit("/", count)[0] for path in allowed for count in range(1, path.count("/") + 1)}
        files = set(); directories = set(); visited = 0
        def walk(fd, prefix=""):
            nonlocal visited
            for entry in os.scandir(fd):
                if not prefix and entry.name == ".git":
                    continue
                visited += 1
                if visited > 8192:
                    raise HostGitError("task projection entry budget exhausted")
                path = prefix + entry.name
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if path not in allowed_dirs or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                        raise HostGitError("unsafe projection directory")
                    directories.add(path)
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        walk(child, path + "/")
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and not info.st_mode & 0o7000 and path in allowed:
                    body = read_regular(fd, entry.name, MAX_FILE, private=False)
                    mode = "100755" if info.st_mode & 0o111 else "100644"
                    if (mode, body) not in (old.get(path), new.get(path)):
                        raise HostGitError("task projection contains an unaccepted edit")
                    files.add(path)
                else:
                    raise HostGitError("task projection contains an untracked file or link")
        walk(root)
        for path in sorted(files - new.keys()):
            parent, leaf = _parent(root, path)
            try:
                os.unlink(leaf, dir_fd=parent); os.fsync(parent)
            finally:
                os.close(parent)
        for path in sorted(directories, key=lambda x: (-x.count("/"), x)):
            parent, leaf = _parent(root, path)
            try:
                try:
                    os.rmdir(leaf, dir_fd=parent)
                except OSError as exc:
                    if exc.errno not in {39, 66}:  # ENOTEMPTY on Linux/Darwin
                        raise
            finally:
                os.close(parent)
        with contextlib.suppress(FileExistsError):
            staging.mkdir(mode=0o700)
        scratch = open_directory(staging, private=True)
        for path, (mode, body) in sorted(new.items()):
            parent, leaf = _parent(root, path, create=True)
            try:
                name = hashlib.sha256(path.encode()).hexdigest()
                try:
                    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=scratch)
                except FileExistsError:
                    if read_regular(scratch, name, MAX_FILE, private=False) != body:
                        raise HostGitError("uncertain staged projection requires reconciliation")
                else:
                    try:
                        view = memoryview(body)
                        while view:
                            count = os.write(out, view)
                            if count <= 0:
                                raise HostGitError("projection write made no progress")
                            view = view[count:]
                        os.fchmod(out, 0o755 if mode == "100755" else 0o644)
                        os.fsync(out)
                    finally:
                        os.close(out)
                os.replace(name, leaf, src_dir_fd=scratch, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        # Index update only: no -u, path checkout, external filter or hook.
        code, output = git._run(["--git-dir=" + str(metadata), "--work-tree=" + str(worktree),
                                 "read-tree", git.commit_tree(accepted_commit)], maximum=1024)
        if code or output or git.read_ref(ref) != accepted_commit:
            raise HostGitError("task projection index/ref completion is uncertain")
    finally:
        if scratch >= 0:
            os.close(scratch)
        os.close(root)
