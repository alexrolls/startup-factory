#!/usr/bin/env python3
"""Hold one protected launcher lane until its broker parent releases it.

The lifecycle record lock serializes individual lifecycle commands, but a
launch spans several commands: inspect the lane, mint publication authority,
and register the new process generation.  This helper supplies the outer
critical section without exposing a lock descriptor to the launched worker.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import time


class LaneLockError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise LaneLockError(message)


def protected_directory(path: Path, *, private: bool = False) -> None:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        fail(f"protected launch-lock directory is unavailable: {path}")
    if (
        not path.is_absolute()
        or Path(os.path.normpath(str(path))) != path
        or resolved != path
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
        or (private and stat.S_IMODE(info.st_mode) != 0o700)
    ):
        fail(f"protected launch-lock directory is unsafe: {path}")


def write_ready(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            payload = (str(os.getpid()) + "\n").encode("ascii")
            if os.write(descriptor, payload) != len(payload):
                fail("protected launch-lock acknowledgement was truncated")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        fail("cannot publish protected launch-lock acknowledgement")


def release_requested(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        fail("cannot inspect protected launch-lock release")
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        fail("protected launch-lock release is unsafe")
    return True


def project_identity(repository_raw: str) -> str:
    """Return the same stable repository identity as process-lifecycle.py.

    A launch from the main checkout and one from a linked worktree share the
    lifecycle lane.  Keying the outer lock by either checkout path would split
    that lane and reintroduce the check/mint/register race across worktrees.
    """

    try:
        repository = Path(repository_raw).resolve(strict=True)
    except OSError as exc:
        fail(f"cannot inspect launcher repository: {exc}")
    git = "/usr/bin/git" if Path("/usr/bin/git").is_file() else "git"
    try:
        result = subprocess.run(
            [
                git,
                "-C",
                str(repository),
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail(f"cannot resolve canonical Git common directory: {exc}")
    common_raw = result.stdout.strip()
    if result.returncode != 0 or not common_raw or "\n" in common_raw:
        fail("launcher repository is not inside a valid Git worktree")
    try:
        common = Path(common_raw).resolve(strict=True)
        metadata = common.stat()
    except OSError as exc:
        fail(f"cannot inspect canonical Git common directory: {exc}")
    if not stat.S_ISDIR(metadata.st_mode):
        fail("canonical Git common directory is not a directory")
    material = (
        os.fsencode(common)
        + b"\0"
        + str(metadata.st_dev).encode("ascii")
        + b"\0"
        + str(metadata.st_ino).encode("ascii")
    )
    return hashlib.sha256(material).hexdigest()


def validate_lock(path: Path, descriptor: int, label: str) -> None:
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError:
        fail(f"protected {label} lock is unavailable")
    if (
        not stat.S_ISREG(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
    ):
        fail(f"protected {label} lock has unsafe identity or permissions")


def lock_while_parent_alive(descriptor: int, mode: int, parent_pid: int) -> bool:
    while os.getppid() == parent_pid:
        try:
            fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            time.sleep(0.02)
    return False


def hold(args: argparse.Namespace) -> int:
    root = Path(args.root)
    barrier = Path(args.barrier)
    protected_directory(root, private=True)
    protected_directory(barrier, private=True)
    if barrier.parent != root:
        fail("protected launch-lock barrier must be a direct lifecycle child")

    parent_pid = os.getppid()
    if parent_pid <= 1:
        fail("protected launch-lock holder has no broker parent")
    material = "\0".join(
        (project_identity(args.repo), args.team, args.category, args.instance)
    ).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    lock_path = root / ("launch-lane-" + digest + ".lock")
    admission_path = root / ("launch-admission-" + digest + ".lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    admission = -1
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError:
        fail("cannot open protected launch-lane lock")
    try:
        validate_lock(lock_path, descriptor, "launch-lane")
        if args.category == "team":
            # Writer-preference turnstile.  A stop holds admission EX while it
            # waits for the main EX lock.  Later readers cannot barge ahead,
            # while readers already past admission keep their SH overlap.
            try:
                admission = os.open(admission_path, flags, 0o600)
            except OSError:
                fail("cannot open protected team admission lock")
            validate_lock(admission_path, admission, "team admission")
            if not lock_while_parent_alive(admission, fcntl.LOCK_EX, parent_pid):
                return 0
            validate_lock(admission_path, admission, "team admission")
        requested = fcntl.LOCK_SH if args.mode == "shared" else fcntl.LOCK_EX
        # A blocked flock would outlive a broker that died while waiting.
        # Poll non-blockingly so parent death cancels the waiter before it can
        # later acquire and briefly interpose on a different operation.
        if not lock_while_parent_alive(descriptor, requested, parent_pid):
            return 0
        # Revalidate the name after the blocking acquisition.  A displaced
        # inode must never become a private lock namespace for a competing
        # launcher.
        validate_lock(lock_path, descriptor, "launch-lane")
        if admission >= 0:
            fcntl.flock(admission, fcntl.LOCK_UN)
            os.close(admission)
            admission = -1
        write_ready(barrier / "ready")
        release = barrier / "release"
        while os.getppid() == parent_pid:
            if release_requested(release):
                return 0
            time.sleep(0.02)
        # The broker died without releasing.  Parent reparenting is observed
        # before its numeric PID can be reused, so the lock cannot orphan.
        return 0
    finally:
        if admission >= 0:
            try:
                fcntl.flock(admission, fcntl.LOCK_UN)
            finally:
                os.close(admission)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--root", required=True)
    result.add_argument("--repo", required=True)
    result.add_argument("--team", required=True)
    result.add_argument("--category", choices=("gate", "task", "team"), required=True)
    result.add_argument("--instance", required=True)
    result.add_argument("--mode", choices=("shared", "exclusive"), default="exclusive")
    result.add_argument("--barrier", required=True)
    return result


def main() -> int:
    try:
        return hold(parser().parse_args())
    except LaneLockError as exc:
        print(f"launch-lane-lock: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
