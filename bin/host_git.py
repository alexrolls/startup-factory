#!/usr/bin/env python3
"""Fixed raw-object Git operations for trusted host bookkeeping.

There are no checkout, index, merge, filter, archive, remote, or arbitrary Git
command interfaces. Callers own authorization and task locking. Repository code
is data; only a pinned root-protected native Git executable runs on the host.
Linked-worktree metadata, alternates, includes, partial clones and non-SHA-1
object stores are deliberately unsupported by this initial boundary.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Any


OID = re.compile(r"[0-9a-f]{40}\Z")
REF = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,239}\Z")
MAX_CONFIG_BYTES = 64 * 1024
MAX_OBJECT_BYTES = 16 * 1024 * 1024
MAX_TREE_BYTES = 8 * 1024 * 1024
MAX_TREE_ENTRIES = 10_000
FILE_MODES = frozenset({"100644", "100755"})
BASE_MODES = FILE_MODES | {"120000", "160000"}


class HostGitError(ValueError):
    """A fixed object operation was refused or could not establish its result."""


class RefConflict(HostGitError):
    """The assigned ref no longer has the exact expected object identity."""


def object_id(kind: str, content: bytes) -> str:
    if kind not in {"blob", "tree", "commit"} or type(content) is not bytes:
        raise HostGitError("unsupported raw Git object")
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()


def oid(value: Any) -> str:
    if type(value) is not str or not OID.fullmatch(value):
        raise HostGitError("an exact lowercase 40-hex Git object ID is required")
    return value


def branch_ref(value: Any) -> str:
    if (
        type(value) is not str or not REF.fullmatch(value) or ".." in value or "//" in value
        or "@{" in value or value.endswith(("/", "."))
        or any(part.startswith(".") or part.endswith(".lock") for part in value.split("/"))
    ):
        raise HostGitError("assigned ref must be a normalized full branch ref")
    return value


def open_directory(path: Path, *, private: bool = False, root_owned: bool = False) -> int:
    """Walk protected ancestors using only no-follow directory-relative opens."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or str(path).startswith("//"):
        raise HostGitError("directory must use an absolute normalized path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        parts = path.parts[1:]
        for index in range(len(parts) + 1):
            info = os.fstat(descriptor)
            owners = {0} if root_owned else {0, os.geteuid()}
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o022:
                raise HostGitError("directory ancestors are not protected")
            if root_owned:
                current = Path("/").joinpath(*parts[:index])
                if os.access(current, os.W_OK, effective_ids=True):
                    raise HostGitError("controller can write a native toolchain ancestor")
            if index == len(parts):
                if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
                    raise HostGitError("private directory must be account-owned mode 0700")
                result = descriptor
                descriptor = -1
                return result
            opened = os.open(parts[index], flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = opened
    except OSError as exc:
        raise HostGitError("protected directory is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raise HostGitError("protected directory is unavailable")


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def read_regular(directory: int, name: str, maximum: int, *, private: bool = True) -> bytes:
    if not name or "/" in name or name in {".", ".."}:
        raise HostGitError("invalid private file name")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= maximum
            or (private and (before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600))
            or (not private and (before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022))
        ):
            raise HostGitError("file is not a bounded protected regular file")
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if len(result) != before.st_size or _stamp(before) != _stamp(after) or _stamp(after) != _stamp(named):
            raise HostGitError("protected file changed while being read")
        return bytes(result)
    finally:
        os.close(descriptor)


class HostGit:
    def __init__(self, repository: Path, *, git_dir: Path | None = None,
                 git_path: Path = Path("/usr/bin/git"), timeout_seconds: float = 10.0) -> None:
        self.repository = Path(repository)
        self.git_dir = Path(git_dir) if git_dir is not None else self.repository / ".git"
        self.git_path = Path(git_path)
        if type(timeout_seconds) not in {int, float} or not 0.1 <= timeout_seconds <= 30:
            raise HostGitError("invalid native Git deadline")
        self.timeout_seconds = float(timeout_seconds)
        self._creator_pid = os.getpid()
        descriptor = open_directory(self.repository)
        os.close(descriptor)
        descriptor = open_directory(self.git_dir)
        info = os.fstat(descriptor)
        self._git_identity = (info.st_dev, info.st_ino)
        os.close(descriptor)
        self._runtime_identity = self._runtime_stamp()
        self._check_repository()

    def _runtime_stamp(self) -> tuple[int, ...]:
        if not self.git_path.is_absolute() or ".." in self.git_path.parts:
            raise HostGitError("native Git requires an explicit absolute path")
        parent = open_directory(self.git_path.parent, root_owned=True)
        try:
            descriptor = os.open(self.git_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or not info.st_mode & 0o111 or not 0 < info.st_size <= 64 * 1024 * 1024
                    or not os.access(self.git_path, os.X_OK, effective_ids=True)
                    or os.access(self.git_path, os.W_OK, effective_ids=True)
                ):
                    raise HostGitError("native Git must be a protected root-owned executable")
                named = os.stat(self.git_path.name, dir_fd=parent, follow_symlinks=False)
                if _stamp(info) != _stamp(named):
                    raise HostGitError("native Git identity changed")
                return _stamp(info)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)

    def _check_repository(self) -> None:
        if os.getpid() != self._creator_pid:
            raise HostGitError("inherited Git state requires a fresh host handle")
        descriptor = open_directory(self.git_dir)
        try:
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != self._git_identity:
                raise HostGitError("Git directory identity changed")
            for name in ("commondir", "gitdir"):
                try:
                    os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise HostGitError("linked or redirected Git metadata is unsupported")
            config = read_regular(descriptor, "config", MAX_CONFIG_BYTES, private=False)
            if (
                re.search(rb"(?im)^\s*\[\s*(?:include|includeif|protocol)(?:\s|\])", config)
                or re.search(rb"(?i)\b(?:promisor|partialclone|worktreeconfig|objectformat|objectstorage|refstorage|alternaterefscommand)\b", config)
            ):
                raise HostGitError("includes, promisor/alternate storage, and extended Git formats are unsupported")
            objects = open_directory(self.git_dir / "objects")
            os.close(objects)
            info_dir = self.git_dir / "objects/info"
            if info_dir.exists() or info_dir.is_symlink():
                info_fd = open_directory(info_dir)
                try:
                    for name in ("alternates", "http-alternates"):
                        try:
                            os.stat(name, dir_fd=info_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        raise HostGitError("alternate object stores are unsupported")
                finally:
                    os.close(info_fd)
            pack = self.git_dir / "objects/pack"
            if pack.exists() or pack.is_symlink():
                pack_fd = open_directory(pack)
                try:
                    with os.scandir(pack_fd) as entries:
                        for count, entry in enumerate(entries, 1):
                            if count > 10_000 or entry.name.endswith(".promisor"):
                                raise HostGitError("promisor or excessive pack metadata is unsupported")
                finally:
                    os.close(pack_fd)
        except OSError as exc:
            raise HostGitError("Git object store is unavailable or unsafe") from exc
        finally:
            os.close(descriptor)

    def _environment(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_COUNT": "0", "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_ALLOW_PROTOCOL": "", "GIT_LITERAL_PATHSPECS": "1", "GIT_GRAFT_FILE": "/dev/null",
        }

    def assert_no_checkout_programs(self) -> None:
        """Additional prerequisite for native worktree bookkeeping.

        Raw object operations never expand attributes. A later native status or
        worktree operation must also be unable to select a configured filter.
        """
        self._check_repository()
        descriptor = open_directory(self.git_dir)
        try:
            config = read_regular(descriptor, "config", MAX_CONFIG_BYTES, private=False)
        finally:
            os.close(descriptor)
        if re.search(rb'(?im)^\s*\[\s*filter(?:\s|\.|\])', config):
            raise HostGitError("native worktree bookkeeping does not support configured filters")

    def _run(self, arguments: list[str], *, content: bytes = b"", maximum: int = MAX_TREE_BYTES) -> tuple[int, bytes]:
        self._check_repository()
        if self._runtime_stamp() != self._runtime_identity:
            raise HostGitError("native Git executable changed")
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise HostGitError("raw Git requires exclusive ownership of its native children")
        prefix = [str(self.git_path), "--no-pager", "--no-replace-objects", "--git-dir=" + str(self.git_dir),
                  "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                  "-c", "core.attributesFile=/dev/null", "-c", "commit.gpgSign=false",
                  "-c", "tag.gpgSign=false", "-c", "protocol.allow=never", "-c", "gc.auto=0",
                  "-c", "maintenance.auto=false", "-c", "credential.helper=",
                  "-c", "advice.graftFileDeprecated=false"]
        process = subprocess.Popen(prefix + arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=self._environment(), cwd="/",
                                   shell=False, close_fds=True, start_new_session=True)
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        output = bytearray()
        errors = bytearray()
        deadline = time.monotonic() + self.timeout_seconds
        offset = 0
        try:
            with selectors.DefaultSelector() as selector:
                for stream, label in ((process.stdout, "out"), (process.stderr, "err")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, label)
                if content:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "in")
                else:
                    process.stdin.close()
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise HostGitError("raw Git command deadline exceeded")
                    for key, _event in selector.select(remaining):
                        try:
                            if key.data == "in":
                                offset += os.write(key.fileobj.fileno(), content[offset:offset + 8192])
                                if offset == len(content):
                                    selector.unregister(key.fileobj)
                                    key.fileobj.close()
                            else:
                                chunk = os.read(key.fileobj.fileno(), 8192)
                                if not chunk:
                                    selector.unregister(key.fileobj)
                                    key.fileobj.close()
                                else:
                                    target = output if key.data == "out" else errors
                                    if len(target) + len(chunk) > (maximum if key.data == "out" else 16384):
                                        raise HostGitError("raw Git command exceeded its output limit")
                                    target.extend(chunk)
                        except (BlockingIOError, InterruptedError):
                            continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HostGitError("raw Git command deadline exceeded")
            status = process.wait(timeout=remaining)
            if errors:
                raise HostGitError("raw Git emitted unexpected diagnostic output")
            return status, bytes(output)
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostGitError("raw Git command failed") from exc
        finally:
            if process.returncode is None:
                # Preserve the unreaped leader PID until signaling its group.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def read_object(self, kind: str, identifier: str, *, maximum: int = MAX_OBJECT_BYTES) -> bytes:
        if kind not in {"blob", "tree", "commit"} or type(maximum) is not int or not 0 <= maximum <= MAX_OBJECT_BYTES:
            raise HostGitError("unsupported bounded object read")
        identifier = oid(identifier)
        status, raw = self._run(["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], content=(identifier + "\n").encode(), maximum=256)
        if status != 0:
            raise HostGitError("required local object is unavailable")
        match = re.fullmatch(rb"([0-9a-f]{40}) (blob|tree|commit) ([0-9]{1,10})\n", raw)
        if match is None or match[1].decode() != identifier or match[2].decode() != kind or int(match[3]) > maximum:
            raise HostGitError("object identity, type, or size does not match")
        status, content = self._run(["cat-file", kind, identifier], maximum=maximum)
        if status != 0 or len(content) != int(match[3]) or object_id(kind, content) != identifier:
            raise HostGitError("raw object bytes do not match their exact identity")
        return content

    def read_commit(self, identifier: str) -> bytes:
        return self.read_object("commit", identifier, maximum=64 * 1024)

    def read_blob(self, identifier: str, *, maximum: int = MAX_OBJECT_BYTES) -> bytes:
        return self.read_object("blob", identifier, maximum=maximum)

    def commit_tree(self, identifier: str) -> str:
        raw = self.read_commit(identifier)
        match = re.match(rb"tree ([0-9a-f]{40})\n", raw)
        if match is None or b"\n\n" not in raw:
            raise HostGitError("base is not a supported commit object")
        return match[1].decode("ascii")

    def entries(self, identifier: str) -> dict[str, tuple[str, str]]:
        tree = self.commit_tree(oid(identifier))
        status, raw = self._run(["ls-tree", "-r", "-z", "--full-tree", tree], maximum=MAX_TREE_BYTES)
        if status != 0 or raw and not raw.endswith(b"\0"):
            raise HostGitError("base tree could not be read completely")
        result: dict[str, tuple[str, str]] = {}
        for item in raw.split(b"\0")[:-1]:
            if len(result) >= MAX_TREE_ENTRIES:
                raise HostGitError("base tree entry limit exceeded")
            try:
                metadata, name = item.split(b"\t", 1)
                mode, kind, object_name = metadata.decode("ascii").split(" ")
                path = name.decode("utf-8", "strict")
                if mode not in BASE_MODES or kind != ("commit" if mode == "160000" else "blob") or path in result:
                    raise ValueError
                result[path] = (mode, oid(object_name))
            except (UnicodeError, ValueError) as exc:
                raise HostGitError("base tree contains unsupported or duplicate entries") from exc
        return result

    def write_object(self, kind: str, content: bytes) -> str:
        if kind not in {"blob", "tree", "commit"} or type(content) is not bytes or len(content) > MAX_OBJECT_BYTES:
            raise HostGitError("unsupported bounded object write")
        expected = object_id(kind, content)
        status, raw = self._run(["hash-object", "-w", "--no-filters", "-t", kind, "--stdin"], content=content, maximum=64)
        if status != 0 or raw != (expected + "\n").encode() or self.read_object(kind, expected) != content:
            raise HostGitError("written object does not match the complete accepted bytes")
        return expected

    def read_ref(self, ref: str) -> str | None:
        ref = branch_ref(ref)
        status, _raw = self._run(["symbolic-ref", "-q", ref], maximum=512)
        if status == 0:
            raise HostGitError("assigned branch must not be a symbolic ref")
        if status != 1:
            raise HostGitError("assigned branch kind is unavailable")
        status, raw = self._run(["show-ref", "--verify", "--hash", ref], maximum=64)
        if status == 1 and not raw:
            return None
        if status != 0 or not re.fullmatch(rb"[0-9a-f]{40}\n", raw):
            raise HostGitError("assigned branch identity is unavailable")
        return oid(raw[:-1].decode("ascii"))

    def read_head(self) -> str:
        """Resolve the current canonical commit for a read-only doctor job."""
        status, raw = self._run(["rev-parse", "--verify", "HEAD^{commit}"], maximum=64)
        if status != 0 or not re.fullmatch(rb"[0-9a-f]{40}\n", raw):
            raise HostGitError("canonical HEAD commit is unavailable")
        identifier = oid(raw[:-1].decode("ascii"))
        self.read_commit(identifier)
        return identifier

    def compare_and_swap(self, ref: str, expected: str, replacement: str) -> None:
        ref, expected, replacement = branch_ref(ref), oid(expected), oid(replacement)
        if self.read_ref(ref) != expected:
            raise RefConflict("assigned branch no longer matches the expected base")
        status, raw = self._run(["update-ref", "--no-deref", ref, replacement, expected], maximum=64)
        if status != 0 or raw:
            raise RefConflict("assigned branch compare-and-swap did not complete cleanly")
