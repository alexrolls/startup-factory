#!/usr/bin/env python3
"""Recoverable, provider-neutral production release transaction."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets as secrets_module
import signal
import stat
import subprocess
import sys
import tarfile
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from product_acceptance import (
    ProductAcceptancePending,
    evaluate as evaluate_product_acceptance,
    request_payload as product_acceptance_request,
)


SKILL_DIR = Path(__file__).resolve().parent.parent
TRUSTED_SKILL_DIR = SKILL_DIR
# /bin is canonicalized when it is an OS-owned usrmerge alias. Keeping it in
# the portable template also supplies bash on platforms where /usr/bin lacks it.
TRUSTED_PATH = "/usr/bin:/bin"
ACTIVE_TRUSTED_PATH = TRUSTED_PATH
TRUSTED_GIT = "git"
BOUND_GIT_DIR: Path | None = None
BOUND_WORK_TREE: Path | None = None
BOUND_GIT_COMMON_DIR: Path | None = None
BOUND_GIT_DIR_ID: tuple[int, int] | None = None
BOUND_GIT_COMMON_DIR_ID: tuple[int, int] | None = None
PROTECTED_POLICY_CACHE: tuple[Path, dict] | None = None
PROTECTED_HOOK_ROOT: Path | None = None
ACTIVE_HOOK_PROCESS: subprocess.Popen[str] | None = None
DANGEROUS_ENVIRONMENT_NAMES = {
    "HOME", "BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE", "SHELLOPTS",
    "PATH", "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT",
    "PYTHONUSERBASE", "NODE_OPTIONS", "RUBYOPT", "RUBYLIB", "PERL5OPT",
    "PERL5LIB", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
}
DANGEROUS_ENVIRONMENT_PREFIXES = (
    "PYTHON", "LD_", "DYLD_", "BASH_FUNC_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_",
)
MAX_CREDENTIAL_FILE_BYTES = 1024 * 1024
MAX_PROTECTED_CONFIG_BYTES = 16 * 1024 * 1024
BUILTIN_TRACKER_ADAPTERS = {"Linear", "Jira", "GitHubIssues", "Markdown"}
os.umask(0o077)


class ReleaseError(RuntimeError):
    pass


class AwaitingAuthorization(ReleaseError):
    pass


class ProcessDeadline(RuntimeError):
    def __init__(self, stdout: str, stderr: str):
        super().__init__("process deadline exceeded")
        self.stdout = stdout
        self.stderr = stderr


class ReleaseInterrupted(BaseException):
    pass


def timeout_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value or ""


def install_release_signal_handlers() -> None:
    def interrupt(signum: int, _frame: object) -> None:
        raise ReleaseInterrupted(f"release executor received signal {signum}")

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def strict_json(text: str | bytes) -> object:
    def object_from_pairs(pairs: list[tuple[str, object]]) -> dict:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(
        text,
        object_pairs_hook=object_from_pairs,
        parse_constant=reject_constant,
    )


def load_json(path: Path, label: str) -> dict:
    try:
        value = strict_json(path.read_text())
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"cannot load {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be a JSON object")
    return value


def atomic_bytes(path: Path, value: bytes, mode: int = 0o600) -> None:
    """Atomically replace one file without following a workspace-planted symlink."""

    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(path.parent, directory_flags)
    except OSError as exc:
        raise ReleaseError(f"cannot securely open output directory {path.parent}: {exc}") from exc
    temporary_name = f".{path.name}.tmp.{os.getpid()}.{secrets_module.token_hex(8)}"
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary_name, file_flags, mode, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def atomic_text(path: Path, value: str) -> None:
    atomic_bytes(path, value.encode("utf-8"))


def atomic_json(path: Path, value: dict) -> None:
    atomic_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def parse_time(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ReleaseError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ReleaseError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def subprocess_text(argv: list[str], cwd: Path, env: dict[str, str], label: str) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise ReleaseError(f"{label} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def unprivileged_git_environment() -> dict[str, str]:
    """Return a credential-free environment for repository inspection.

    The release executor deliberately keeps tracker/cloud credentials out of Git:
    repository-controlled filters, fsmonitor helpers, hooks, and user config must
    not become a path from untrusted repository state to scheduler secrets.
    """

    return {
        "PATH": ACTIVE_TRUSTED_PATH,
        "LANG": os.environ.get("LANG", "C"),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }


def git_argv(*args: str) -> list[str]:
    command = [TRUSTED_GIT]
    if BOUND_GIT_DIR is not None and BOUND_WORK_TREE is not None:
        command.extend([
            f"--git-dir={BOUND_GIT_DIR}",
            f"--work-tree={BOUND_WORK_TREE}",
        ])
    return [
        *command,
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "credential.helper=",
        "-c", "submodule.recurse=false",
        *args,
    ]


def raw_git_argv(*args: str) -> list[str]:
    return [
        TRUSTED_GIT,
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "credential.helper=",
        "-c", "submodule.recurse=false",
        *args,
    ]


def raw_git_text(repository: Path, label: str, *args: str) -> str:
    return subprocess_text(
        raw_git_argv(*args), repository, unprivileged_git_environment(), label
    )


def git_text(repository: Path, label: str, *args: str) -> str:
    return subprocess_text(
        git_argv(*args), repository, unprivileged_git_environment(), label
    )


def canonical_trusted_directories(
    trusted_path: object,
    repository: Path | None = None,
) -> list[Path]:
    entries = trusted_path.split(":") if isinstance(trusted_path, str) else []
    if (
        not isinstance(trusted_path, str)
        or not trusted_path
        or any(not item.startswith("/") or item in {"/", ".", ".."} for item in entries)
    ):
        raise ReleaseError("trustedPath must contain only non-root absolute directory entries")
    canonical: list[Path] = []
    for item in entries:
        directory = Path(item)
        current = Path(directory.anchor)
        for part in directory.parts[1:]:
            current /= part
            try:
                info = current.lstat()
            except OSError as exc:
                raise ReleaseError(
                    f"trustedPath directory is unavailable: {directory}: {exc}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                if info.st_uid != 0:
                    raise ReleaseError(
                        f"trustedPath symlink components must be root-owned: {directory}"
                    )
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise ReleaseError(f"trustedPath entry is not a directory: {directory}")
            if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o022:
                raise ReleaseError(
                    "trustedPath components must be executor/root-owned and not "
                    f"group/world writable: {directory}"
                )
        try:
            resolved = directory.resolve(strict=True)
            final_info = resolved.lstat()
        except OSError as exc:
            raise ReleaseError(f"trustedPath directory is unavailable: {directory}: {exc}") from exc
        if not stat.S_ISDIR(final_info.st_mode):
            raise ReleaseError(f"trustedPath entry is not a directory: {directory}")
        current = Path(resolved.anchor)
        for part in resolved.parts[1:]:
            current /= part
            info = current.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise ReleaseError(
                    "trustedPath canonical components must be executor/root-owned, "
                    f"non-symlink directories and not group/world writable: {resolved}"
                )
        if repository is not None:
            try:
                resolved.relative_to(repository)
            except ValueError:
                pass
            else:
                raise ReleaseError(
                    f"trustedPath entry must live outside the agent repository: {directory}"
                )
        if resolved not in canonical:
            canonical.append(resolved)
    return canonical


def read_environment(config: dict, key: str, repository: Path | None = None) -> dict[str, str]:
    allowlist = config.get(key) or []
    if (
        not isinstance(allowlist, list)
        or not all(isinstance(name, str) and re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) for name in allowlist)
        or len(set(allowlist)) != len(allowlist)
    ):
        raise ReleaseError(f"{key} must be a list of names")
    rejected = sorted(
        name for name in allowlist
        if (name in DANGEROUS_ENVIRONMENT_NAMES and name != "PATH")
        or any(name.startswith(prefix) for prefix in DANGEROUS_ENVIRONMENT_PREFIXES)
    )
    if rejected:
        raise ReleaseError(f"{key} contains process-loader/control variables: {', '.join(rejected)}")
    canonical = canonical_trusted_directories(config.get("trustedPath", TRUSTED_PATH), repository)
    child = {name: os.environ[name] for name in allowlist if name != "PATH" and name in os.environ}
    child["PATH"] = ":".join(str(path) for path in canonical)
    child["PYTHONNOUSERSITE"] = "1"
    child["PYTHONSAFEPATH"] = "1"
    return child


def configure_trusted_tools(config: dict, repository: Path) -> None:
    """Resolve Git from the already validated protected release PATH."""
    global ACTIVE_TRUSTED_PATH, TRUSTED_GIT
    child = read_environment(config, "planningEnvironmentAllowlist", repository)
    ACTIVE_TRUSTED_PATH = child["PATH"]
    for item in ACTIVE_TRUSTED_PATH.split(":"):
        candidate = Path(item) / "git"
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if (
            not candidate.is_symlink()
            and stat.S_ISREG(info.st_mode)
            and info.st_uid in {0, os.geteuid()}
            and not stat.S_IMODE(info.st_mode) & 0o022
        ):
            TRUSTED_GIT = str(candidate.resolve())
            return
    raise ReleaseError(
        "trustedPath contains no executor/root-owned, non-writable, non-symlink Git executable"
    )


def validate_planning_isolation_config(config: dict) -> None:
    """Require a provider-neutral, protected sandbox contract for source planning."""
    isolation = config.get("planningIsolation")
    required = {
        "enforced",
        "provider",
        "separateIdentity",
        "credentialPathsUnmounted",
        "statePathsUnmounted",
        "productionEgress",
    }
    if not isinstance(isolation, dict) or set(isolation) != required:
        raise ReleaseError(
            "planningIsolation must contain exactly enforced, provider, separateIdentity, "
            "credentialPathsUnmounted, statePathsUnmounted, and productionEgress"
        )
    provider = isolation.get("provider")
    if not isinstance(provider, str) or not provider.strip() or len(provider) > 256:
        raise ReleaseError("planningIsolation.provider must identify the protected sandbox")
    if (
        isolation.get("enforced") is not True
        or isolation.get("separateIdentity") is not True
        or isolation.get("credentialPathsUnmounted") is not True
        or isolation.get("statePathsUnmounted") is not True
        or isolation.get("productionEgress") is not False
    ):
        raise ReleaseError(
            "planningIsolation must enforce a separate identity with credential/state paths "
            "unmounted and no production egress"
        )


def directory_identity(path: Path, label: str) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseError(f"{label} must be a non-symlink directory")
    return info.st_dev, info.st_ino


def parse_directory_identity(value: str | None, label: str) -> tuple[int, int] | None:
    if value is None:
        return None
    match = re.fullmatch(r"([0-9]+):([0-9]+)", value)
    if not match:
        raise ReleaseError(f"{label} must be device:inode")
    return int(match.group(1)), int(match.group(2))


def bind_repository_identity(args: argparse.Namespace, repository: Path) -> None:
    """Pin Git to the supervisor-authorized worktree, ignoring later .git swaps."""
    global BOUND_GIT_DIR, BOUND_WORK_TREE, BOUND_GIT_COMMON_DIR
    global BOUND_GIT_DIR_ID, BOUND_GIT_COMMON_DIR_ID
    observed_root = Path(
        raw_git_text(repository, "unbound worktree root lookup", "rev-parse", "--show-toplevel")
    ).resolve()
    if observed_root != repository:
        raise ReleaseError("repository is not the canonical Git worktree root")

    def resolve_git_path(raw: str) -> Path:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = repository / candidate
        return candidate.resolve()

    observed_git_dir = resolve_git_path(
        raw_git_text(repository, "unbound Git directory lookup", "rev-parse", "--git-dir")
    )
    observed_common_dir = resolve_git_path(
        raw_git_text(repository, "unbound Git common-directory lookup", "rev-parse", "--git-common-dir")
    )
    observed_git_id = directory_identity(observed_git_dir, "Git worktree directory")
    observed_common_id = directory_identity(observed_common_dir, "Git common directory")
    supplied = (
        args.expected_git_dir,
        args.expected_git_dir_id,
        args.expected_git_common_dir,
        args.expected_git_common_dir_id,
    )
    if any(value is not None for value in supplied) and not all(value is not None for value in supplied):
        raise ReleaseError("expected Git identity requires both paths and both device:inode values")
    if all(value is not None for value in supplied):
        expected_git_dir = args.expected_git_dir.expanduser().resolve()
        expected_common_dir = args.expected_git_common_dir.expanduser().resolve()
        expected_git_id = parse_directory_identity(args.expected_git_dir_id, "expected Git directory identity")
        expected_common_id = parse_directory_identity(
            args.expected_git_common_dir_id, "expected Git common-directory identity"
        )
        if (
            observed_git_dir != expected_git_dir
            or observed_common_dir != expected_common_dir
            or observed_git_id != expected_git_id
            or observed_common_id != expected_common_id
        ):
            raise ReleaseError("Git worktree provenance differs from the supervisor-authorized identity")
    BOUND_GIT_DIR = observed_git_dir
    BOUND_WORK_TREE = repository
    BOUND_GIT_COMMON_DIR = observed_common_dir
    BOUND_GIT_DIR_ID = observed_git_id
    BOUND_GIT_COMMON_DIR_ID = observed_common_id
    # Prove that explicitly bound Git resolves the same root and branch store.
    if Path(git_text(repository, "bound worktree root lookup", "rev-parse", "--show-toplevel")).resolve() != repository:
        raise ReleaseError("bound Git worktree root changed during provenance binding")


def revalidate_bound_repository_identity(repository: Path) -> None:
    if (
        BOUND_GIT_DIR is None
        or BOUND_GIT_COMMON_DIR is None
        or BOUND_GIT_DIR_ID is None
        or BOUND_GIT_COMMON_DIR_ID is None
    ):
        raise ReleaseError("Git worktree identity was not bound")
    if directory_identity(BOUND_GIT_DIR, "bound Git worktree directory") != BOUND_GIT_DIR_ID:
        raise ReleaseError("bound Git worktree directory identity changed before apply")
    if directory_identity(BOUND_GIT_COMMON_DIR, "bound Git common directory") != BOUND_GIT_COMMON_DIR_ID:
        raise ReleaseError("bound Git common-directory identity changed before apply")
    if Path(git_text(repository, "apply-boundary worktree root lookup", "rev-parse", "--show-toplevel")).resolve() != repository:
        raise ReleaseError("bound Git worktree root changed before apply")


def read_private_credential_file(candidate: Path, repository: Path) -> str:
    """Capture a bounded credential file once through a no-follow descriptor."""
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"cannot resolve credentialEnvFile parent: {exc}") from exc
    path = parent / candidate.name
    try:
        path.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ReleaseError("credentialEnvFile must not live inside the repository")
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ReleaseError("credentialEnvFile parent path must not traverse symlinks")
        try:
            parent_info = current.lstat()
        except OSError as exc:
            raise ReleaseError(f"cannot inspect credentialEnvFile parent: {exc}") from exc
        if not stat.S_ISDIR(parent_info.st_mode):
            raise ReleaseError("credentialEnvFile parent path contains a non-directory")
        mode = stat.S_IMODE(parent_info.st_mode)
        protected_sticky_root = (
            parent_info.st_uid == 0 and bool(mode & stat.S_ISVTX)
        )
        if (
            parent_info.st_uid not in {0, os.geteuid()}
            or (mode & 0o022 and not protected_sticky_root)
        ):
            raise ReleaseError(
                "credentialEnvFile parent directories must be executor/root-owned and protected from entry replacement"
            )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseError(f"cannot securely open credentialEnvFile: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseError("credentialEnvFile must be a non-symlink regular file")
        if before.st_uid not in {0, os.geteuid()}:
            raise ReleaseError("credentialEnvFile must be owned by the executor/root")
        if stat.S_IMODE(before.st_mode) & 0o077:
            raise ReleaseError("credentialEnvFile must not be accessible by group or other users")
        if before.st_size < 0 or before.st_size > MAX_CREDENTIAL_FILE_BYTES:
            raise ReleaseError(
                f"credentialEnvFile exceeds the {MAX_CREDENTIAL_FILE_BYTES}-byte limit"
            )
        chunks: list[bytes] = []
        remaining = MAX_CREDENTIAL_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_CREDENTIAL_FILE_BYTES:
            raise ReleaseError(
                f"credentialEnvFile exceeds the {MAX_CREDENTIAL_FILE_BYTES}-byte limit"
            )
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ReleaseError("credentialEnvFile changed while it was being captured")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseError("credentialEnvFile must be UTF-8 text") from exc
    finally:
        os.close(descriptor)


def read_credentials(config: dict, repository: Path) -> tuple[dict[str, str], list[str]]:
    child = read_environment(config, "environmentAllowlist", repository)
    secrets: list[str] = []
    credential_allowlist = config.get("credentialEnvironmentAllowlist") or []
    if (
        not isinstance(credential_allowlist, list)
        or not all(isinstance(name, str) and re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) for name in credential_allowlist)
        or len(set(credential_allowlist)) != len(credential_allowlist)
    ):
        raise ReleaseError("credentialEnvironmentAllowlist must be a unique list of environment names")
    allowed_credentials = set(credential_allowlist)
    for name in allowed_credentials:
        if name in DANGEROUS_ENVIRONMENT_NAMES or any(
            name.startswith(prefix) for prefix in DANGEROUS_ENVIRONMENT_PREFIXES
        ):
            raise ReleaseError(
                "credentialEnvironmentAllowlist contains a process-loader/control variable"
            )
    env_file = config.get("credentialEnvFile")
    if env_file:
        candidate = Path(str(env_file)).expanduser()
        if not candidate.is_absolute():
            raise ReleaseError("credentialEnvFile must be absolute and outside the repository")
        captured_credentials = read_private_credential_file(candidate, repository)
        for number, line in enumerate(captured_credentials.splitlines(), 1):
            if not line or line.lstrip().startswith("#"):
                continue
            if "=" not in line:
                raise ReleaseError(f"credentialEnvFile line {number} is not KEY=VALUE")
            name, value = line.split("=", 1)
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
                raise ReleaseError(f"credentialEnvFile line {number} has an invalid name")
            if name not in allowed_credentials:
                raise ReleaseError(
                    f"credentialEnvFile line {number} names {name}, which is not in credentialEnvironmentAllowlist"
                )
            child[name] = value
            if value:
                secrets.append(value)
    child["STARTUP_FACTORY_RELEASE_EXECUTOR"] = "1"
    return child, sorted(secrets, key=len, reverse=True)


def redact(text: str, secrets: list[str]) -> str:
    value = text
    for secret in secrets:
        value = value.replace(secret, "***REDACTED***")
    value = re.sub(r"(?i)(authorization|token|secret|password|api[_-]?key)(\s*[:=]\s*)\S+", r"\1\2***REDACTED***", value)
    return value


def render_hook(hook: object, values: dict[str, str], name: str) -> list[str]:
    if not isinstance(hook, list) or not hook or not all(isinstance(token, str) and token for token in hook):
        raise ReleaseError(f"deployment hook '{name}' must be a non-empty JSON argv array")
    rendered: list[str] = []
    for token in hook:
        value = token
        for key, replacement in values.items():
            value = value.replace("{" + key + "}", replacement)
        unknown = re.search(r"\{[^{}]*\}", value)
        if unknown:
            raise ReleaseError(f"deployment hook '{name}' uses unknown placeholder {unknown.group(0)}")
        if "{" in value or "}" in value:
            raise ReleaseError(f"deployment hook '{name}' contains a malformed placeholder")
        rendered.append(value)
    return rendered


def read_trusted_file(
    path: Path,
    expected_digest: object,
    label: str,
    *,
    allow_root_owner: bool = True,
) -> bytes:
    if not path.is_absolute():
        raise ReleaseError(f"{label} must be an absolute path")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseError(f"cannot securely open {label}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseError(f"{label} must be a non-symlink regular file")
        allowed_owners = {os.geteuid()}
        if allow_root_owner:
            allowed_owners.add(0)
        if info.st_uid not in allowed_owners or stat.S_IMODE(info.st_mode) & 0o022:
            raise ReleaseError(f"{label} must be owned by the executor/root and not group/world writable")
        if not isinstance(expected_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
            raise ReleaseError(f"{label} needs a pinned sha256 digest")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        value = b"".join(chunks)
        observed = "sha256:" + hashlib.sha256(value).hexdigest()
        if observed != expected_digest:
            raise ReleaseError(f"{label} digest does not match the protected deployment config")
        after = os.fstat(descriptor)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ReleaseError(f"{label} changed while it was being verified")
        return value
    finally:
        os.close(descriptor)


def capture_protected_file(path: Path, label: str, maximum: int = MAX_PROTECTED_CONFIG_BYTES) -> tuple[bytes, str]:
    """Read stable protected bytes once when the digest is the resulting identity."""
    if not path.is_absolute():
        raise ReleaseError(f"{label} must be an absolute path")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseError(f"cannot securely open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseError(f"{label} must be a non-symlink regular file")
        if before.st_uid not in {0, os.geteuid()} or stat.S_IMODE(before.st_mode) & 0o022:
            raise ReleaseError(f"{label} must be owned by the executor/root and not group/world writable")
        if before.st_size < 0 or before.st_size > maximum:
            raise ReleaseError(f"{label} exceeds the {maximum}-byte limit")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > maximum:
            raise ReleaseError(f"{label} exceeds the {maximum}-byte limit")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ReleaseError(f"{label} changed while it was being captured")
        return value, "sha256:" + hashlib.sha256(value).hexdigest()
    finally:
        os.close(descriptor)


def validate_trusted_file(path: Path, expected_digest: object, label: str, *, allow_root_owner: bool = True) -> None:
    read_trusted_file(path, expected_digest, label, allow_root_owner=allow_root_owner)


def trusted_file_specs() -> dict[str, tuple[Path, Path]]:
    specs = {
        "release-feature.py": (Path(__file__).resolve(), Path("bin/release-feature.py")),
        "policy-check.py": ((SKILL_DIR / "bin" / "policy-check.py").resolve(), Path("bin/policy-check.py")),
        "tracker-ops.sh": ((SKILL_DIR / "bin" / "tracker-ops.sh").resolve(), Path("bin/tracker-ops.sh")),
        "finalize-integrations.sh": ((SKILL_DIR / "bin" / "finalize-integrations.sh").resolve(), Path("bin/finalize-integrations.sh")),
        "task-hold.py": ((SKILL_DIR / "bin" / "task-hold.py").resolve(), Path("bin/task-hold.py")),
        "outbox_capability.py": ((SKILL_DIR / "bin" / "outbox_capability.py").resolve(), Path("bin/outbox_capability.py")),
        "broker_evidence.py": ((SKILL_DIR / "bin" / "broker_evidence.py").resolve(), Path("bin/broker_evidence.py")),
        "runtime-state.py": ((SKILL_DIR / "bin" / "runtime-state.py").resolve(), Path("bin/runtime-state.py")),
        "task_metadata.py": ((SKILL_DIR / "bin" / "task_metadata.py").resolve(), Path("bin/task_metadata.py")),
        "product_acceptance.py": ((SKILL_DIR / "bin" / "product_acceptance.py").resolve(), Path("bin/product_acceptance.py")),
        "teamwork-path.py": ((SKILL_DIR / "bin" / "teamwork-path.py").resolve(), Path("bin/teamwork-path.py")),
        "review_evidence.py": ((SKILL_DIR / "bin" / "review_evidence.py").resolve(), Path("bin/review_evidence.py")),
        "statuses.config.json": ((SKILL_DIR / "config" / "statuses.config.json").resolve(), Path("config/statuses.config.json")),
        "guardrails.config.json": ((SKILL_DIR / "config" / "guardrails.config.json").resolve(), Path("config/guardrails.config.json")),
        "team.config.md": ((SKILL_DIR / "config" / "team.config.md").resolve(), Path("config/team.config.md")),
        "project-management.config.md": ((SKILL_DIR / "config" / "project-management.config.md").resolve(), Path("config/project-management.config.md")),
    }
    pm_config_path = SKILL_DIR / "config" / "project-management.config.md"
    try:
        pm_config_text = pm_config_path.read_text()
    except OSError as exc:
        raise ReleaseError(f"cannot read project-management config: {exc}") from exc
    pm_values: dict[str, str | None] = {}
    for match in re.finditer(r"^([A-Z_]+)=(.*)$", pm_config_text, re.MULTILINE):
        name = match.group(1)
        if name in pm_values:
            raise ReleaseError(f"duplicate project-management setting {name}")
        value = match.group(2).split("#", 1)[0].strip().strip('"')
        pm_values[name] = None if value == "null" else value
    tracker_adapter = os.environ.get("TRACKER_ADAPTER") or pm_values.get(
        "PRODUCT_MANAGEMENT_TOOL"
    )
    if not isinstance(tracker_adapter, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_-]{0,63}", tracker_adapter
    ):
        raise ReleaseError("trusted code requires a valid configured tracker adapter")
    if tracker_adapter not in BUILTIN_TRACKER_ADAPTERS:
        relative = Path("extensions", "tracker-backends", f"{tracker_adapter}.py")
        specs[f"tracker-backend.{tracker_adapter}.py"] = (
            SKILL_DIR / relative,
            relative,
        )
    return specs


def skill_path(relative: str) -> Path:
    return TRUSTED_SKILL_DIR / relative


def validate_release_trust(config_path: Path, config: dict, repository: Path) -> tuple[str, dict[str, bytes]]:
    candidate = config_path.expanduser()
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate)
    if candidate.is_symlink():
        raise ReleaseError("deployment config must not be a symlink")
    resolved_config = candidate.resolve()
    try:
        resolved_config.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ReleaseError("enabled deployment config must live outside the agent repository")
    config_digest = file_digest(resolved_config)
    raw_config = read_trusted_file(resolved_config, config_digest, "deployment config")
    try:
        verified_config = strict_json(raw_config)
    except ValueError as exc:
        raise ReleaseError(f"deployment config is invalid JSON: {exc}") from exc
    if verified_config != config:
        raise ReleaseError("deployment config changed while it was being loaded")
    trusted = config.get("trustedCodeDigests")
    if not isinstance(trusted, dict):
        raise ReleaseError("enabled deployment requires trustedCodeDigests")
    specs = trusted_file_specs()
    if set(trusted) != set(specs):
        raise ReleaseError(
            "trustedCodeDigests must contain exactly: " + ", ".join(sorted(specs))
        )
    captured: dict[str, bytes] = {}
    for name, (path, _) in specs.items():
        captured[name] = read_trusted_file(path, trusted.get(name), f"trusted skill file {name}")
    return config_digest, captured


def validate_hook_executable(
    name: str,
    argv: list[str],
    config: dict,
    repository: Path,
    source_directory: Path | None = None,
    source_archive: Path | None = None,
) -> tuple[str, Path]:
    executable = Path(argv[0]).expanduser()
    if not executable.is_absolute():
        raise ReleaseError(f"deployment hook '{name}' executable must be absolute")
    if executable.is_symlink():
        raise ReleaseError(f"deployment hook '{name}' executable must not be a symlink")
    executable = executable.resolve()
    try:
        executable.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ReleaseError(f"deployment hook '{name}' executable must live outside the agent repository")
    generic_runtimes = {
        "env", "sh", "bash", "dash", "zsh", "csh", "ksh", "fish",
        "python", "python2", "python3", "perl", "ruby", "node", "deno", "php",
        "java", "jshell", "pwsh", "powershell", "osascript",
    }
    if executable.name.lower() in generic_runtimes:
        raise ReleaseError(
            f"deployment hook '{name}' must use a dedicated pinned executable/wrapper, not generic runtime {executable.name}"
        )
    try:
        repository_token = str(repository.resolve())
    except OSError:
        repository_token = str(repository)
    if any(repository_token in token for token in argv[1:]):
        raise ReleaseError(
            f"deployment hook '{name}' must not receive the live agent repository"
        )
    if name != "plan" and source_directory is not None:
        source_tokens = {str(source_directory)}
        if source_archive is not None:
            source_tokens.add(str(source_archive))
        if any(source_token in token for source_token in source_tokens for token in argv[1:]):
            raise ReleaseError(
                f"deployment hook '{name}' must consume the immutable artifact, not release source"
            )
    pins = config.get("trustedHookDigests")
    if not isinstance(pins, dict):
        raise ReleaseError("enabled deployment requires trustedHookDigests")
    expected = pins.get(name)
    captured = read_trusted_file(
        executable, expected, f"deployment hook '{name}' executable"
    )
    digest = "sha256:" + hashlib.sha256(captured).hexdigest()
    if PROTECTED_HOOK_ROOT is None:
        raise ReleaseError("protected hook snapshot root is not initialized")
    bundle = PROTECTED_HOOK_ROOT / digest.removeprefix("sha256:")
    for directory in (PROTECTED_HOOK_ROOT, bundle):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseError(f"protected hook directory is unsafe: {directory}")
        if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o077:
            raise ReleaseError(
                f"protected hook directory must be private and executor-owned: {directory}"
            )
    snapshot = bundle / name
    if snapshot.exists() or snapshot.is_symlink():
        observed = read_trusted_file(
            snapshot, digest, f"protected deployment hook snapshot {name}"
        )
        if observed != captured:
            raise ReleaseError(f"protected deployment hook snapshot {name} changed")
    else:
        atomic_bytes(snapshot, captured, 0o500)
        os.chmod(snapshot, 0o500, follow_symlinks=False)
        read_trusted_file(snapshot, digest, f"protected deployment hook snapshot {name}")
    return digest, snapshot


def protected_policy() -> tuple[dict, dict]:
    """Load the digest-pinned policy in-process, without an ambient-env child."""
    global PROTECTED_POLICY_CACHE
    source_path = skill_path("bin/policy-check.py")
    if PROTECTED_POLICY_CACHE is None or PROTECTED_POLICY_CACHE[0] != source_path:
        try:
            source = source_path.read_bytes()
            namespace: dict = {
                "__name__": "startup_factory_protected_policy",
                "__file__": str(source_path),
            }
            exec(compile(source, str(source_path), "exec"), namespace)
        except Exception as exc:
            raise ReleaseError(f"cannot load protected policy evaluator: {exc}") from exc
        required = {"load_config", "evaluate_command", "evaluate_plan", "ALLOW", "APPROVAL"}
        if not required.issubset(namespace):
            raise ReleaseError("protected policy evaluator is missing its required interface")
        PROTECTED_POLICY_CACHE = (source_path, namespace)
    namespace = PROTECTED_POLICY_CACHE[1]
    try:
        config = namespace["load_config"](skill_path("config/guardrails.config.json"))
    except Exception as exc:
        raise ReleaseError(f"cannot load protected guardrail config: {exc}") from exc
    return namespace, config


def enforce_policy_decision(policy: dict, decision: object, fallback: str) -> None:
    if not isinstance(decision, dict):
        raise ReleaseError(fallback)
    reason = str(decision.get("reason") or fallback)
    value = decision.get("decision")
    if value == policy["APPROVAL"]:
        raise AwaitingAuthorization(reason)
    if value != policy["ALLOW"]:
        raise ReleaseError(reason)


def policy_command(action: str, environment: str, argv: list[str], *, authorization_digest: str | None) -> None:
    policy, config = protected_policy()
    try:
        decision = policy["evaluate_command"](
            action, environment, argv, authorization_digest, config
        )
    except Exception as exc:
        raise ReleaseError(f"protected command policy failed: {exc}") from exc
    enforce_policy_decision(policy, decision, "policy gate failed")


def policy_plan(plan_file: Path, mode: str, approved: bool) -> None:
    try:
        payload = strict_json(plan_file.read_text())
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"cannot load release plan: {exc}") from exc
    policy, config = protected_policy()
    try:
        decision = policy["evaluate_plan"](payload, mode, approved, config)
    except Exception as exc:
        raise ReleaseError(f"protected release-plan policy failed: {exc}") from exc
    enforce_policy_decision(policy, decision, "release-plan policy failed")


def stop_process_group(
    process: subprocess.Popen[str],
    *,
    grace: int,
    stdout: str = "",
    stderr: str = "",
) -> tuple[str, str]:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        final_stdout, final_stderr = process.communicate(timeout=grace)
        return timeout_text(final_stdout) or stdout, timeout_text(final_stderr) or stderr
    except subprocess.TimeoutExpired as term_exc:
        stdout = timeout_text(term_exc.stdout) or stdout
        stderr = timeout_text(term_exc.stderr) or stderr
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        final_stdout, final_stderr = process.communicate(timeout=grace)
        return timeout_text(final_stdout) or stdout, timeout_text(final_stderr) or stderr
    except subprocess.TimeoutExpired as kill_exc:
        # A hook is forbidden to daemonize outside its process group. If a
        # detached descendant nevertheless retains the pipes, keep the release
        # executor's own deadline bounded.
        stdout = timeout_text(kill_exc.stdout) or stdout
        stderr = timeout_text(kill_exc.stderr) or stderr
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
        return stdout, stderr


def run_process_group(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int | float,
    before_spawn: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded hook and ensure its whole process group is gone on timeout."""
    global ACTIVE_HOOK_PROCESS
    if before_spawn is not None:
        before_spawn()
    process: subprocess.Popen[str] | None = None
    try:
        blocked_signals = {signal.SIGTERM, signal.SIGINT}
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
        def restore_hook_signal_mask() -> None:
            signal.pthread_sigmask(
                signal.SIG_SETMASK,
                set(previous_mask).difference(blocked_signals),
            )
        try:
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                    preexec_fn=restore_hook_signal_mask,
                )
            except OSError as exc:
                raise ReleaseError(
                    f"deployment hook could not start: {exc.strerror or 'operating-system error'}"
                ) from exc
            ACTIVE_HOOK_PROCESS = process
        finally:
            # A pending termination is delivered only after ACTIVE_HOOK_PROCESS
            # identifies the new process group, so the outer BaseException path
            # cannot orphan a privileged child in the Popen/assignment gap.
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = stop_process_group(
                process,
                grace=5,
                stdout=timeout_text(exc.stdout),
                stderr=timeout_text(exc.stderr),
            )
            process = None
            raise ProcessDeadline(timeout_text(stdout), timeout_text(stderr)) from exc
    except BaseException:
        if process is not None:
            stop_process_group(process, grace=2)
        raise
    finally:
        ACTIVE_HOOK_PROCESS = None
    if process is None:
        raise ReleaseError("deployment hook terminated without a process result")
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def run_hook(
    name: str,
    action: str,
    config: dict,
    values: dict[str, str],
    *,
    repository: Path,
    env: dict[str, str],
    secrets: list[str],
    logs: Path,
    authorization_digest: str | None = None,
    expected_binding: dict | None = None,
    before_spawn: Callable[[], None] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    source_argv = render_hook((config.get("hooks") or {}).get(name), values, name)
    source_directory = Path(values["source_dir"])
    digest, executable = validate_hook_executable(
        name, source_argv, config, repository, source_directory, Path(values["source_archive"])
    )
    argv = [str(executable), *source_argv[1:]]
    binding = {"executableDigest": digest, "sourceArgv": source_argv, "argv": argv}
    if expected_binding is not None and binding != expected_binding:
        raise ReleaseError(f"deployment hook '{name}' no longer matches the recorded manifest binding")
    policy_command(
        action,
        str(config["environment"]),
        source_argv,
        authorization_digest=authorization_digest,
    )
    timeouts = config.get("timeoutsSeconds", {})
    if not isinstance(timeouts, dict):
        raise ReleaseError("timeoutsSeconds must be an object")
    timeout = timeouts.get(name, 300)
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ReleaseError(
            f"timeoutsSeconds.{name} must be an integer from 1 to 86400"
        )
    cwd = source_directory if name == "plan" else logs.parent
    try:
        result = run_process_group(
            argv,
            cwd=cwd,
            env=env,
            timeout=timeout,
            before_spawn=before_spawn,
        )
    except ProcessDeadline as exc:
        logs.mkdir(parents=True, exist_ok=True)
        log = logs / f"{name}.log"
        atomic_text(
            log,
            redact(
                f"stdout:\n{exc.stdout}\n\nstderr:\n{exc.stderr}\n\n"
                f"result: timed out after {timeout}s; process group terminated\n",
                secrets,
            ),
        )
        raise ReleaseError(f"deployment hook '{name}' timed out after {timeout}s") from exc
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / f"{name}.log"
    atomic_text(log, redact(f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}\n", secrets))
    if check and result.returncode:
        raise ReleaseError(f"deployment hook '{name}' failed with exit {result.returncode}; see {log}")
    return result


def current_release_status(
    config: dict,
    values: dict[str, str],
    repository: Path,
    env: dict[str, str],
    secrets: list[str],
    logs: Path,
    expected_bindings: dict[str, dict],
) -> dict:
    result = run_hook(
        "status", "deploy.status", config, values,
        repository=repository, env=env, secrets=secrets, logs=logs,
        expected_binding=expected_bindings.get("status"),
    )
    try:
        payload = strict_json(result.stdout)
    except ValueError as exc:
        raise ReleaseError("status hook must print one JSON object") from exc
    if not isinstance(payload, dict) or payload.get("state") not in {"not-applied", "in-progress", "applied", "failed"}:
        raise ReleaseError("status hook returned an invalid state")
    for field in ("artifactDigest", "currentArtifactDigest"):
        if payload.get(field) is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", str(payload[field])):
            raise ReleaseError(f"status hook returned an invalid {field}")
    if payload.get("state") == "applied" and not payload.get("artifactDigest"):
        raise ReleaseError("status hook must return artifactDigest when state is applied")
    if payload.get("state") in {"in-progress", "applied", "failed"}:
        if payload.get("releaseId") != values["release_id"]:
            raise ReleaseError("status hook did not bind the active/applied/failed state to this exact releaseId")
    elif payload.get("releaseId") not in {None, values["release_id"]}:
        raise ReleaseError("status hook returned a different releaseId")
    return payload


def trusted_state_root(config: dict, repository: Path) -> Path:
    raw = config.get("stateRoot")
    if not isinstance(raw, str) or not raw:
        raise ReleaseError("enabled deployment requires an absolute stateRoot")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ReleaseError("stateRoot must be absolute")
    try:
        path.resolve().relative_to(repository)
    except ValueError:
        pass
    else:
        raise ReleaseError("stateRoot must live outside the agent repository")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseError(f"cannot stat stateRoot: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseError("stateRoot must be a non-symlink directory")
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o077:
        raise ReleaseError("stateRoot must be private (0700) and owned by executor/root")
    return path.resolve()


def materialize_trusted_code(
    state_root: Path,
    config_digest: str,
    captured: dict[str, bytes],
    configured_digests: dict[str, str],
) -> Path:
    """Install one immutable-by-convention helper snapshot in protected state.

    Captured bytes came from the same descriptors used for pin verification, so
    helper execution cannot race a later mutation of the installed skill tree.
    Ordinary agents must not be able to write ``state_root``; owner/mode checks
    on every later pass detect corruption rather than repairing over it.
    """

    bundle = state_root / "trusted-code" / config_digest.removeprefix("sha256:")
    specs = trusted_file_specs()
    trusted_directories = {
        state_root / "trusted-code",
        bundle,
        *((bundle / relative).parent for _, relative in specs.values()),
    }
    for directory in sorted(trusted_directories, key=lambda item: (len(item.parts), str(item))):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseError(f"trusted code directory is unsafe: {directory}")
        if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o077:
            raise ReleaseError(f"trusted code directory must be private and executor-owned: {directory}")
    for name, (_, relative) in specs.items():
        destination = bundle / relative
        expected = configured_digests[name]
        if destination.exists() or destination.is_symlink():
            observed = read_trusted_file(destination, expected, f"protected trusted-code copy {name}")
            if observed != captured[name]:
                raise ReleaseError(f"protected trusted-code copy {name} differs from the verified bytes")
            continue
        mode = 0o500 if name in {"tracker-ops.sh", "finalize-integrations.sh"} else 0o400
        atomic_bytes(destination, captured[name], mode)
        os.chmod(destination, mode, follow_symlinks=False)
        read_trusted_file(destination, expected, f"protected trusted-code copy {name}")
    marker = bundle / "bundle.json"
    material = {
        "schemaVersion": 1,
        "deploymentConfigDigest": config_digest,
        "files": {name: configured_digests[name] for name in sorted(specs)},
    }
    if marker.is_symlink():
        raise ReleaseError("protected trusted-code bundle marker must not be a symlink")
    if marker.exists():
        if load_json(marker, "trusted code bundle marker") != material:
            raise ReleaseError("protected trusted-code bundle marker changed")
    else:
        atomic_json(marker, material)
        os.chmod(marker, 0o400, follow_symlinks=False)
    return bundle


@contextmanager
def release_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AwaitingAuthorization("another release transaction owns the feature/environment lock") from exc
        yield
    finally:
        os.close(descriptor)


def target_lease_key(environment: str, target: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(
            {"environment": environment, "target": target},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()


def _unlink_regular(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReleaseError(f"{label} is not a regular file")
    path.unlink()


def claim_target_lease(
    active_file: Path,
    *,
    state_root: Path,
    transaction_file: Path,
    release_id: str,
    feature_id: str,
    environment: str,
    target: dict[str, str],
    lease_key: str,
) -> None:
    """Durably fence all releases sharing one canonical production target."""

    relative = transaction_file.relative_to(state_root).as_posix()
    active: dict | None = None
    if active_file.exists() or active_file.is_symlink():
        if active_file.is_symlink() or not active_file.is_file():
            raise ReleaseError("production target lease record is unsafe")
        active = load_json(active_file, "production target lease")
        required = {
            "schemaVersion", "leaseKey", "environment", "target", "releaseId",
            "featureId", "transactionRelative", "claimedAt", "updatedAt",
        }
        if set(active) != required or active.get("schemaVersion") != 1:
            raise ReleaseError("production target lease has an unsupported schema")
        if active.get("leaseKey") != lease_key or active.get("environment") != environment or active.get("target") != target:
            raise ReleaseError("production target lease is bound to different target inputs")
        if active.get("releaseId") == release_id:
            if active.get("featureId") != feature_id or active.get("transactionRelative") != relative:
                raise ReleaseError("production target lease owner binding changed")
            active["updatedAt"] = now()
            atomic_json(active_file, active)
            return

        owner_relative = PurePosixPath(str(active.get("transactionRelative") or ""))
        if (
            owner_relative.is_absolute()
            or ".." in owner_relative.parts
            or len(owner_relative.parts) != 5
            or owner_relative.parts[0] != "features"
            or owner_relative.parts[2] != "releases"
            or owner_relative.parts[4] != "transaction.json"
        ):
            raise ReleaseError("production target lease references an unsafe transaction path")
        owner_path = state_root.joinpath(*owner_relative.parts)
        if owner_path.is_symlink() or not owner_path.is_file():
            raise ReleaseError("production target lease owner transaction is unavailable; manual recovery required")
        owner = load_json(owner_path, "production target lease owner transaction")
        if owner.get("releaseId") != active.get("releaseId") or owner.get("featureId") != active.get("featureId"):
            raise ReleaseError("production target lease does not match its owner transaction")
        owner_phase = owner.get("phase")
        if owner_phase in {"succeeded", "rolled-back"}:
            _unlink_regular(active_file, "production target lease")
        elif owner_phase == "failed":
            raise ReleaseError(
                "production target is fenced by a failed release; explicit operator recovery is required"
            )
        else:
            raise AwaitingAuthorization(
                "production target is owned by another in-flight release transaction"
            )

    timestamp = now()
    atomic_json(active_file, {
        "schemaVersion": 1,
        "leaseKey": lease_key,
        "environment": environment,
        "target": target,
        "releaseId": release_id,
        "featureId": feature_id,
        "transactionRelative": relative,
        "claimedAt": timestamp,
        "updatedAt": timestamp,
    })


def release_target_lease(active_file: Path, release_id: str, *, require_owner: bool = False) -> bool:
    if not (active_file.exists() or active_file.is_symlink()):
        return False
    if active_file.is_symlink() or not active_file.is_file():
        raise ReleaseError("production target lease record is unsafe")
    active = load_json(active_file, "production target lease")
    if active.get("releaseId") != release_id:
        if require_owner:
            raise ReleaseError("cannot release a production target lease owned by another release")
        return False
    _unlink_regular(active_file, "production target lease")
    return True


def normalize_target(config: dict) -> dict[str, str]:
    target = config.get("target")
    if not isinstance(target, dict) or not isinstance(target.get("id"), str) or not target["id"].strip():
        raise ReleaseError("deployment target requires a non-empty target.id")
    normalized: dict[str, str] = {}
    for key, value in target.items():
        if not re.fullmatch(r"[a-z][a-zA-Z0-9_-]{0,63}", str(key)):
            raise ReleaseError(f"deployment target has an invalid key: {key}")
        if not isinstance(value, str) or not value.strip() or len(value) > 512 or any(ord(char) < 32 for char in value):
            raise ReleaseError(f"deployment target field {key} must be a bounded non-empty string")
        normalized[str(key)] = value.strip()
    return normalized


def bounded_positive_integer(config: dict, key: str, default: int, maximum: int) -> int:
    value = config.get(key, default)
    if type(value) is not int or value < 1 or value > maximum:
        raise ReleaseError(f"{key} must be an integer from 1 to {maximum}")
    return value


def create_source_archive(
    repository: Path,
    commit: str,
    release_dir: Path,
    config: dict,
) -> tuple[Path, str]:
    """Create and verify a Git-object-only archive for the exact release commit."""

    try:
        listing = subprocess.run(
            git_argv("ls-tree", "-r", "-z", "--full-tree", commit),
            cwd=repository,
            env=unprivileged_git_environment(),
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReleaseError("source tree inspection timed out") from exc
    if listing.returncode:
        raise ReleaseError(
            "source tree inspection failed: "
            + listing.stderr.decode("utf-8", "replace").strip()
        )
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_name = record.partition(b"\t")
        if not separator or len(metadata.split()) != 3:
            raise ReleaseError("git ls-tree returned an invalid source record")
        mode = metadata.split()[0]
        if mode == b"160000":
            raise ReleaseError(
                "release source contains a gitlink/submodule; production source must be self-contained"
            )
        if b"\n" in raw_name or b"\r" in raw_name:
            raise ReleaseError("release source contains an unsafe path")

    maximum = bounded_positive_integer(
        config, "maxSourceArchiveBytes", 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024
    )
    archive = release_dir / "source.tar"
    temporary = release_dir / f".source.tar.tmp.{os.getpid()}.{secrets_module.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            try:
                result = subprocess.run(
                    git_argv("archive", "--format=tar", commit),
                    cwd=repository,
                    env=unprivileged_git_environment(),
                    stdout=handle,
                    stderr=subprocess.PIPE,
                    timeout=300,
                )
            except subprocess.TimeoutExpired as exc:
                raise ReleaseError("source archive creation timed out") from exc
            handle.flush()
            os.fsync(handle.fileno())
        if result.returncode:
            raise ReleaseError(
                "source archive creation failed: "
                + result.stderr.decode("utf-8", "replace").strip()
            )
        size = temporary.stat().st_size
        if size < 1 or size > maximum:
            raise ReleaseError(f"source archive size must be from 1 to {maximum} bytes")
        digest = file_digest(temporary)
        if archive.exists() or archive.is_symlink():
            if archive.is_symlink() or not archive.is_file():
                raise ReleaseError("recorded source archive is not a regular file")
            if file_digest(archive) != digest:
                raise ReleaseError("exact-commit source archive changed across release passes")
        else:
            os.replace(temporary, archive)
            os.chmod(archive, 0o400, follow_symlinks=False)
        return archive, digest
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def materialize_source_archive(
    archive: Path,
    archive_digest: str,
    commit: str,
    release_dir: Path,
    config: dict,
) -> Path:
    """Extract regular files/directories only into a release-owned read-only tree."""

    if config.get("gitLfsPolicy", "reject-pointers") != "reject-pointers":
        raise ReleaseError("gitLfsPolicy must be 'reject-pointers'; release never fetches external LFS bytes")
    source = release_dir / "source"
    marker = release_dir / "source-materialization.json"
    material = {
        "schemaVersion": 1,
        "commit": commit,
        "sourceArchiveDigest": archive_digest,
    }
    if source.exists() or source.is_symlink() or marker.exists() or marker.is_symlink():
        if source.is_symlink() or not source.is_dir() or marker.is_symlink() or not marker.is_file():
            raise ReleaseError("source materialization is incomplete or unsafe")
        if load_json(marker, "source materialization marker") != material:
            raise ReleaseError("source materialization is bound to different release inputs")
        return source

    max_bytes = bounded_positive_integer(
        config, "maxSourceBytes", 2 * 1024 * 1024 * 1024, 16 * 1024 * 1024 * 1024
    )
    max_files = bounded_positive_integer(config, "maxSourceFiles", 200000, 1000000)
    temporary = release_dir / f".source.tmp.{os.getpid()}.{secrets_module.token_hex(8)}"
    temporary.mkdir(mode=0o700)
    try:
        with tarfile.open(archive, mode="r:") as handle:
            members = handle.getmembers()
            if len(members) > max_files:
                raise ReleaseError(f"source archive exceeds {max_files} members")
            entries: dict[str, tarfile.TarInfo] = {}
            total = 0
            for member in members:
                raw = member.name.rstrip("/")
                path = PurePosixPath(raw)
                if (
                    not raw
                    or path.is_absolute()
                    or raw != path.as_posix()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or any(ord(char) < 32 or ord(char) == 127 for char in raw)
                ):
                    raise ReleaseError(f"source archive contains unsafe member path: {member.name!r}")
                if raw in entries:
                    raise ReleaseError(f"source archive contains duplicate member: {raw}")
                if not (member.isdir() or member.isreg()):
                    raise ReleaseError(
                        f"source archive member {raw!r} is not a regular file or directory"
                    )
                if member.size < 0:
                    raise ReleaseError(f"source archive member {raw!r} has an invalid size")
                total += member.size
                if total > max_bytes:
                    raise ReleaseError(f"source archive expands beyond {max_bytes} bytes")
                entries[raw] = member
            kinds = {name: ("dir" if member.isdir() else "file") for name, member in entries.items()}
            for name in kinds:
                parent = PurePosixPath(name).parent
                while parent.as_posix() != ".":
                    if kinds.get(parent.as_posix()) == "file":
                        raise ReleaseError(f"source archive places a child beneath file {parent}")
                    parent = parent.parent

            for name, member in sorted(entries.items(), key=lambda item: (len(PurePosixPath(item[0]).parts), item[0])):
                destination = temporary.joinpath(*PurePosixPath(name).parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                input_handle = handle.extractfile(member)
                if input_handle is None:
                    raise ReleaseError(f"cannot read source archive member {name!r}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(destination, flags, 0o600)
                prefix = b""
                written = 0
                with os.fdopen(descriptor, "wb") as output_handle:
                    while True:
                        chunk = input_handle.read(1024 * 1024)
                        if not chunk:
                            break
                        if len(prefix) < 256:
                            prefix += chunk[: 256 - len(prefix)]
                        written += len(chunk)
                        output_handle.write(chunk)
                    output_handle.flush()
                    os.fsync(output_handle.fileno())
                if written != member.size:
                    raise ReleaseError(f"source archive member {name!r} changed size while extracting")
                if prefix.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                    raise ReleaseError(
                        f"release source contains a Git LFS pointer ({name}); external LFS content is forbidden"
                    )
                os.chmod(destination, 0o500 if member.mode & 0o111 else 0o400, follow_symlinks=False)
        for directory in sorted(
            (path for path in temporary.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            os.chmod(directory, 0o500, follow_symlinks=False)
        os.chmod(temporary, 0o500, follow_symlinks=False)
        os.rename(temporary, source)
        atomic_json(marker, material)
        os.chmod(marker, 0o400, follow_symlinks=False)
        return source
    except tarfile.TarError as exc:
        raise ReleaseError(f"source archive cannot be parsed safely: {exc}") from exc
    except Exception:
        # The temporary directory is private and never used as a release source.
        # Leave it as crash/forensic evidence instead of recursively deleting
        # potentially surprising paths from an untrusted archive.
        raise


def normalize_trusted_base_ref(config: dict) -> str:
    value = config.get("trustedBaseRef")
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", value)
        or ".." in value
        or "//" in value
        or value.endswith(("/", ".", ".lock"))
    ):
        raise ReleaseError("enabled deployment requires a safe trustedBaseRef")
    return value


def configured_teamwork_root(repository: Path) -> Path:
    text = skill_path("config/team.config.md").read_text()
    match = re.search(r"^TEAMWORK_ROOT=(.*)$", text, re.MULTILINE)
    if not match:
        raise ReleaseError("team config has no TEAMWORK_ROOT")
    value = match.group(1).split("#", 1)[0].strip().strip('"')
    relative = Path(value)
    if not value or relative.is_absolute() or ".." in relative.parts:
        raise ReleaseError("TEAMWORK_ROOT must be a contained repository-relative path")
    current = repository
    for part in relative.parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise ReleaseError("TEAMWORK_ROOT must not traverse symlinks")
    resolved = (repository / relative).resolve()
    try:
        resolved.relative_to(repository)
    except ValueError as exc:
        raise ReleaseError("TEAMWORK_ROOT escapes the repository") from exc
    return resolved


def hook_binding(name: str, config: dict, values: dict[str, str], repository: Path) -> dict:
    source_argv = render_hook((config.get("hooks") or {}).get(name), values, name)
    digest, executable = validate_hook_executable(
        name,
        source_argv,
        config,
        repository,
        Path(values["source_dir"]),
        Path(values["source_archive"]),
    )
    return {
        "executableDigest": digest,
        "sourceArgv": source_argv,
        "argv": [str(executable), *source_argv[1:]],
    }


def validate_manifest_bindings(
    manifest: dict,
    config: dict,
    values: dict[str, str],
    repository: Path,
    deployment_config_digest: str,
) -> dict[str, dict]:
    if manifest.get("deploymentConfigDigest") != deployment_config_digest:
        raise ReleaseError("deployment config changed after the release manifest was recorded")
    recorded = manifest.get("hookBindings")
    if not isinstance(recorded, dict):
        raise ReleaseError("release manifest has no hook bindings")
    expected_names = {
        name
        for name in ("apply", "status", "verify", "rollback", "verifyApproval", "verifyDelivery")
        if (config.get("hooks") or {}).get(name)
    }
    if set(recorded) != expected_names:
        raise ReleaseError("release manifest hook set differs from the protected deployment config")
    current = {name: hook_binding(name, config, values, repository) for name in sorted(expected_names)}
    if current != recorded:
        raise ReleaseError("release hook argv/digests changed after the manifest was recorded")
    return current


def write_manifest(
    path: Path,
    *,
    args: argparse.Namespace,
    config: dict,
    values: dict[str, str],
    target: dict[str, str],
    plan: dict,
    plan_digest: str,
    deployment_config_digest: str,
    integration_evidence_digest: str,
    product_acceptance_digest: str,
    delivery_attestation_digest: str | None,
    source_archive_digest: str,
    repository: Path,
) -> dict:
    ttl = config.get("approvalTtlSeconds", 900)
    if type(ttl) is not int or ttl < 60 or ttl > 86400:
        raise ReleaseError("approvalTtlSeconds must be an integer from 60 to 86400")
    created = datetime.now(timezone.utc)
    expires = created + timedelta(seconds=ttl)
    if delivery_attestation_digest is not None:
        attestation_expiry = parse_time(
            values.get("delivery_attestation_expires_at"),
            "delivery attestation expiresAt",
        )
        expires = min(expires, attestation_expiry)
    values["authorization_expires_at"] = expires.isoformat(timespec="seconds")
    bindings = {
        name: hook_binding(name, config, values, repository)
        for name in ("apply", "status", "verify", "rollback", "verifyApproval", "verifyDelivery")
        if (config.get("hooks") or {}).get(name)
    }
    manifest = {
        "schemaVersion": 1,
        "actionType": "deploy.apply",
        "environment": config["environment"],
        "target": target,
        "featureId": args.feature,
        "team": args.team,
        "commit": plan["commit"],
        "sourceArchiveDigest": source_archive_digest,
        "artifactDigest": plan["artifactDigest"],
        "planDigest": plan_digest,
        "deploymentConfigDigest": deployment_config_digest,
        "integrationEvidenceDigest": integration_evidence_digest,
        "productAcceptanceDigest": product_acceptance_digest,
        "deliveryAttestationDigest": delivery_attestation_digest,
        "releaseId": values["release_id"],
        "hookBindings": bindings,
        "nonce": secrets_module.token_hex(32),
        "createdAt": created.isoformat(timespec="seconds"),
        "expiresAt": values["authorization_expires_at"],
    }
    atomic_json(path, manifest)
    return manifest


def validate_approval_proof(proof: dict, manifest: dict, *, require_fresh: bool) -> None:
    expected_fields = {
        "schemaVersion", "approved", "manifestDigest", "nonce", "approver",
        "approvalId", "approvedAt", "expiresAt",
    }
    expected_digest = canonical_digest(manifest)
    if (
        not isinstance(proof, dict)
        or set(proof) != expected_fields
        or type(proof.get("schemaVersion")) is not int
        or proof.get("schemaVersion") != 1
        or proof.get("approved") is not True
    ):
        raise ReleaseError("approval verifier returned an invalid proof")
    if proof.get("manifestDigest") != expected_digest or proof.get("nonce") != manifest.get("nonce"):
        raise ReleaseError("approval proof is not bound to the exact manifest nonce/digest")
    approver = proof.get("approver")
    if isinstance(approver, dict):
        approver = approver.get("id")
    if not isinstance(approver, str) or not approver.strip() or len(approver) > 256:
        raise ReleaseError("approval proof needs a bounded approver identity")
    approval_id = proof.get("approvalId")
    if not isinstance(approval_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,256}", approval_id):
        raise ReleaseError("approval proof needs a stable approvalId")
    approved_at = parse_time(proof.get("approvedAt"), "approval approvedAt")
    expires_at = parse_time(proof.get("expiresAt"), "approval expiresAt")
    manifest_expiry = parse_time(manifest.get("expiresAt"), "manifest expiresAt")
    current = datetime.now(timezone.utc)
    if expires_at != manifest_expiry or approved_at > current + timedelta(minutes=5) or approved_at < parse_time(manifest["createdAt"], "manifest createdAt") - timedelta(minutes=5):
        raise ReleaseError("approval proof timestamps do not match the manifest validity window")
    if require_fresh and current >= expires_at:
        raise AwaitingAuthorization("approval expired before apply")


def verify_approval(
    manifest: dict,
    manifest_file: Path,
    proof_file: Path,
    config: dict,
    values: dict[str, str],
    repository: Path,
    env: dict[str, str],
    logs: Path,
    expected_bindings: dict[str, dict],
) -> dict:
    result = run_hook(
        "verifyApproval", "approval.verify", config, values,
        repository=repository, env=env, secrets=[], logs=logs, check=False,
        expected_binding=expected_bindings.get("verifyApproval"),
    )
    if result.returncode:
        raise AwaitingAuthorization("external approval verifier has not authorized this exact manifest")
    try:
        proof = strict_json(result.stdout)
    except ValueError as exc:
        raise ReleaseError("approval verifier must print one JSON proof object") from exc
    validate_approval_proof(proof, manifest, require_fresh=True)
    atomic_json(proof_file, proof)
    return proof


def validate_delivery_attestation(
    proof: dict,
    *,
    feature_id: str,
    team: str,
    commit: str,
    source_archive_digest: str,
    integration_evidence_digest: str,
    product_acceptance_digest: str,
    config: dict,
    require_fresh: bool,
) -> None:
    if proof.get("schemaVersion") != 1 or proof.get("trusted") is not True:
        raise ReleaseError("delivery attestation must be a trusted schemaVersion 1 proof")
    expected = {
        "featureIdDigest": text_digest(feature_id),
        "team": team,
        "commit": commit,
        "sourceArchiveDigest": source_archive_digest,
        "integrationEvidenceDigest": integration_evidence_digest,
        "productAcceptanceDigest": product_acceptance_digest,
    }
    if any(proof.get(key) != value for key, value in expected.items()):
        raise ReleaseError("delivery attestation is not bound to the exact feature/team/commit/source/evidence")
    if (
        proof.get("roleIsolation") is not True
        or proof.get("approvalAuthenticity") is not True
        or proof.get("planningIsolation") is not True
    ):
        raise ReleaseError(
            "delivery attestation must independently verify role, planning, and approval isolation/authenticity"
        )
    provider = proof.get("isolationProvider")
    if not isinstance(provider, str) or not provider.strip() or len(provider) > 256:
        raise ReleaseError("delivery attestation needs a bounded isolationProvider")
    planning_provider = proof.get("planningIsolationProvider")
    configured_planning = config.get("planningIsolation") or {}
    if (
        not isinstance(planning_provider, str)
        or planning_provider != configured_planning.get("provider")
    ):
        raise ReleaseError(
            "delivery attestation planningIsolationProvider does not match the protected config"
        )
    attestation_id = proof.get("attestationId")
    if not isinstance(attestation_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,256}", attestation_id):
        raise ReleaseError("delivery attestation needs a stable attestationId")
    issued = parse_time(proof.get("issuedAt"), "delivery attestation issuedAt")
    expires = parse_time(proof.get("expiresAt"), "delivery attestation expiresAt")
    ttl = config.get("deliveryAttestationTtlSeconds", 900)
    if type(ttl) is not int or ttl < 60 or ttl > 3600:
        raise ReleaseError("deliveryAttestationTtlSeconds must be an integer from 60 to 3600")
    if expires <= issued or expires - issued > timedelta(seconds=ttl):
        raise ReleaseError("delivery attestation validity exceeds the configured maximum")
    current = datetime.now(timezone.utc)
    if issued > current + timedelta(minutes=5):
        raise ReleaseError("delivery attestation was issued in the future")
    if require_fresh and current >= expires:
        raise AwaitingAuthorization("delivery identity/isolation attestation expired before apply")


def obtain_delivery_attestation(
    proof_file: Path,
    config: dict,
    values: dict[str, str],
    repository: Path,
    planning_env: dict[str, str],
    logs: Path,
    *,
    feature_id: str,
    team: str,
    commit: str,
    source_archive_digest: str,
    integration_evidence_digest: str,
    product_acceptance_digest: str,
) -> dict:
    result = run_hook(
        "verifyDelivery", "delivery.verify", config, values,
        repository=repository, env=planning_env, secrets=[], logs=logs, check=False,
    )
    if result.returncode:
        raise AwaitingAuthorization("external delivery attestor has not verified isolated role identities")
    try:
        proof = strict_json(result.stdout)
    except ValueError as exc:
        raise ReleaseError("delivery attestor must print one JSON proof object") from exc
    if not isinstance(proof, dict):
        raise ReleaseError("delivery attestor must print one JSON proof object")
    validate_delivery_attestation(
        proof,
        feature_id=feature_id,
        team=team,
        commit=commit,
        source_archive_digest=source_archive_digest,
        integration_evidence_digest=integration_evidence_digest,
        product_acceptance_digest=product_acceptance_digest,
        config=config,
        require_fresh=True,
    )
    atomic_json(proof_file, proof)
    return proof


def check_sibling_transactions(releases: Path, release_id: str, commit: str) -> None:
    safe_preapply = {
        "new", "awaiting-product-approval", "awaiting-attestation", "planned",
        "awaiting-approval",
    }
    postapply = {"applying", "verifying", "rolling-back"}
    if not releases.exists():
        return
    for path in releases.glob("*/transaction.json"):
        if path.parent.name == release_id:
            continue
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"unsafe sibling deployment transaction: {path}")
        transaction = load_json(path, "sibling deployment transaction")
        phase = transaction.get("phase")
        if transaction.get("commit") == commit:
            continue
        if phase in safe_preapply:
            if transaction.get("productAcceptanceConsumedAt") or transaction.get("approvalConsumedAt"):
                raise ReleaseError(
                    "an older deployment transaction consumed production authority and needs manual recovery"
                )
            transaction.update({
                "phase": "superseded",
                "supersededByReleaseId": release_id,
                "supersededByCommit": commit,
                "updatedAt": now(),
            })
            atomic_json(path, transaction)
        elif phase in postapply:
            raise ReleaseError("another commit has an active deployment transaction for this feature/environment")


def latest_verified_predecessor(
    releases: Path,
    release_id: str,
    *,
    feature_id: str,
    environment: str,
    target: dict[str, str],
) -> dict | None:
    """Return the newest protected successful release commit for an incremental generation."""
    candidates: list[tuple[datetime, str, Path, dict]] = []
    if not releases.exists():
        return None
    for path in releases.glob("*/transaction.json"):
        if path.parent.name == release_id:
            continue
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"unsafe predecessor deployment transaction: {path}")
        transaction = load_json(path, "predecessor deployment transaction")
        if transaction.get("phase") != "succeeded":
            continue
        if (
            transaction.get("featureId") != feature_id
            or transaction.get("environment") != environment
            or transaction.get("target") != target
        ):
            raise ReleaseError("successful predecessor transaction does not match its feature/environment group")
        commit = str(transaction.get("commit") or "")
        verified_at = str(transaction.get("verifiedAt") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ReleaseError("successful predecessor transaction has an invalid commit")
        try:
            timestamp = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReleaseError("successful predecessor transaction has an invalid verifiedAt") from exc
        if timestamp.tzinfo is None:
            raise ReleaseError("successful predecessor transaction verifiedAt must be timezone-aware")
        candidates.append((timestamp, path.parent.name, path.parent, transaction))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]))
    newest_time = candidates[-1][0]
    newest = [item for item in candidates if item[0] == newest_time]
    newest_commits = {str(item[3].get("commit") or "") for item in newest}
    if len(newest_commits) != 1:
        raise ReleaseError("successful predecessor transactions have an ambiguous latest commit")
    _timestamp, _release_id, release_dir, transaction = newest[-1]
    manifest_path = release_dir / "integration-evidence.json"
    snapshot_path = release_dir / "tasks.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ReleaseError("successful predecessor release has no protected integration evidence manifest")
    if snapshot_path.is_symlink() or not snapshot_path.is_file():
        raise ReleaseError("successful predecessor release has no protected tracker snapshot")
    manifest = load_json(manifest_path, "predecessor integration evidence manifest")
    snapshot = load_json(snapshot_path, "predecessor tracker snapshot")
    evidence_digest = str(transaction.get("integrationEvidenceDigest") or "")
    if canonical_digest(manifest) != evidence_digest:
        raise ReleaseError("successful predecessor integration evidence digest does not match its manifest")
    if (
        manifest.get("featureId") != feature_id
        or manifest.get("headCommit") != transaction.get("commit")
        or snapshot.get("featureId") != feature_id
    ):
        raise ReleaseError("successful predecessor evidence is bound to different release inputs")
    return {
        "commit": str(transaction["commit"]),
        "integrationEvidenceDigest": evidence_digest,
        "manifest": manifest,
        "snapshot": snapshot,
        "releaseId": str(transaction.get("releaseId") or ""),
    }


def safe_task_key(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()[:32] or "task"
    return f"{slug}-{hashlib.sha256(value.encode()).hexdigest()[:10]}"


def ignored_task_labels() -> set[str]:
    raw = os.environ.get(
        "STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON", '["human-work"]'
    )
    try:
        values = json.loads(raw)
    except ValueError as exc:
        raise ReleaseError("ignored-task label policy is invalid JSON") from exc
    if not isinstance(values, list) or any(
        not isinstance(item, str) or not item.strip() or item != item.strip()
        for item in values
    ):
        raise ReleaseError(
            "ignored-task label policy must be a JSON array of canonical strings"
        )
    canonical = [item.casefold() for item in values]
    if len(canonical) != len(set(canonical)):
        raise ReleaseError("ignored-task label policy contains a duplicate")
    return set(canonical)


def verify_integrations(
    snapshot: dict,
    workspace: Path,
    repository: Path,
    team: str,
    feature_id: str,
    tracker_env: dict[str, str],
    trusted_base_ref: str,
    expected_commit: str,
    trusted_generation_predecessor: dict | None = None,
    evidence_manifest_path: Path | None = None,
) -> str:
    board = load_json(skill_path("config/statuses.config.json"), "status config")
    terminals = {
        status["name"] for status in board.get("tasks", {}).get("statuses", [])
        if status.get("terminal") and status.get("requiresCommit")
    }
    tasks = snapshot.get("tasks") or []
    if not tasks or not terminals:
        raise ReleaseError("release requires at least one integrated [task] and one commit-requiring terminal status")
    if any(task.get("status") not in terminals for task in tasks):
        raise ReleaseError("not every [task] is in the commit-requiring terminal status")
    ignored = ignored_task_labels()
    for task in tasks:
        labels = task.get("labels") or []
        if not isinstance(labels, list) or any(not isinstance(item, str) for item in labels):
            raise ReleaseError("tracker snapshot contains malformed task labels")
        if ignored.intersection(item.strip().casefold() for item in labels):
            raise ReleaseError(
                "a [task] is labeled for human work; production delivery is stopped"
            )
    integrations = workspace / "integrations"
    if integrations.is_symlink() or not integrations.is_dir():
        raise ReleaseError("release requires a non-symlink integration transaction directory")
    # The same deterministic broker that authorized terminal tracker writes revalidates
    # current approvals, package bytes, commit trailers, execution identity, and every
    # transaction before production authority is considered.
    subprocess_text(
        [str(skill_path("bin/finalize-integrations.sh")), team, feature_id],
        repository,
        tracker_env,
        "integration evidence validation",
    )
    records: dict[str, dict] = {}
    for path in integrations.glob("*.json"):
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"unsafe integration transaction: {path}")
        value = load_json(path, "integration transaction")
        if value.get("schemaVersion") != 2:
            raise ReleaseError(f"integration transaction uses an unsupported schema: {path.name}")
        task_id = str(value.get("taskId") or "")
        if path.name != safe_task_key(task_id) + ".json":
            raise ReleaseError("integration transaction filename is not bound to its task")
        if value.get("team") != team or value.get("featureId") != feature_id:
            raise ReleaseError("integration transaction is bound to a different team/feature")
        if value.get("phase") == "completed":
            if task_id in records:
                raise ReleaseError(f"duplicate completed integration transaction for [task] {task_id}")
            records[task_id] = value
    tasks_by_id = {str(task.get("taskId")): task for task in tasks}
    if len(tasks_by_id) != len(tasks) or "" in tasks_by_id:
        raise ReleaseError("tracker snapshot contains missing or duplicate task identifiers")
    if not set(records).issubset(tasks_by_id):
        raise ReleaseError("current-generation integration transactions include a task outside the tracker set")
    for task_id, record in records.items():
        if not record.get("commit"):
            raise ReleaseError(f"[task] {task_id} has no completed integration transaction")
        for field in (
            "transactionId", "executionDigest", "reviewPackageSha256",
            "approvalEvidenceDigest", "completionBodySha256",
        ):
            value = str(record.get(field) or "")
            if field == "transactionId":
                valid = bool(re.fullmatch(r"integration-[0-9a-f]{32}", value))
            else:
                valid = bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value))
            if not valid:
                raise ReleaseError(f"integration transaction for [task] {task_id} has invalid {field}")
        ancestor = subprocess.run(
            git_argv("merge-base", "--is-ancestor", str(record["commit"]), team),
            cwd=repository,
            env=unprivileged_git_environment(),
            capture_output=True,
            text=True,
        )
        if ancestor.returncode:
            raise ReleaseError(f"integration commit for [task] {task_id} is not on {team}")

    predecessor_commit = None
    predecessor_digest = None
    inherited_task_ids: list[str] = []
    inherited_evidence: list[dict[str, str]] = []
    if trusted_generation_predecessor is not None:
        predecessor_commit = str(trusted_generation_predecessor.get("commit") or "")
        predecessor_digest = str(
            trusted_generation_predecessor.get("integrationEvidenceDigest") or ""
        )
        prior_manifest = trusted_generation_predecessor.get("manifest") or {}
        prior_snapshot = trusted_generation_predecessor.get("snapshot") or {}
        prior_evidence_items = [
            *(prior_manifest.get("transactions") or []),
            *(prior_manifest.get("inheritedEvidence") or []),
        ]
        prior_transactions = {
            str(item.get("taskId")): item
            for item in prior_evidence_items
            if isinstance(item, dict) and item.get("taskId")
        }
        prior_tasks = {
            str(item.get("taskId")): item
            for item in prior_snapshot.get("tasks") or []
            if isinstance(item, dict) and item.get("taskId")
        }
        if len(prior_transactions) != len(prior_evidence_items):
            raise ReleaseError("predecessor integration manifest has missing or duplicate task identifiers")
        if len(prior_tasks) != len(prior_snapshot.get("tasks") or []):
            raise ReleaseError("predecessor tracker snapshot has missing or duplicate task identifiers")
        prior_ids = set(prior_transactions)
        if not prior_ids.issubset(tasks_by_id):
            raise ReleaseError("a previously released task disappeared from the authoritative feature export")
        inherited = set(tasks_by_id) - set(records)
        if not inherited.issubset(prior_ids):
            missing = sorted(inherited - prior_ids)
            raise ReleaseError(
                "current tracker tasks without generation transactions are not protected predecessor tasks: "
                + ", ".join(missing)
            )
        implementation_markers = {
            "claim", "design-note", "design-approved", "design-pushback",
            "review-request", "review-findings", "review-approval",
            "architecture-approval", "handoff", "andon",
        }

        def implementation_evidence(task: dict) -> list[str]:
            result = []
            for comment in task.get("comments") or []:
                body = str(comment.get("body") or "").strip()
                match = re.match(r"^\s*\[([\w-]+)\]", body)
                if match and match.group(1) in implementation_markers:
                    result.append(body)
            return result

        for task_id in sorted(inherited):
            current_task = tasks_by_id[task_id]
            prior_task = prior_tasks.get(task_id)
            prior_transaction = prior_transactions[task_id]
            if prior_task is None:
                raise ReleaseError(f"protected predecessor snapshot is missing [task] {task_id}")
            for field in ("title", "description", "blockedBy", "labels", "status"):
                if current_task.get(field) != prior_task.get(field):
                    raise ReleaseError(
                        f"previously released [task] {task_id} changed {field}; it requires a current-generation transaction"
                    )
            if implementation_evidence(current_task) != implementation_evidence(prior_task):
                raise ReleaseError(
                    f"previously released [task] {task_id} has changed implementation/review evidence"
                )
            token = "Integrated: commit %s." % prior_transaction.get("commit")
            current_comments = [str(item.get("body") or "") for item in current_task.get("comments") or []]
            prior_comments = [str(item.get("body") or "") for item in prior_task.get("comments") or []]
            if not any(token in body for body in current_comments) or not any(
                token in body for body in prior_comments
            ):
                raise ReleaseError(
                    f"previously released [task] {task_id} lacks its protected integration receipt"
                )
            inherited_evidence.append({
                "taskId": task_id,
                "transactionId": str(prior_transaction.get("transactionId") or ""),
                "commit": str(prior_transaction.get("commit") or ""),
            })
        inherited_task_ids = sorted(inherited)
    elif set(records) != set(tasks_by_id):
        raise ReleaseError("completed integration transactions do not exactly match the tracker task set")

    by_commit: dict[str, dict] = {}
    for record in records.values():
        commit = str(record.get("commit") or "")
        if commit in by_commit:
            raise ReleaseError("two integration transactions claim the same merge commit")
        by_commit[commit] = record
    feature_head = git_text(repository, "feature head lookup", "rev-parse", "--verify", f"{team}^{{commit}}")
    if feature_head != expected_commit:
        raise ReleaseError(
            "feature HEAD changed after the release source commit was captured"
        )
    if feature_head not in by_commit:
        raise ReleaseError("feature HEAD is not the final reviewed integration commit")
    reverse_chain: list[dict] = []
    seen: set[str] = set()
    cursor = feature_head
    while cursor in by_commit:
        if cursor in seen:
            raise ReleaseError("integration commit chain contains a cycle")
        seen.add(cursor)
        record = by_commit[cursor]
        reverse_chain.append(record)
        cursor = str(record.get("baseCommit") or "")
    if len(reverse_chain) != len(records):
        raise ReleaseError("integration commits do not form one closed, gap-free feature chain")
    trusted_tip = git_text(
        repository, "trusted base lookup", "rev-parse", "--verify", f"{trusted_base_ref}^{{commit}}"
    )
    starts_on_protected_base = subprocess.run(
        git_argv("merge-base", "--is-ancestor", cursor, trusted_tip),
        cwd=repository,
        env=unprivileged_git_environment(),
        capture_output=True,
        text=True,
    ).returncode == 0
    if not starts_on_protected_base and cursor != predecessor_commit:
        raise ReleaseError(
            "the integration chain starts outside both protected base-ref history and the latest verified generation"
        )
    chain_trust = (
        {"kind": "protected-base-ref", "commit": cursor}
        if starts_on_protected_base
        else {
            "kind": "prior-verified-release",
            "commit": cursor,
            "integrationEvidenceDigest": predecessor_digest,
        }
    )
    chain = list(reversed(reverse_chain))
    material = {
        "schemaVersion": 1,
        "featureId": feature_id,
        "team": team,
        "trustedBaseRef": trusted_base_ref,
        "chainBaseCommit": cursor,
        "chainTrust": chain_trust,
        "headCommit": feature_head,
        "transactions": [
            {
                "taskId": record["taskId"],
                "transactionId": record["transactionId"],
                "baseCommit": record["baseCommit"],
                "taskBranchHead": record["taskBranchHead"],
                "commit": record["commit"],
                "executionDigest": record["executionDigest"],
                "reviewPackageSha256": record["reviewPackageSha256"],
                "approvalEvidenceDigest": record["approvalEvidenceDigest"],
            }
            for record in chain
        ],
        "inheritedTasks": inherited_task_ids,
        "inheritedEvidence": inherited_evidence,
    }
    if evidence_manifest_path is not None:
        atomic_json(evidence_manifest_path, material)
    return canonical_digest(material)


def deployment_projection(transaction: dict) -> str:
    lines = [
        "[deployment]",
        f"state: {transaction.get('phase')}",
        f"environment: {transaction.get('environment')}",
        f"target: {(transaction.get('target') or {}).get('id')}",
        f"release-id: {transaction.get('releaseId')}",
        f"commit: {transaction.get('commit')}",
        f"artifact: {transaction.get('artifactDigest')}",
        f"integration-evidence-digest: {transaction.get('integrationEvidenceDigest')}",
        f"product-acceptance: {transaction.get('productAcceptanceState') or 'pending'}",
        f"product-acceptance-digest: {transaction.get('productAcceptanceDigest') or 'pending'}",
        f"plan-digest: {transaction.get('planDigest')}",
        f"approval-id: {transaction.get('approvalId') or 'not-required-or-pending'}",
        f"updated-at: {transaction.get('updatedAt')}",
        "",
        "— release-executor",
    ]
    return "\n".join(lines) + "\n"


def project_transaction(
    transaction: dict,
    release_dir: Path,
    repository: Path,
    feature_id: str,
    tracker_env: dict[str, str],
) -> None:
    body = release_dir / "deployment-projection.md"
    atomic_text(body, deployment_projection(transaction))
    subprocess_text(
        [str(skill_path("bin/tracker-ops.sh")), "upsert-deployment", feature_id, str(body)],
        repository,
        tracker_env,
        "deployment projection",
    )


def finish_feature(
    repository: Path,
    feature_id: str,
    tracker_env: dict[str, str],
    before_transition=None,
) -> None:
    board = load_json(skill_path("config/statuses.config.json"), "status config")
    terminals = [status["name"] for status in board.get("features", {}).get("statuses", []) if status.get("terminal")]
    if len(terminals) != 1:
        raise ReleaseError("production completion requires exactly one terminal [feature] status")
    if before_transition is not None:
        before_transition()
    subprocess_text(
        [str(skill_path("bin/tracker-ops.sh")), "feature-state", feature_id, terminals[0]],
        repository,
        tracker_env,
        "terminal [feature] transition",
    )


def record_release_denial(
    snapshot: dict,
    release_dir: Path,
    repository: Path,
    tracker_env: dict[str, str],
    release_id: str,
    plan_digest: str,
) -> None:
    task_ids = sorted(
        str(task.get("taskId"))
        for task in (snapshot.get("tasks") or [])
        if task.get("taskId") is not None
    )
    if not task_ids:
        raise ReleaseError("cannot project release policy denial without an anchor task")
    attempted = release_dir / "denied-action.txt"
    atomic_text(
        attempted,
        "Production deployment of the exact reviewed release plan "
        f"(release-id {release_id}, plan-digest {plan_digest}).\n",
    )
    denial_id = "release-denial-" + hashlib.sha256(
        (release_id + "\0" + plan_digest).encode()
    ).hexdigest()[:24]
    subprocess_text(
        [
            str(skill_path("bin/tracker-ops.sh")),
            "record-denial",
            task_ids[0],
            "--actor", "release-executor",
            "--reason", "protected production release policy denied the normalized plan",
            "--denial-id", denial_id,
            str(attempted),
        ],
        repository,
        tracker_env,
        "release denial projection",
    )


def reset_preapply_transaction_for_product(transaction: dict) -> None:
    """Invalidate every derived authorization when the product verdict changes."""

    for key in (
        "artifactDigest", "planDigest", "manifestDigest", "manifestNonce", "manifestExpiresAt",
        "deliveryAttestationDigest", "deliveryAttestationId", "deliveryAttestationExpiresAt",
        "approvalId", "approvalApprover", "approvalProofDigest", "approvalExpiresAt",
        "approvalVerifiedAt", "approvalConsumedAt", "productAcceptanceConsumedAt",
        "productAcceptanceReason", "failure",
    ):
        transaction.pop(key, None)
    transaction["phase"] = "new"


def reset_preapply_transaction_for_attestation(transaction: dict) -> None:
    """Discard plans and authorizations derived from an expired delivery proof."""

    for key in (
        "artifactDigest", "planDigest", "manifestDigest", "manifestNonce", "manifestExpiresAt",
        "deliveryAttestationDigest", "deliveryAttestationId", "deliveryAttestationExpiresAt",
        "approvalId", "approvalApprover", "approvalProofDigest", "approvalExpiresAt",
        "approvalVerifiedAt", "approvalConsumedAt", "failure",
    ):
        transaction.pop(key, None)
    transaction["phase"] = "new"


def reset_preapply_transaction_for_evidence(transaction: dict) -> None:
    """Invalidate product and release authority when the tracker/evidence set changes."""

    reset_preapply_transaction_for_product(transaction)
    for key in (
        "productAcceptanceDigest", "productAcceptanceState", "productAcceptanceAnchorTaskId",
        "productAcceptanceFreshness", "productAcceptanceBodyDigest", "productAcceptanceReason",
    ):
        transaction.pop(key, None)


def reconcile_rolling_back(transaction: dict, observed: dict) -> str:
    """Reconcile a crash during rollback without replaying apply or rollback."""

    previous = transaction.get("previousArtifactDigest")
    state = observed.get("state")
    if state == "applied" and observed.get("artifactDigest") == previous:
        transaction.update({
            "phase": "rolled-back",
            "rollbackVerifiedAt": now(),
            "updatedAt": now(),
        })
        return "rolled-back"
    if state == "in-progress" and observed.get("artifactDigest") in {None, previous}:
        transaction["updatedAt"] = now()
        return "in-progress"
    transaction.update({
        "phase": "failed",
        "failure": "rollback outcome is uncertain; explicit operator recovery is required",
        "updatedAt": now(),
    })
    return "failed"


def execute(args: argparse.Namespace) -> int:
    global TRUSTED_SKILL_DIR, PROTECTED_HOOK_ROOT
    repository = args.repository.resolve()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", args.team):
        raise ReleaseError("unsafe team/branch identifier")
    requested_workspace = args.workspace.expanduser()
    if requested_workspace.is_symlink():
        raise ReleaseError("team workspace must not be a symlink")
    workspace = requested_workspace.resolve()
    config = load_json(args.config, "deployment config")
    if config.get("schemaVersion") != 1:
        raise ReleaseError("deployment config schemaVersion must be 1")
    if type(config.get("enabled")) is not bool:
        raise ReleaseError("deployment config enabled must be true or false")
    if not config["enabled"]:
        print("release-feature: deployment is disabled")
        return 4
    config_candidate = args.config.expanduser()
    if not config_candidate.is_absolute():
        config_candidate = Path.cwd() / config_candidate
    if config_candidate.is_symlink():
        raise ReleaseError("enabled deployment config must not be a symlink")
    protected_config_path = config_candidate.resolve()
    try:
        protected_config_path.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ReleaseError("enabled deployment config must live outside the agent repository")
    protected_config_raw, _ = capture_protected_file(
        protected_config_path, "deployment config"
    )
    try:
        protected_config = strict_json(protected_config_raw)
    except ValueError as exc:
        raise ReleaseError(f"deployment config is invalid JSON: {exc}") from exc
    if protected_config != config:
        raise ReleaseError("deployment config changed while it was being loaded")
    if config.get("mode") not in {"automatic", "approval-required"}:
        raise ReleaseError("deployment mode must be automatic or approval-required")
    if config.get("environment") != "production":
        raise ReleaseError("release executor is reserved for the production environment")
    required = {"plan", "apply", "status", "verify"}
    missing = sorted(name for name in required if not (config.get("hooks") or {}).get(name))
    if missing:
        raise ReleaseError("missing required deployment hooks: " + ", ".join(missing))
    if not any(
        "{authorization_expires_at}" in token
        for token in (config.get("hooks") or {}).get("apply", [])
        if isinstance(token, str)
    ):
        raise ReleaseError(
            "apply hook must receive {authorization_expires_at} and enforce that deadline in the protected provider"
        )
    if config["mode"] == "approval-required" and not (config.get("hooks") or {}).get("verifyApproval"):
        raise ReleaseError("approval-required mode needs a verifyApproval hook")
    if config["mode"] == "automatic" and not (config.get("hooks") or {}).get("verifyDelivery"):
        raise ReleaseError("automatic mode needs a protected verifyDelivery identity/isolation attestor")

    validate_planning_isolation_config(config)
    configure_trusted_tools(config, repository)
    bind_repository_identity(args, repository)

    try:
        SKILL_DIR.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ReleaseError(
            "enabled release executor/skill must be installed outside the target agent repository"
        )
    deployment_config_digest, captured_trusted_code = validate_release_trust(
        args.config, config, repository
    )
    target = normalize_target(config)
    trusted_base_ref = normalize_trusted_base_ref(config)
    state_root = trusted_state_root(config, repository)
    TRUSTED_SKILL_DIR = materialize_trusted_code(
        state_root,
        deployment_config_digest,
        captured_trusted_code,
        config["trustedCodeDigests"],
    )
    PROTECTED_HOOK_ROOT = state_root / "trusted-hooks" / deployment_config_digest.removeprefix("sha256:")

    expected_workspace_path = configured_teamwork_root(repository) / args.team
    if expected_workspace_path.is_symlink():
        raise ReleaseError("canonical team workspace must not be a symlink")
    expected_workspace = expected_workspace_path.resolve()
    if workspace != expected_workspace:
        raise ReleaseError("workspace must equal the canonical configured TEAMWORK_ROOT/team path")
    if not workspace.is_dir():
        raise ReleaseError("canonical team workspace must be a non-symlink directory")

    branch = git_text(repository, "branch check", "branch", "--show-current")
    if branch != args.team:
        raise ReleaseError(f"integration worktree must be on feature branch '{args.team}'")
    dirty = git_text(
        repository,
        "clean check",
        "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=all",
    )
    if dirty:
        raise ReleaseError("feature integration worktree is dirty")
    commit = git_text(repository, "commit lookup", "rev-parse", "--verify", f"{args.team}^{{commit}}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("feature branch did not resolve to a full commit hash")

    tracker_env = read_environment(config, "trackerEnvironmentAllowlist", repository)
    lifecycle_authority = os.environ.get("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT")
    if lifecycle_authority:
        # Internal broker authority is deliberately not a deployment-provider
        # credential and is never forwarded to hooks.  It is required by the
        # pinned integration finalizer to honor Blocked holds during release.
        tracker_env["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = lifecycle_authority
    tracker_env["STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON"] = json.dumps(
        sorted(ignored_task_labels()), separators=(",", ":")
    )
    tracker_env.setdefault("TRACKER_PROJECT_ROOT", str(repository))
    tracker_env["STARTUP_FACTORY_RELEASE_EXECUTOR"] = "1"
    environment = str(config["environment"])
    release_id = hashlib.sha256((args.feature + "\0" + commit + "\0" + environment).encode()).hexdigest()[:24]
    group_id = hashlib.sha256((str(repository) + "\0" + args.feature + "\0" + environment).encode()).hexdigest()[:24]
    group_root = state_root / "features" / group_id
    releases = group_root / "releases"
    releases.mkdir(parents=True, exist_ok=True, mode=0o700)
    lease_key = target_lease_key(environment, target)
    target_root = state_root / "targets" / lease_key
    target_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    target_active_file = target_root / "active.json"

    with release_lock(target_root / "release.lock"), release_lock(group_root / "release.lock"):
        release_dir = releases / release_id
        release_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        transaction_file = release_dir / "transaction.json"
        plan_file = release_dir / "plan.json"
        manifest_file = release_dir / "approval-manifest.json"
        proof_file = release_dir / "approval-proof.json"
        delivery_attestation_file = release_dir / "delivery-attestation.json"
        product_request_file = workspace / "product-acceptance-request.json"
        snapshot_path = release_dir / "tasks.json"
        logs = release_dir / "logs"
        source_archive, source_archive_digest = create_source_archive(
            repository, commit, release_dir, config
        )
        source_directory = materialize_source_archive(
            source_archive, source_archive_digest, commit, release_dir, config
        )

        check_sibling_transactions(releases, release_id, commit)
        trusted_generation_predecessor = latest_verified_predecessor(
            releases,
            release_id,
            feature_id=args.feature,
            environment=environment,
            target=target,
        )
        subprocess_text(
            [str(skill_path("bin/tracker-ops.sh")), "export", args.feature, str(snapshot_path)],
            repository, tracker_env, "release tracker snapshot",
        )
        snapshot = load_json(snapshot_path, "release tracker snapshot")
        integration_manifest_path = release_dir / "integration-evidence.json"
        integration_evidence_digest = verify_integrations(
            snapshot, workspace, repository, args.team, args.feature, tracker_env,
            trusted_base_ref, commit, trusted_generation_predecessor,
            integration_manifest_path,
        )

        values = {
            "team": args.team, "feature_id_digest": text_digest(args.feature),
            "commit": commit, "environment": environment, "release_id": release_id,
            "plan_file": str(plan_file), "manifest_file": str(manifest_file),
            "proof_file": str(proof_file), "transaction_file": str(transaction_file),
            "attestation_file": str(delivery_attestation_file),
            "integration_evidence_digest": integration_evidence_digest,
            "source_archive": str(source_archive),
            "source_archive_digest": source_archive_digest,
            "source_dir": str(source_directory),
            "target_id": target["id"],
        }
        values.update({f"target_{key}": value for key, value in target.items()})
        planning_env = read_environment(config, "planningEnvironmentAllowlist", repository)

        if transaction_file.exists():
            if transaction_file.is_symlink():
                raise ReleaseError("deployment transaction must not be a symlink")
            transaction = load_json(transaction_file, "deployment transaction")
            expected = {
                "schemaVersion": 4, "releaseId": release_id, "featureId": args.feature,
                "team": args.team, "environment": environment, "commit": commit,
                "target": target, "deploymentConfigDigest": deployment_config_digest,
                "integrationEvidenceDigest": integration_evidence_digest,
                "trustedBaseRef": trusted_base_ref,
                "sourceArchiveDigest": source_archive_digest,
                "targetLeaseKey": lease_key,
            }
            if any(transaction.get(key) != value for key, value in expected.items()):
                raise ReleaseError("deployment transaction is bound to different release inputs")
        else:
            transaction = {
                "schemaVersion": 4, "phase": "new", "releaseId": release_id,
                "featureId": args.feature, "team": args.team, "environment": environment,
                "target": target, "commit": commit,
                "deploymentConfigDigest": deployment_config_digest,
                "integrationEvidenceDigest": integration_evidence_digest,
                "trustedBaseRef": trusted_base_ref,
                "sourceArchiveDigest": source_archive_digest,
                "targetLeaseKey": lease_key,
                "createdAt": now(), "updatedAt": now(),
            }
            atomic_json(transaction_file, transaction)

        product_acceptance_digest = str(transaction.get("productAcceptanceDigest") or "")
        if transaction.get("productAcceptanceConsumedAt"):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", product_acceptance_digest):
                raise ReleaseError("consumed product acceptance has no protected digest")
        else:
            try:
                product_acceptance = evaluate_product_acceptance(
                    snapshot,
                    feature_id=args.feature,
                    commit=commit,
                    integration_evidence_digest=integration_evidence_digest,
                )
            except ProductAcceptancePending as exc:
                request = product_acceptance_request(
                    snapshot,
                    feature_id=args.feature,
                    commit=commit,
                    integration_evidence_digest=integration_evidence_digest,
                    reason=str(exc),
                )
                atomic_json(product_request_file, request)
                transaction.update({
                    "phase": "awaiting-product-approval",
                    "productAcceptanceState": "awaiting",
                    "productAcceptanceReason": str(exc)[:512],
                    "updatedAt": now(),
                })
                atomic_json(transaction_file, transaction)
                project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
                raise AwaitingAuthorization(str(exc)) from exc

            observed_product_digest = product_acceptance.digest
            recorded_product_digest = transaction.get("productAcceptanceDigest")
            if (
                (recorded_product_digest and recorded_product_digest != observed_product_digest)
                or transaction.get("phase") == "awaiting-product-approval"
            ):
                safe_preapply = {
                    "new", "awaiting-product-approval", "awaiting-attestation",
                    "planned", "awaiting-approval",
                }
                if transaction.get("phase") not in safe_preapply or transaction.get("approvalConsumedAt"):
                    raise AwaitingAuthorization(
                        "product approval changed after production apply authority was consumed; manual recovery is required"
                    )
                reset_preapply_transaction_for_product(transaction)
            product_acceptance_digest = observed_product_digest
            transaction.update({
                "productAcceptanceDigest": product_acceptance_digest,
                "productAcceptanceState": "approved",
                "productAcceptanceAnchorTaskId": product_acceptance.anchor_task_id,
                "productAcceptanceFreshness": product_acceptance.freshness,
                "productAcceptanceBodyDigest": product_acceptance.body_digest,
                "updatedAt": now(),
            })
            atomic_json(transaction_file, transaction)

        values["product_acceptance_digest"] = product_acceptance_digest

        delivery_attestation_digest: str | None = None
        if config["mode"] == "automatic":
            recorded_attestation_digest = transaction.get("deliveryAttestationDigest")
            if recorded_attestation_digest:
                attestation = load_json(delivery_attestation_file, "delivery attestation")
                delivery_attestation_digest = canonical_digest(attestation)
                if delivery_attestation_digest != recorded_attestation_digest:
                    raise ReleaseError("delivery attestation changed after being recorded")
                authority_consumed = bool(
                    transaction.get("productAcceptanceConsumedAt")
                    or transaction.get("approvalConsumedAt")
                    or transaction.get("phase") in {
                        "applying", "verifying", "rolling-back", "succeeded",
                        "failed", "denied", "rolled-back", "superseded",
                    }
                )
                try:
                    validate_delivery_attestation(
                        attestation,
                        feature_id=args.feature,
                        team=args.team,
                        commit=commit,
                        source_archive_digest=source_archive_digest,
                        integration_evidence_digest=integration_evidence_digest,
                        product_acceptance_digest=product_acceptance_digest,
                        config=config,
                        require_fresh=not authority_consumed,
                    )
                except AwaitingAuthorization:
                    safe_preapply = {
                        "new", "awaiting-product-approval", "awaiting-attestation",
                        "planned", "awaiting-approval",
                    }
                    if authority_consumed or transaction.get("phase") not in safe_preapply:
                        raise ReleaseError(
                            "delivery attestation expired after production authority was consumed"
                        )
                    reset_preapply_transaction_for_attestation(transaction)
                    transaction["updatedAt"] = now()
                    atomic_json(transaction_file, transaction)
                    recorded_attestation_digest = None
                    delivery_attestation_digest = None
            if not recorded_attestation_digest:
                if transaction.get("phase") not in {"new", "awaiting-attestation"}:
                    raise ReleaseError("automatic release lost its delivery identity/isolation attestation")
                try:
                    attestation = obtain_delivery_attestation(
                        delivery_attestation_file,
                        config,
                        values,
                        repository,
                        planning_env,
                        logs,
                        feature_id=args.feature,
                        team=args.team,
                        commit=commit,
                        source_archive_digest=source_archive_digest,
                        integration_evidence_digest=integration_evidence_digest,
                        product_acceptance_digest=product_acceptance_digest,
                    )
                except AwaitingAuthorization:
                    transaction.update({"phase": "awaiting-attestation", "updatedAt": now()})
                    atomic_json(transaction_file, transaction)
                    project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
                    raise
                delivery_attestation_digest = canonical_digest(attestation)
                transaction.update({
                    "phase": "new",
                    "deliveryAttestationDigest": delivery_attestation_digest,
                    "deliveryAttestationId": attestation["attestationId"],
                    "deliveryAttestationExpiresAt": attestation["expiresAt"],
                    "updatedAt": now(),
                })
                atomic_json(transaction_file, transaction)
            values["delivery_attestation_expires_at"] = str(
                transaction.get("deliveryAttestationExpiresAt") or attestation.get("expiresAt")
            )
        elif transaction.get("deliveryAttestationDigest") is not None:
            raise ReleaseError("approval-required transaction unexpectedly contains an automatic delivery attestation")

        def revalidate_tracker_release_authority(boundary: str) -> None:
            """Rebind production/terminal authority to a fresh exhaustive export."""
            boundary_path = release_dir / ("tracker-authority-%s.json" % boundary)
            subprocess_text(
                [
                    str(skill_path("bin/tracker-ops.sh")),
                    "export",
                    args.feature,
                    str(boundary_path),
                ],
                repository,
                tracker_env,
                "%s tracker authority snapshot" % boundary,
            )
            boundary_snapshot = load_json(
                boundary_path, "%s tracker authority snapshot" % boundary
            )
            boundary_digest = verify_integrations(
                boundary_snapshot,
                workspace,
                repository,
                args.team,
                args.feature,
                tracker_env,
                trusted_base_ref,
                commit,
                trusted_generation_predecessor,
                release_dir / ("integration-evidence-%s.json" % boundary),
            )
            if boundary_digest != integration_evidence_digest:
                raise ReleaseError(
                    "terminal task/integration evidence changed at the %s boundary"
                    % boundary
                )
            try:
                boundary_product = evaluate_product_acceptance(
                    boundary_snapshot,
                    feature_id=args.feature,
                    commit=commit,
                    integration_evidence_digest=integration_evidence_digest,
                )
            except ProductAcceptancePending as exc:
                raise AwaitingAuthorization(
                    "product authority changed at the %s boundary: %s"
                    % (boundary, exc)
                ) from exc
            if boundary_product.digest != product_acceptance_digest:
                raise AwaitingAuthorization(
                    "product authority digest changed at the %s boundary" % boundary
                )

        if transaction.get("phase") == "succeeded":
            revalidate_tracker_release_authority("already-succeeded-close")
            release_target_lease(target_active_file, release_id)
            project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
            finish_feature(
                repository,
                args.feature,
                tracker_env,
                before_transition=lambda: revalidate_tracker_release_authority(
                    "already-succeeded-terminal-write"
                ),
            )
            print(f"release-feature: {release_id} already succeeded")
            return 0
        if transaction.get("phase") == "rolled-back":
            release_target_lease(target_active_file, release_id)
            raise ReleaseError("release transaction is terminal: rolled-back")
        if transaction.get("phase") in {"failed", "denied", "rolled-back", "superseded"}:
            raise ReleaseError(f"release transaction is terminal: {transaction.get('phase')}")

        if transaction.get("phase") == "new":
            run_hook(
                "plan", "deploy.plan", config, values,
                repository=repository, env=planning_env, secrets=[], logs=logs,
            )
            plan = load_json(plan_file, "release plan")
            if (
                plan.get("commit") != commit
                or plan.get("environment") != environment
                or plan.get("target") != target
                or plan.get("sourceArchiveDigest") != source_archive_digest
            ):
                raise ReleaseError(
                    "release plan does not bind the requested commit/source/environment/target"
                )
            plan_digest = canonical_digest(plan)
            values["artifact_digest"] = str(plan.get("artifactDigest") or "")
            manifest = write_manifest(
                manifest_file, args=args, config=config, values=values, target=target,
                plan=plan, plan_digest=plan_digest,
                deployment_config_digest=deployment_config_digest,
                integration_evidence_digest=integration_evidence_digest,
                product_acceptance_digest=product_acceptance_digest,
                delivery_attestation_digest=delivery_attestation_digest,
                source_archive_digest=source_archive_digest,
                repository=repository,
            )
            transaction.update({
                "phase": "planned", "artifactDigest": plan.get("artifactDigest"),
                "planDigest": plan_digest, "manifestDigest": canonical_digest(manifest),
                "manifestNonce": manifest["nonce"], "manifestExpiresAt": manifest["expiresAt"],
                "updatedAt": now(),
            })
            atomic_json(transaction_file, transaction)
        else:
            plan = load_json(plan_file, "release plan")
            manifest = load_json(manifest_file, "approval manifest")
            values["authorization_expires_at"] = str(manifest.get("expiresAt") or "")
            if canonical_digest(plan) != transaction.get("planDigest") or canonical_digest(manifest) != transaction.get("manifestDigest"):
                raise ReleaseError("release plan or manifest changed after being recorded")
            if manifest.get("nonce") != transaction.get("manifestNonce"):
                raise ReleaseError("approval manifest nonce changed after being recorded")
            if manifest.get("productAcceptanceDigest") != product_acceptance_digest:
                raise ReleaseError("approval manifest is not bound to the protected product acceptance")
            if manifest.get("sourceArchiveDigest") != source_archive_digest:
                raise ReleaseError("approval manifest is not bound to the exact source archive")
            values["artifact_digest"] = str(transaction.get("artifactDigest") or "")

        expected_bindings = validate_manifest_bindings(
            manifest, config, values, repository, deployment_config_digest
        )

        approved = False
        authorization_digest = transaction["manifestDigest"]
        if config["mode"] == "approval-required" and not transaction.get("approvalConsumedAt"):
            if datetime.now(timezone.utc) >= parse_time(manifest.get("expiresAt"), "manifest expiresAt"):
                manifest = write_manifest(
                    manifest_file, args=args, config=config, values=values, target=target,
                    plan=plan, plan_digest=transaction["planDigest"],
                    deployment_config_digest=deployment_config_digest,
                    integration_evidence_digest=integration_evidence_digest,
                    product_acceptance_digest=product_acceptance_digest,
                    delivery_attestation_digest=delivery_attestation_digest,
                    source_archive_digest=source_archive_digest,
                    repository=repository,
                )
                transaction.update({
                    "phase": "awaiting-approval", "manifestDigest": canonical_digest(manifest),
                    "manifestNonce": manifest["nonce"], "manifestExpiresAt": manifest["expiresAt"],
                    "updatedAt": now(),
                })
                atomic_json(transaction_file, transaction)
                expected_bindings = validate_manifest_bindings(
                    manifest, config, values, repository, deployment_config_digest
                )
            try:
                proof = verify_approval(
                    manifest, manifest_file, proof_file, config, values,
                    repository, planning_env, logs, expected_bindings,
                )
            except AwaitingAuthorization:
                transaction.update({"phase": "awaiting-approval", "updatedAt": now()})
                atomic_json(transaction_file, transaction)
                project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
                raise
            approved = True
            authorization_digest = canonical_digest(proof)
            transaction.update({
                "phase": "planned", "approvalId": proof["approvalId"],
                "approvalApprover": (proof["approver"].get("id") if isinstance(proof["approver"], dict) else proof["approver"]),
                "approvalProofDigest": authorization_digest,
                "approvalExpiresAt": proof["expiresAt"], "approvalVerifiedAt": now(), "updatedAt": now(),
            })
            atomic_json(transaction_file, transaction)
        elif config["mode"] == "approval-required":
            authorization_digest = str(transaction.get("approvalProofDigest") or "")

        try:
            policy_plan(plan_file, str(config["mode"]), approved or bool(transaction.get("approvalConsumedAt")))
        except AwaitingAuthorization:
            transaction.update({"phase": "awaiting-approval", "updatedAt": now()})
            atomic_json(transaction_file, transaction)
            project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
            raise
        except ReleaseError:
            transaction.update({"phase": "denied", "updatedAt": now(), "failure": "release plan denied by policy"})
            atomic_json(transaction_file, transaction)
            record_release_denial(
                snapshot,
                release_dir,
                repository,
                tracker_env,
                release_id,
                str(transaction.get("planDigest") or "sha256:" + "0" * 64),
            )
            project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
            raise

        release_env, secret_values = read_credentials(config, repository)
        observed = current_release_status(
            config, values, repository, release_env, secret_values, logs, expected_bindings
        )
        if transaction.get("phase") == "rolling-back":
            claim_target_lease(
                target_active_file,
                state_root=state_root,
                transaction_file=transaction_file,
                release_id=release_id,
                feature_id=args.feature,
                environment=environment,
                target=target,
                lease_key=lease_key,
            )
            outcome = reconcile_rolling_back(transaction, observed)
            atomic_json(transaction_file, transaction)
            project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
            if outcome == "rolled-back":
                release_target_lease(target_active_file, release_id, require_owner=True)
                raise ReleaseError("production rollback completed after crash recovery")
            if outcome == "in-progress":
                print("release-feature: rollback is still in progress; next pass will query status")
                return 4
            raise ReleaseError("production rollback outcome is uncertain; manual recovery required")
        if observed["state"] == "failed":
            claim_target_lease(
                target_active_file,
                state_root=state_root,
                transaction_file=transaction_file,
                release_id=release_id,
                feature_id=args.feature,
                environment=environment,
                target=target,
                lease_key=lease_key,
            )
            transaction.update({"phase": "failed", "updatedAt": now(), "failure": "status hook reported failed"})
            atomic_json(transaction_file, transaction)
            project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
            raise ReleaseError("deployment target reports the release failed")
        if observed["state"] == "in-progress":
            if observed.get("artifactDigest") not in {None, transaction["artifactDigest"]}:
                raise ReleaseError("in-progress deployment reports a different artifact digest")
            claim_target_lease(
                target_active_file,
                state_root=state_root,
                transaction_file=transaction_file,
                release_id=release_id,
                feature_id=args.feature,
                environment=environment,
                target=target,
                lease_key=lease_key,
            )
            transaction.update({"phase": "applying", "updatedAt": now()})
            atomic_json(transaction_file, transaction)
            print("release-feature: apply is still in progress; next pass will query status")
            return 4
        if observed["state"] == "applied":
            if observed.get("artifactDigest") != transaction.get("artifactDigest"):
                raise ReleaseError(
                    "applied deployment reports a foreign artifact; target lease was not claimed"
                )
            claim_target_lease(
                target_active_file,
                state_root=state_root,
                transaction_file=transaction_file,
                release_id=release_id,
                feature_id=args.feature,
                environment=environment,
                target=target,
                lease_key=lease_key,
            )
        if observed["state"] == "not-applied":
            if config["mode"] == "approval-required" and transaction.get("approvalConsumedAt"):
                manifest = write_manifest(
                    manifest_file, args=args, config=config, values=values, target=target,
                    plan=plan, plan_digest=transaction["planDigest"],
                    deployment_config_digest=deployment_config_digest,
                    integration_evidence_digest=integration_evidence_digest,
                    product_acceptance_digest=product_acceptance_digest,
                    delivery_attestation_digest=delivery_attestation_digest,
                    source_archive_digest=source_archive_digest,
                    repository=repository,
                )
                for key in (
                    "approvalId", "approvalApprover", "approvalProofDigest", "approvalExpiresAt",
                    "approvalVerifiedAt", "approvalConsumedAt", "productAcceptanceConsumedAt",
                ):
                    transaction.pop(key, None)
                transaction.update({
                    "phase": "awaiting-approval", "manifestDigest": canonical_digest(manifest),
                    "manifestNonce": manifest["nonce"], "manifestExpiresAt": manifest["expiresAt"],
                    "updatedAt": now(),
                })
                atomic_json(transaction_file, transaction)
                project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
                raise AwaitingAuthorization("prior one-use approval was consumed; a fresh exact-manifest approval is required")

            # Planning and external approval can take time. Re-read the tracker
            # immediately before first apply so a concurrent product pushback or
            # edited/reposted verdict cannot race the original snapshot.
            recheck_path = release_dir / "product-acceptance-recheck.json"
            subprocess_text(
                [str(skill_path("bin/tracker-ops.sh")), "export", args.feature, str(recheck_path)],
                repository,
                tracker_env,
                "pre-apply product acceptance snapshot",
            )
            recheck_snapshot = load_json(recheck_path, "pre-apply product acceptance snapshot")
            rechecked_integration_evidence_digest = verify_integrations(
                recheck_snapshot,
                workspace,
                repository,
                args.team,
                args.feature,
                tracker_env,
                trusted_base_ref,
                commit,
                trusted_generation_predecessor,
                release_dir / "integration-evidence-recheck.json",
            )
            if rechecked_integration_evidence_digest != integration_evidence_digest:
                reason = (
                    "the terminal task/review/integration evidence changed before apply; "
                    "a fresh product verdict and release plan are required"
                )
                reset_preapply_transaction_for_evidence(transaction)
                transaction.update({
                    "phase": "awaiting-product-approval",
                    "integrationEvidenceDigest": rechecked_integration_evidence_digest,
                    "productAcceptanceState": "awaiting",
                    "productAcceptanceReason": reason,
                    "updatedAt": now(),
                })
                atomic_json(
                    product_request_file,
                    product_acceptance_request(
                        recheck_snapshot,
                        feature_id=args.feature,
                        commit=commit,
                        integration_evidence_digest=rechecked_integration_evidence_digest,
                        reason=reason,
                    ),
                )
                atomic_json(transaction_file, transaction)
                project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
                raise AwaitingAuthorization(reason)
            try:
                rechecked_product = evaluate_product_acceptance(
                    recheck_snapshot,
                    feature_id=args.feature,
                    commit=commit,
                    integration_evidence_digest=integration_evidence_digest,
                )
            except ProductAcceptancePending as exc:
                atomic_json(
                    product_request_file,
                    product_acceptance_request(
                        recheck_snapshot,
                        feature_id=args.feature,
                        commit=commit,
                        integration_evidence_digest=integration_evidence_digest,
                        reason=str(exc),
                    ),
                )
                transaction.update({
                    "phase": "awaiting-product-approval",
                    "productAcceptanceState": "awaiting",
                    "productAcceptanceReason": str(exc)[:512],
                    "updatedAt": now(),
                })
                atomic_json(transaction_file, transaction)
                project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
                raise AwaitingAuthorization(str(exc)) from exc
            if rechecked_product.digest != product_acceptance_digest:
                reason = "feature product approval changed after the release manifest was created; retry with a fresh manifest"
                atomic_json(
                    product_request_file,
                    product_acceptance_request(
                        recheck_snapshot,
                        feature_id=args.feature,
                        commit=commit,
                        integration_evidence_digest=integration_evidence_digest,
                        reason=reason,
                    ),
                )
                transaction.update({
                    "phase": "awaiting-product-approval",
                    "productAcceptanceState": "awaiting",
                    "productAcceptanceReason": reason,
                    "updatedAt": now(),
                })
                atomic_json(transaction_file, transaction)
                project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
                raise AwaitingAuthorization(reason)

            # Consume only authority that is still fresh at the last possible
            # point before the production lease/state transition and apply.
            # Planning, status, and tracker revalidation can outlive a proof.
            if config["mode"] == "automatic":
                current_attestation = load_json(
                    delivery_attestation_file, "pre-apply delivery attestation"
                )
                if canonical_digest(current_attestation) != transaction.get("deliveryAttestationDigest"):
                    raise ReleaseError(
                        "delivery attestation changed before production authority consumption"
                    )
                try:
                    validate_delivery_attestation(
                        current_attestation,
                        feature_id=args.feature,
                        team=args.team,
                        commit=commit,
                        source_archive_digest=source_archive_digest,
                        integration_evidence_digest=integration_evidence_digest,
                        product_acceptance_digest=product_acceptance_digest,
                        config=config,
                        require_fresh=True,
                    )
                except AwaitingAuthorization:
                    reset_preapply_transaction_for_attestation(transaction)
                    transaction.update({"phase": "awaiting-attestation", "updatedAt": now()})
                    atomic_json(transaction_file, transaction)
                    project_transaction(
                        transaction, release_dir, repository, args.feature, tracker_env
                    )
                    raise
                if datetime.now(timezone.utc) >= parse_time(
                    manifest.get("expiresAt"), "manifest expiresAt"
                ):
                    manifest = write_manifest(
                        manifest_file, args=args, config=config, values=values, target=target,
                        plan=plan, plan_digest=transaction["planDigest"],
                        deployment_config_digest=deployment_config_digest,
                        integration_evidence_digest=integration_evidence_digest,
                        product_acceptance_digest=product_acceptance_digest,
                        delivery_attestation_digest=delivery_attestation_digest,
                        source_archive_digest=source_archive_digest,
                        repository=repository,
                    )
                    transaction.update({
                        "manifestDigest": canonical_digest(manifest),
                        "manifestNonce": manifest["nonce"],
                        "manifestExpiresAt": manifest["expiresAt"],
                        "updatedAt": now(),
                    })
                    atomic_json(transaction_file, transaction)
                    expected_bindings = validate_manifest_bindings(
                        manifest, config, values, repository, deployment_config_digest
                    )
                    authorization_digest = transaction["manifestDigest"]
            else:
                current_proof = load_json(proof_file, "pre-apply approval proof")
                if canonical_digest(current_proof) != transaction.get("approvalProofDigest"):
                    raise ReleaseError(
                        "approval proof changed before production authority consumption"
                    )
                try:
                    validate_approval_proof(current_proof, manifest, require_fresh=True)
                except AwaitingAuthorization:
                    manifest = write_manifest(
                        manifest_file, args=args, config=config, values=values, target=target,
                        plan=plan, plan_digest=transaction["planDigest"],
                        deployment_config_digest=deployment_config_digest,
                        integration_evidence_digest=integration_evidence_digest,
                        product_acceptance_digest=product_acceptance_digest,
                        delivery_attestation_digest=delivery_attestation_digest,
                        source_archive_digest=source_archive_digest,
                        repository=repository,
                    )
                    for key in (
                        "approvalId", "approvalApprover", "approvalProofDigest",
                        "approvalExpiresAt", "approvalVerifiedAt", "approvalConsumedAt",
                    ):
                        transaction.pop(key, None)
                    transaction.update({
                        "phase": "awaiting-approval",
                        "manifestDigest": canonical_digest(manifest),
                        "manifestNonce": manifest["nonce"],
                        "manifestExpiresAt": manifest["expiresAt"],
                        "updatedAt": now(),
                    })
                    atomic_json(transaction_file, transaction)
                    project_transaction(
                        transaction, release_dir, repository, args.feature, tracker_env
                    )
                    raise AwaitingAuthorization(
                        "approval expired during pre-apply revalidation; "
                        "a fresh exact-manifest approval is required"
                    )
            def revalidate_apply_authority() -> None:
                revalidate_tracker_release_authority("apply-process")
                revalidate_bound_repository_identity(repository)
                boundary_head = git_text(
                    repository,
                    "apply-boundary feature head lookup",
                    "rev-parse", "--verify", f"{args.team}^{{commit}}",
                )
                if boundary_head != commit:
                    raise ReleaseError(
                        "feature HEAD changed at the apply process boundary"
                    )
                if config["mode"] == "automatic":
                    boundary_attestation = load_json(
                        delivery_attestation_file,
                        "apply-boundary delivery attestation",
                    )
                    if canonical_digest(boundary_attestation) != transaction.get(
                        "deliveryAttestationDigest"
                    ):
                        raise ReleaseError(
                            "delivery attestation changed at the apply process boundary"
                        )
                    validate_delivery_attestation(
                        boundary_attestation,
                        feature_id=args.feature,
                        team=args.team,
                        commit=commit,
                        source_archive_digest=source_archive_digest,
                        integration_evidence_digest=integration_evidence_digest,
                        product_acceptance_digest=product_acceptance_digest,
                        config=config,
                        require_fresh=True,
                    )
                else:
                    boundary_proof = load_json(
                        proof_file,
                        "apply-boundary approval proof",
                    )
                    if canonical_digest(boundary_proof) != transaction.get(
                        "approvalProofDigest"
                    ):
                        raise ReleaseError(
                            "approval proof changed at the apply process boundary"
                        )
                    validate_approval_proof(
                        boundary_proof,
                        manifest,
                        require_fresh=True,
                    )

            def consume_apply_authority() -> None:
                # This callback runs inside run_hook after executable binding and
                # policy validation, directly before Popen. Validate once before
                # consuming state, persist the crash-recovery marker, then check
                # freshness again so a proof cannot expire during those writes.
                revalidate_apply_authority()
                claim_target_lease(
                    target_active_file,
                    state_root=state_root,
                    transaction_file=transaction_file,
                    release_id=release_id,
                    feature_id=args.feature,
                    environment=environment,
                    target=target,
                    lease_key=lease_key,
                )
                transaction.update({
                    "phase": "applying",
                    "previousArtifactDigest": observed.get("currentArtifactDigest"),
                    "productAcceptanceConsumedAt": (
                        transaction.get("productAcceptanceConsumedAt") or now()
                    ),
                    "updatedAt": now(),
                })
                if config["mode"] == "approval-required":
                    transaction["approvalConsumedAt"] = now()
                atomic_json(transaction_file, transaction)
                try:
                    revalidate_apply_authority()
                except AwaitingAuthorization:
                    release_target_lease(
                        target_active_file,
                        release_id,
                        require_owner=True,
                    )
                    transaction.pop("productAcceptanceConsumedAt", None)
                    if config["mode"] == "automatic":
                        reset_preapply_transaction_for_attestation(transaction)
                        transaction["phase"] = "awaiting-attestation"
                    else:
                        for key in (
                            "approvalId", "approvalApprover", "approvalProofDigest",
                            "approvalExpiresAt", "approvalVerifiedAt", "approvalConsumedAt",
                        ):
                            transaction.pop(key, None)
                        transaction["phase"] = "awaiting-approval"
                    transaction["updatedAt"] = now()
                    atomic_json(transaction_file, transaction)
                    project_transaction(
                        transaction,
                        release_dir,
                        repository,
                        args.feature,
                        tracker_env,
                    )
                    raise

            run_hook(
                "apply", "deploy.apply", config, values,
                repository=repository, env=release_env, secrets=secret_values, logs=logs,
                authorization_digest=authorization_digest,
                expected_binding=expected_bindings.get("apply"),
                before_spawn=consume_apply_authority,
            )
            observed = current_release_status(
                config, values, repository, release_env, secret_values, logs, expected_bindings
            )
            if observed["state"] == "in-progress":
                print("release-feature: apply accepted and is in progress")
                return 4
            if observed["state"] != "applied":
                raise ReleaseError(f"apply returned but status is {observed['state']}; refusing to report success")
        if observed.get("artifactDigest") != transaction.get("artifactDigest"):
            raise ReleaseError("deployed artifact digest does not match the release plan")

        revalidate_tracker_release_authority("pre-verify")
        transaction.update({"phase": "verifying", "updatedAt": now()})
        atomic_json(transaction_file, transaction)
        verification_result = run_hook(
            "verify", "deploy.verify", config, values,
            repository=repository, env=release_env, secrets=secret_values, logs=logs, check=False,
            expected_binding=expected_bindings.get("verify"),
        )
        try:
            verification = strict_json(verification_result.stdout)
        except ValueError as exc:
            raise ReleaseError("verify hook must print one JSON attestation") from exc
        verified = (
            verification_result.returncode == 0
            and isinstance(verification, dict)
            and verification.get("healthy") is True
            and verification.get("artifactDigest") == transaction.get("artifactDigest")
            and verification.get("releaseId") in {None, release_id}
        )
        if not verified:
            rollback = plan.get("rollback") or {}
            hook = (config.get("hooks") or {}).get("rollback")
            previous = transaction.get("previousArtifactDigest")
            safe = bool(
                hook and rollback.get("automaticSafe") is True
                and re.fullmatch(r"sha256:[0-9a-f]{64}", str(previous or ""))
                and rollback.get("previousArtifactDigest") == previous
            )
            if safe:
                transaction.update({"phase": "rolling-back", "updatedAt": now(), "failure": "verification failed"})
                atomic_json(transaction_file, transaction)
                rollback_authorization = canonical_digest({
                    "releaseId": release_id, "planDigest": transaction["planDigest"],
                    "previousArtifactDigest": previous,
                })
                run_hook(
                    "rollback", "deploy.rollback", config, values,
                    repository=repository, env=release_env, secrets=secret_values, logs=logs,
                    authorization_digest=rollback_authorization,
                    expected_binding=expected_bindings.get("rollback"),
                )
                rolled_back = current_release_status(
                    config, values, repository, release_env, secret_values, logs, expected_bindings
                )
                if rolled_back.get("state") == "applied" and rolled_back.get("artifactDigest") == previous:
                    transaction.update({"phase": "rolled-back", "rollbackVerifiedAt": now(), "updatedAt": now()})
                else:
                    transaction.update({"phase": "failed", "updatedAt": now(), "failure": "rollback could not be verified"})
            else:
                transaction.update({"phase": "failed", "updatedAt": now(), "failure": "verification failed; no verified safe rollback"})
            atomic_json(transaction_file, transaction)
            project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
            if transaction.get("phase") == "rolled-back":
                release_target_lease(target_active_file, release_id, require_owner=True)
            raise ReleaseError("production verification failed")

        revalidate_tracker_release_authority("post-verify-success")
        transaction.update({
            "phase": "succeeded", "verifiedAt": now(), "updatedAt": now(),
            "verificationDigest": canonical_digest(verification),
        })
        atomic_json(transaction_file, transaction)
        release_target_lease(target_active_file, release_id, require_owner=True)
        project_transaction(transaction, release_dir, repository, args.feature, tracker_env)
        finish_feature(
            repository,
            args.feature,
            tracker_env,
            before_transition=lambda: revalidate_tracker_release_authority(
                "terminal-feature-write"
            ),
        )
        print(f"release-feature: {release_id} succeeded at {commit}")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--team", required=True)
    parser.add_argument("--feature", required=True)
    parser.add_argument("--config", type=Path, default=SKILL_DIR / "config" / "deployment.config.json")
    parser.add_argument("--expected-git-dir", type=Path)
    parser.add_argument("--expected-git-dir-id")
    parser.add_argument("--expected-git-common-dir", type=Path)
    parser.add_argument("--expected-git-common-dir-id")
    args = parser.parse_args()
    return execute(args)


if __name__ == "__main__":
    install_release_signal_handlers()
    try:
        raise SystemExit(main())
    except ReleaseInterrupted as exc:
        print(f"release-feature: interrupted: {exc}", file=sys.stderr)
        raise SystemExit(143)
    except AwaitingAuthorization as exc:
        print(f"release-feature: awaiting authorization: {exc}", file=sys.stderr)
        raise SystemExit(4)
    except ReleaseError as exc:
        print(f"release-feature: {exc}", file=sys.stderr)
        raise SystemExit(1)
