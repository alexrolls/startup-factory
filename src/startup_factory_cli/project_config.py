"""Safe, byte-preserving edits for Startup Factory project configuration."""

from __future__ import annotations

import dataclasses
import ctypes
import errno
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Mapping

from .installer import InstallerError


PROJECT_CONFIG_RELATIVE_PATH = Path("config/project-management.config.md")
MAX_PROJECT_CONFIG_BYTES = 1024 * 1024
EDITABLE_KEYS = ("PRODUCT_MANAGEMENT_TOOL", "TEAM_MODE")
_ASSIGNMENT = re.compile(
    r"(?m)^(?P<key>PRODUCT_MANAGEMENT_TOOL|TEAM_MODE)=(?P<value>[^\t #\r\n]+)"
)
_TOOL = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_STAT_SUPPORTS_DIR_FD = os.stat in os.supports_dir_fd
_STAT_SUPPORTS_NOFOLLOW = os.stat in os.supports_follow_symlinks
_RENAME_EXCHANGE = 0x00000002


@dataclasses.dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclasses.dataclass(frozen=True)
class _DirectoryIdentity:
    device: int
    inode: int


@dataclasses.dataclass(frozen=True)
class Assignment:
    key: str
    value: str
    value_start: int
    value_end: int


@dataclasses.dataclass(frozen=True)
class ProjectConfig:
    path: Path
    raw: bytes
    text: str
    file_mode: int
    identity: _FileIdentity
    parent_identity: _DirectoryIdentity
    assignments: Mapping[str, Assignment]

    def value(self, key: str) -> str:
        try:
            return self.assignments[key].value
        except KeyError as exc:  # pragma: no cover - parser guarantees both keys.
            raise InstallerError(f"project configuration is missing exact key: {key}") from exc


@dataclasses.dataclass(frozen=True)
class ConfigChange:
    key: str
    before: str
    after: str

    def as_dict(self) -> dict[str, str]:
        return {"key": self.key, "before": self.before, "after": self.after}


def _identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    return _DirectoryIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _open_parent_directory(path: Path) -> tuple[int, Path, os.stat_result]:
    """Open every parent component without following links and return the held FD."""

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory or not _OPEN_SUPPORTS_DIR_FD:
        raise InstallerError(
            "project configuration requires secure dirfd and no-follow file opens"
        )

    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name or absolute.name in {".", ".."}:
        raise InstallerError("project configuration path must name a file")

    flags = os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(absolute.anchor, flags)
        parent_parts = absolute.parent.parts[1:]
        for component in parent_parts:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):  # pragma: no cover - O_DIRECTORY enforces this.
            raise InstallerError("project configuration parent is not a directory")
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise InstallerError(
            f"cannot securely open project configuration directory: {absolute.parent}: {exc}"
        ) from exc
    except InstallerError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    return descriptor, absolute, metadata


def _open_relative_parent_directory(
    root_descriptor: int, relative_path: Path
) -> tuple[int, Path, os.stat_result]:
    """Walk a relative config path beneath an already verified project FD."""

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory or not _OPEN_SUPPORTS_DIR_FD:
        raise InstallerError(
            "project configuration requires secure dirfd and no-follow file opens"
        )
    relative = Path(relative_path)
    parts = relative.parts
    if (
        relative.is_absolute()
        or not parts
        or any(component in {"", ".", ".."} for component in parts)
    ):
        raise InstallerError("project configuration path must be a safe relative file path")

    flags = os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.dup(root_descriptor)
        root_metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise InstallerError("verified project descriptor is not a directory")
        for component in parts[:-1]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):  # pragma: no cover - traversal enforces this.
            raise InstallerError("project configuration parent is not a directory")
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise InstallerError(
            f"cannot securely open project configuration directory: {relative.parent}: {exc}"
        ) from exc
    except InstallerError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    return descriptor, relative, metadata


def _read_regular_file_at(
    parent_descriptor: int, name: str, display_path: Path
) -> tuple[bytes, os.stat_result]:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    non_blocking = getattr(os, "O_NONBLOCK", 0)
    if not no_follow or not non_blocking:
        raise InstallerError(
            "project configuration requires secure no-follow, non-blocking file opens"
        )
    if not _STAT_SUPPORTS_DIR_FD or not _STAT_SUPPORTS_NOFOLLOW:
        raise InstallerError(
            "project configuration requires secure named no-follow metadata checks"
        )
    flags = os.O_RDONLY | no_follow | non_blocking | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise InstallerError(f"cannot open project configuration: {display_path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallerError("project configuration is not a regular file")
        if metadata.st_size > MAX_PROJECT_CONFIG_BYTES:
            raise InstallerError(
                f"project configuration exceeds {MAX_PROJECT_CONFIG_BYTES}-byte limit"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_PROJECT_CONFIG_BYTES + 1)
        if len(raw) > MAX_PROJECT_CONFIG_BYTES:
            raise InstallerError(
                f"project configuration exceeds {MAX_PROJECT_CONFIG_BYTES}-byte limit"
            )
        post_read_metadata = os.fstat(descriptor)
        try:
            named_metadata = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise InstallerError(
                "project configuration changed while it was being read"
            ) from exc
        expected_identity = _identity(metadata)
        if (
            _identity(post_read_metadata) != expected_identity
            or _identity(named_metadata) != expected_identity
        ):
            raise InstallerError(
                "project configuration changed while it was being read"
            )
        metadata = post_read_metadata
    except OSError as exc:
        raise InstallerError(
            f"cannot read project configuration: {display_path}: {exc}"
        ) from exc
    finally:
        os.close(descriptor)
    return raw, metadata


def _read_regular_file(
    path: Path,
) -> tuple[bytes, os.stat_result, _DirectoryIdentity, Path]:
    parent_descriptor, absolute, parent_metadata = _open_parent_directory(path)
    try:
        raw, metadata = _read_regular_file_at(
            parent_descriptor, absolute.name, absolute
        )
    finally:
        os.close(parent_descriptor)
    return raw, metadata, _directory_identity(parent_metadata), absolute


def _project_config(
    path: Path,
    raw: bytes,
    metadata: os.stat_result,
    parent_identity: _DirectoryIdentity,
) -> ProjectConfig:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallerError("project configuration is not valid UTF-8") from exc

    found = _parse_assignments(text)
    return ProjectConfig(
        path=path,
        raw=raw,
        text=text,
        file_mode=stat.S_IMODE(metadata.st_mode),
        identity=_identity(metadata),
        parent_identity=parent_identity,
        assignments=found,
    )


def _validate_values(assignments: Mapping[str, Assignment]) -> None:
    team_mode = assignments["TEAM_MODE"].value
    if team_mode not in {"true", "false"}:
        raise InstallerError("TEAM_MODE must be exactly true or false")
    tool = assignments["PRODUCT_MANAGEMENT_TOOL"].value
    if _TOOL.fullmatch(tool) is None:
        raise InstallerError(
            "PRODUCT_MANAGEMENT_TOOL must be an adapter name without path separators"
        )


def _parse_assignments(text: str) -> dict[str, Assignment]:
    found: dict[str, Assignment] = {}
    for match in _ASSIGNMENT.finditer(text):
        key = match.group("key")
        if key in found:
            raise InstallerError(f"project configuration contains duplicate exact key: {key}")
        found[key] = Assignment(
            key=key,
            value=match.group("value"),
            value_start=match.start("value"),
            value_end=match.end("value"),
        )
    for key in EDITABLE_KEYS:
        if key not in found:
            raise InstallerError(f"project configuration is missing exact key: {key}")
    _validate_values(found)
    return found


def read_project_config(path: Path) -> ProjectConfig:
    """Read the two editable assignments without accepting aliases or duplicates."""

    raw, metadata, parent_identity, absolute = _read_regular_file(path)
    return _project_config(absolute, raw, metadata, parent_identity)


def read_project_config_at(
    root_descriptor: int,
    relative_path: Path = PROJECT_CONFIG_RELATIVE_PATH,
) -> ProjectConfig:
    """Read config beneath a caller-held, already verified project root FD."""

    parent_descriptor, relative, parent_metadata = _open_relative_parent_directory(
        root_descriptor, relative_path
    )
    try:
        raw, metadata = _read_regular_file_at(
            parent_descriptor, relative.name, relative
        )
    finally:
        os.close(parent_descriptor)
    return _project_config(
        relative,
        raw,
        metadata,
        _directory_identity(parent_metadata),
    )


def plan_changes(config: ProjectConfig, updates: Mapping[str, str]) -> tuple[ConfigChange, ...]:
    unexpected = sorted(set(updates) - set(EDITABLE_KEYS))
    if unexpected:
        raise InstallerError(f"project configuration key is not editable: {unexpected[0]}")
    proposed = dict(config.assignments)
    for key, value in updates.items():
        current = config.assignments[key]
        proposed[key] = dataclasses.replace(current, value=value)
    _validate_values(proposed)
    return tuple(
        ConfigChange(key=key, before=config.value(key), after=updates[key])
        for key in EDITABLE_KEYS
        if key in updates and config.value(key) != updates[key]
    )


def render_changes(config: ProjectConfig, changes: tuple[ConfigChange, ...]) -> bytes:
    text = config.text
    for change in sorted(
        changes,
        key=lambda item: config.assignments[item.key].value_start,
        reverse=True,
    ):
        assignment = config.assignments[change.key]
        text = text[: assignment.value_start] + change.after + text[assignment.value_end :]
    return text.encode("utf-8")


def _create_temporary_file(parent_descriptor: int, target_name: str) -> tuple[int, str]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for _ in range(128):
        name = f".{target_name}.{secrets.token_hex(16)}.tmp"
        try:
            return os.open(name, flags, 0o600, dir_fd=parent_descriptor), name
        except FileExistsError:
            continue
    raise InstallerError("cannot allocate a unique project configuration temporary file")


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:  # pragma: no cover - defensive guard around the OS contract.
            raise OSError("short write while updating project configuration")
        remaining = remaining[written:]


def _atomic_exchange_at(
    parent_descriptor: int, first_name: str, second_name: str
) -> None:
    """Atomically exchange two names using the supported platform primitive."""

    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        symbol = "renameatx_np"
    elif sys.platform.startswith("linux"):
        symbol = "renameat2"
    else:
        raise InstallerError(
            "atomic project configuration exchange is unsupported on this platform"
        )
    function = getattr(library, symbol, None)
    if function is None:
        raise InstallerError(
            f"atomic project configuration exchange primitive {symbol} is unavailable"
        )
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(
        parent_descriptor,
        os.fsencode(first_name),
        parent_descriptor,
        os.fsencode(second_name),
        _RENAME_EXCHANGE,
    )
    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(
            error_number,
            f"atomic project configuration exchange failed: {os.strerror(error_number)}",
        )


def _exchange_snapshot_matches(
    raw: bytes,
    metadata: os.stat_result,
    expected_raw: bytes,
    expected_identity: _FileIdentity,
) -> bool:
    # Both supported exchange primitives update ctime as a consequence of the
    # rename. The remaining identity fields plus exact bytes identify the inode
    # that crossed the atomic boundary without mistaking that expected ctime
    # transition for a concurrent edit.
    return raw == expected_raw and (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    ) == (
        expected_identity.device,
        expected_identity.inode,
        expected_identity.mode,
        expected_identity.size,
        expected_identity.modified_ns,
    )


def _recovery_location(display_path: Path, temporary_name: str) -> str:
    return os.fspath(display_path.with_name(temporary_name))


def _validated_replacement(
    config: ProjectConfig, changes: tuple[ConfigChange, ...]
) -> bytes:
    replacement = render_changes(config, changes)
    try:
        replacement_text = replacement.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - render starts from valid UTF-8.
        raise InstallerError("replacement project configuration is not valid UTF-8") from exc
    _parse_assignments(replacement_text)
    return replacement


def _apply_changes_in_directory(
    config: ProjectConfig,
    replacement: bytes,
    parent_descriptor: int,
    target_name: str,
    display_path: Path,
    parent_metadata: os.stat_result,
) -> None:
    if _directory_identity(parent_metadata) != config.parent_identity:
        raise InstallerError(
            "project configuration directory changed while init was preparing its update"
        )

    temporary_name: str | None = None
    preserve_temporary = False
    try:
        descriptor, temporary_name = _create_temporary_file(
            parent_descriptor, target_name
        )
        try:
            os.fchmod(descriptor, config.file_mode)
            _write_all(descriptor, replacement)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        prepared_raw, prepared_metadata = _read_regular_file_at(
            parent_descriptor,
            temporary_name,
            display_path.with_name(temporary_name),
        )
        prepared_identity = _identity(prepared_metadata)
        if prepared_raw != replacement:
            raise InstallerError(
                "prepared project configuration changed before atomic exchange"
            )

        current_raw, current_metadata = _read_regular_file_at(
            parent_descriptor, target_name, display_path
        )
        if _identity(current_metadata) != config.identity or current_raw != config.raw:
            raise InstallerError("project configuration changed while init was preparing its update")

        _atomic_exchange_at(parent_descriptor, temporary_name, target_name)
        # From this point onward the temporary name contains the exact inode
        # displaced at the atomic boundary. Never remove it until both sides
        # have been identified, or recoverable bytes could be lost.
        preserve_temporary = True
        recovery = _recovery_location(display_path, temporary_name)

        try:
            displaced_raw, displaced_metadata = _read_regular_file_at(
                parent_descriptor,
                temporary_name,
                display_path.with_name(temporary_name),
            )
            installed_raw, installed_metadata = _read_regular_file_at(
                parent_descriptor, target_name, display_path
            )
        except InstallerError as exc:
            os.fsync(parent_descriptor)
            raise InstallerError(
                "project configuration exchange is ambiguous; "
                f"recoverable displaced bytes retained at {recovery}"
            ) from exc

        displaced_matches = _exchange_snapshot_matches(
            displaced_raw,
            displaced_metadata,
            config.raw,
            config.identity,
        )
        installed_matches = _exchange_snapshot_matches(
            installed_raw,
            installed_metadata,
            prepared_raw,
            prepared_identity,
        )

        if displaced_matches and installed_matches:
            os.fsync(parent_descriptor)
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            temporary_name = None
            preserve_temporary = False
            os.fsync(parent_descriptor)
            return

        if displaced_matches:
            # A writer changed the replacement after the exchange. Leave that
            # writer's bytes at the canonical path and retain the displaced
            # original for recovery instead of overwriting either side.
            os.fsync(parent_descriptor)
            raise InstallerError(
                "project configuration changed after atomic exchange; "
                f"recoverable original bytes retained at {recovery}"
            )

        if not installed_matches:
            os.fsync(parent_descriptor)
            raise InstallerError(
                "project configuration and replacement both changed at atomic exchange; "
                f"recoverable displaced bytes retained at {recovery}"
            )

        displaced_identity = _identity(displaced_metadata)
        try:
            _atomic_exchange_at(parent_descriptor, target_name, temporary_name)
        except (InstallerError, OSError) as exc:
            os.fsync(parent_descriptor)
            raise InstallerError(
                "project configuration changed at atomic exchange and rollback failed; "
                f"recoverable displaced bytes retained at {recovery}"
            ) from exc

        try:
            restored_raw, restored_metadata = _read_regular_file_at(
                parent_descriptor, target_name, display_path
            )
            rollback_raw, rollback_metadata = _read_regular_file_at(
                parent_descriptor,
                temporary_name,
                display_path.with_name(temporary_name),
            )
        except InstallerError as exc:
            os.fsync(parent_descriptor)
            raise InstallerError(
                "project configuration rollback is ambiguous; "
                f"recoverable bytes retained at {recovery}"
            ) from exc

        restored_matches = _exchange_snapshot_matches(
            restored_raw,
            restored_metadata,
            displaced_raw,
            displaced_identity,
        )
        rollback_replacement_matches = _exchange_snapshot_matches(
            rollback_raw,
            rollback_metadata,
            prepared_raw,
            prepared_identity,
        )
        os.fsync(parent_descriptor)
        if not restored_matches or not rollback_replacement_matches:
            raise InstallerError(
                "project configuration rollback encountered another concurrent change; "
                f"recoverable bytes retained at {recovery}"
            )

        os.unlink(temporary_name, dir_fd=parent_descriptor)
        temporary_name = None
        preserve_temporary = False
        os.fsync(parent_descriptor)
        raise InstallerError(
            "project configuration changed at the atomic exchange boundary; "
            "the late change was restored"
        )
    except InstallerError:
        raise
    except OSError as exc:
        recovery = (
            "; recoverable bytes retained at "
            + _recovery_location(display_path, temporary_name)
            if preserve_temporary and temporary_name is not None
            else ""
        )
        raise InstallerError(
            f"cannot atomically update project configuration: {exc}{recovery}"
        ) from exc
    finally:
        if temporary_name is not None and not preserve_temporary:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass


def apply_changes(config: ProjectConfig, changes: tuple[ConfigChange, ...]) -> None:
    """Atomically replace one config after detecting concurrent modification."""

    if not changes:
        return
    replacement = _validated_replacement(config, changes)
    parent_descriptor: int | None = None
    try:
        parent_descriptor, absolute, parent_metadata = _open_parent_directory(config.path)
        if absolute != config.path:
            raise InstallerError(
                "project configuration path changed while init was preparing its update"
            )
        _apply_changes_in_directory(
            config,
            replacement,
            parent_descriptor,
            absolute.name,
            absolute,
            parent_metadata,
        )
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def apply_changes_at(
    config: ProjectConfig,
    changes: tuple[ConfigChange, ...],
    root_descriptor: int,
    relative_path: Path = PROJECT_CONFIG_RELATIVE_PATH,
    *,
    display_root: Path | None = None,
) -> None:
    """Apply config changes beneath a caller-held, verified project root FD."""

    if not changes:
        return
    replacement = _validated_replacement(config, changes)
    parent_descriptor: int | None = None
    try:
        parent_descriptor, relative, parent_metadata = _open_relative_parent_directory(
            root_descriptor, relative_path
        )
        if relative != config.path:
            raise InstallerError(
                "project configuration path changed while init was preparing its update"
            )
        display_path = relative if display_root is None else Path(display_root) / relative
        _apply_changes_in_directory(
            config,
            replacement,
            parent_descriptor,
            relative.name,
            display_path,
            parent_metadata,
        )
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
