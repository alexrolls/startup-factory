"""Safe, byte-preserving edits for Startup Factory project configuration."""

from __future__ import annotations

import dataclasses
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Mapping

from .installer import InstallerError


PROJECT_CONFIG_RELATIVE_PATH = Path("config/project-management.config.md")
EDITABLE_KEYS = ("PRODUCT_MANAGEMENT_TOOL", "TEAM_MODE")
_ASSIGNMENT = re.compile(
    r"(?m)^(?P<key>PRODUCT_MANAGEMENT_TOOL|TEAM_MODE)=(?P<value>[^\t #\r\n]+)"
)
_TOOL = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")


@dataclasses.dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int


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
    )


def _read_regular_file(path: Path) -> tuple[bytes, os.stat_result]:
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise InstallerError("project configuration parent is not a regular directory")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not no_follow:
        raise InstallerError("project configuration requires secure no-follow file opens")
    try:
        descriptor = os.open(path, os.O_RDONLY | no_follow)
    except OSError as exc:
        raise InstallerError(f"cannot open project configuration: {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallerError("project configuration is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read()
    except OSError as exc:
        raise InstallerError(f"cannot read project configuration: {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    return raw, metadata


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

    raw, metadata = _read_regular_file(path)
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
        assignments=found,
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


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InstallerError(f"cannot open project configuration directory: {exc}") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise InstallerError(f"cannot sync project configuration directory: {exc}") from exc
    finally:
        os.close(descriptor)


def apply_changes(config: ProjectConfig, changes: tuple[ConfigChange, ...]) -> None:
    """Atomically replace one config after detecting concurrent modification."""

    if not changes:
        return
    replacement = render_changes(config, changes)
    try:
        replacement_text = replacement.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - render starts from valid UTF-8.
        raise InstallerError("replacement project configuration is not valid UTF-8") from exc
    _parse_assignments(replacement_text)
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{config.path.name}.", suffix=".tmp", dir=config.path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, config.file_mode)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(replacement)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)

        current_raw, current_metadata = _read_regular_file(config.path)
        if _identity(current_metadata) != config.identity or current_raw != config.raw:
            raise InstallerError("project configuration changed while init was preparing its update")
        os.replace(temporary, config.path)
        temporary = None
        _fsync_directory(config.path.parent)
    except InstallerError:
        raise
    except OSError as exc:
        raise InstallerError(f"cannot atomically update project configuration: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
