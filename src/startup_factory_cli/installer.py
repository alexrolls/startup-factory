"""Validated, transactional installation of the Startup Factory bundle.

This module intentionally uses only the Python standard library.  The package
manager supplies an isolated Python process; project configuration and custom
extensions remain in the target repository.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import errno
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from . import __version__

try:  # Startup Factory's operational runtime is POSIX-only.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX hosts.
    fcntl = None  # type: ignore[assignment]


BUNDLE_PREFIX = "startup-factory/"
BUNDLE_MANIFEST = ".startup-factory-bundle.json"
OWNERSHIP_MANIFEST = ".startup-factory-owned-files"
INSTALL_PROVENANCE = ".startup-factory-install.json"
SKILL_NAME = "startup-factory"
SCHEMA_VERSION = 1
POLICY_VERSION = 1
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILES = 20_000

PRESERVED_CONFIG_FILES = (
    "config/project-management.config.md",
    "config/planning.config.md",
    "config/team.config.md",
    "config/statuses.config.json",
    "config/automation.config.json",
    "config/deployment.config.json",
    "config/guardrails.config.json",
)
EXTENSION_ROOTS = ("adapters", "extensions", "teams")

_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_MODE = re.compile(r"0[0-7]{3}\Z")


class InstallerError(RuntimeError):
    """A safe, user-facing installer failure."""


@dataclasses.dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    mode: int
    mode_text: str
    sha256: str


@dataclasses.dataclass(frozen=True)
class BundleManifest:
    version: str
    source_repository: str
    source_commit: str
    required_paths: tuple[str, ...]
    files: tuple[FileRecord, ...]
    raw: dict[str, Any]

    @property
    def file_map(self) -> dict[str, FileRecord]:
        return {record.path: record for record in self.files}


@dataclasses.dataclass(frozen=True)
class ValidatedBundle:
    archive_path: Path
    archive_sha256: str
    manifest: BundleManifest
    manifest_bytes: bytes
    payload: dict[str, bytes]


@dataclasses.dataclass(frozen=True)
class SyncPlan:
    target: Path
    command: str
    writes: tuple[str, ...]
    deletes: tuple[str, ...]
    preserved_configs: tuple[str, ...]
    preserved_extensions: tuple[str, ...]
    adopted_extensions: tuple[str, ...]
    had_target: bool
    repair: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "writes": list(self.writes),
            "deletes": list(self.deletes),
            "preservedConfigs": list(self.preserved_configs),
            "preservedExtensions": list(self.preserved_extensions),
            "adoptedExtensions": list(self.adopted_extensions),
            "repair": self.repair,
        }


@dataclasses.dataclass(frozen=True)
class OperationResult:
    action: str
    target: Path
    version: str
    source_repository: str
    source_commit: str
    archive_sha256: str
    dry_run: bool
    plan: SyncPlan | None = None
    verified_files: int = 0
    preserved_configs: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": True,
            "action": self.action,
            "target": str(self.target),
            "version": self.version,
            "sourceRepository": self.source_repository,
            "sourceCommit": self.source_commit,
            "archiveSha256": self.archive_sha256,
            "dryRun": self.dry_run,
        }
        if self.plan is not None:
            result["changes"] = self.plan.as_dict()
        if self.action == "verify":
            result["verifiedFiles"] = self.verified_files
            result["preservedConfigs"] = list(self.preserved_configs)
        return result


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InstallerError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _expect_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise InstallerError(f"{label} has invalid fields ({'; '.join(details)})")


def _safe_relative_path(value: Any, label: str, *, directory: bool = False) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise InstallerError(f"{label} must be a non-empty relative path")
    if "\\" in value:
        raise InstallerError(f"{label} must use POSIX separators")
    trailing = value.endswith("/")
    if trailing and not directory:
        raise InstallerError(f"{label} must name a file")
    candidate = value[:-1] if trailing else value
    pure = PurePosixPath(candidate)
    if pure.is_absolute() or candidate in {"", ".", ".."}:
        raise InstallerError(f"{label} is not a safe relative path: {value}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise InstallerError(f"{label} is not a safe relative path: {value}")
    normalized = pure.as_posix()
    if normalized != candidate:
        raise InstallerError(f"{label} is not normalized: {value}")
    return normalized + ("/" if trailing else "")


def _string(value: Any, label: str, *, max_length: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise InstallerError(f"{label} must be a non-empty string")
    if any(ord(character) < 32 for character in value):
        raise InstallerError(f"{label} contains control characters")
    return value


def parse_manifest(data: bytes) -> BundleManifest:
    if len(data) > MAX_MANIFEST_BYTES:
        raise InstallerError("bundle manifest is too large")
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallerError("bundle manifest is not valid UTF-8") from exc
    try:
        raw = json.loads(decoded, object_pairs_hook=_strict_object)
    except InstallerError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise InstallerError("bundle manifest is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise InstallerError("bundle manifest must be a JSON object")
    _expect_exact_keys(
        raw,
        {
            "schemaVersion",
            "name",
            "version",
            "sourceRepository",
            "sourceCommit",
            "preservationPolicy",
            "requiredPaths",
            "files",
        },
        "bundle manifest",
    )
    if raw["schemaVersion"] != SCHEMA_VERSION or isinstance(raw["schemaVersion"], bool):
        raise InstallerError(f"unsupported bundle manifest schema: {raw['schemaVersion']!r}")
    if raw["name"] != SKILL_NAME:
        raise InstallerError("bundle manifest has the wrong name")
    version = _string(raw["version"], "bundle version", max_length=128)
    if not _VERSION.fullmatch(version):
        raise InstallerError("bundle version contains unsupported characters")
    source_repository = _string(raw["sourceRepository"], "sourceRepository")
    source_commit = _string(raw["sourceCommit"], "sourceCommit", max_length=64)
    if not _COMMIT.fullmatch(source_commit):
        raise InstallerError("sourceCommit must be a full 40- or 64-character hexadecimal object id")

    policy = raw["preservationPolicy"]
    if not isinstance(policy, dict):
        raise InstallerError("preservationPolicy must be an object")
    _expect_exact_keys(
        policy,
        {"version", "preservedConfigFiles", "extensionRoots"},
        "preservationPolicy",
    )
    if policy["version"] != POLICY_VERSION or isinstance(policy["version"], bool):
        raise InstallerError("unsupported preservation policy version")
    preserved = policy["preservedConfigFiles"]
    extensions = policy["extensionRoots"]
    if not isinstance(preserved, list) or any(not isinstance(item, str) for item in preserved):
        raise InstallerError("preservedConfigFiles must be an array of paths")
    if not isinstance(extensions, list) or any(not isinstance(item, str) for item in extensions):
        raise InstallerError("extensionRoots must be an array of paths")
    normalized_preserved = tuple(
        _safe_relative_path(item, "preserved config path") for item in preserved
    )
    normalized_extensions = tuple(
        _safe_relative_path(item, "extension root") for item in extensions
    )
    if len(set(normalized_preserved)) != len(normalized_preserved):
        raise InstallerError("preservedConfigFiles contains duplicates")
    if len(set(normalized_extensions)) != len(normalized_extensions):
        raise InstallerError("extensionRoots contains duplicates")
    if set(normalized_preserved) != set(PRESERVED_CONFIG_FILES):
        raise InstallerError("bundle preservation policy does not name the seven supported config files")
    if set(normalized_extensions) != set(EXTENSION_ROOTS):
        raise InstallerError("bundle preservation policy has unsupported extension roots")

    required = raw["requiredPaths"]
    if not isinstance(required, list) or not required:
        raise InstallerError("requiredPaths must be a non-empty array")
    required_paths = tuple(
        _safe_relative_path(item, "required path", directory=True) for item in required
    )
    if len(set(required_paths)) != len(required_paths):
        raise InstallerError("requiredPaths contains duplicates")

    raw_files = raw["files"]
    if not isinstance(raw_files, list) or not raw_files or len(raw_files) > MAX_FILES:
        raise InstallerError("files must be a non-empty bounded array")
    records: list[FileRecord] = []
    seen: set[str] = set()
    expanded_size = 0
    for index, raw_file in enumerate(raw_files):
        label = f"files[{index}]"
        if not isinstance(raw_file, dict):
            raise InstallerError(f"{label} must be an object")
        _expect_exact_keys(raw_file, {"path", "size", "mode", "sha256"}, label)
        path = _safe_relative_path(raw_file["path"], f"{label}.path")
        if path in {BUNDLE_MANIFEST, OWNERSHIP_MANIFEST, INSTALL_PROVENANCE}:
            raise InstallerError(f"{label}.path is reserved installer metadata")
        if path in seen:
            raise InstallerError(f"bundle manifest contains duplicate file path: {path}")
        seen.add(path)
        size = raw_file["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise InstallerError(f"{label}.size must be a non-negative integer")
        expanded_size += size
        if expanded_size > MAX_EXPANDED_BYTES:
            raise InstallerError("bundle expanded size exceeds the safety limit")
        mode_text = raw_file["mode"]
        if not isinstance(mode_text, str) or not _MODE.fullmatch(mode_text):
            raise InstallerError(f"{label}.mode must be a zero-padded four-digit octal string")
        mode = int(mode_text, 8)
        if mode & ~0o777:
            raise InstallerError(f"{label}.mode contains unsupported permission bits")
        digest = raw_file["sha256"]
        if not isinstance(digest, str) or not _HEX_DIGEST.fullmatch(digest):
            raise InstallerError(f"{label}.sha256 must be a lowercase SHA-256 digest")
        records.append(FileRecord(path, size, mode, mode_text, digest))

    file_paths = {record.path for record in records}
    for required_path in required_paths:
        if required_path.endswith("/"):
            if not any(path.startswith(required_path) for path in file_paths):
                raise InstallerError(f"required bundle directory is empty or missing: {required_path}")
        elif required_path not in file_paths:
            raise InstallerError(f"required bundle file is missing: {required_path}")
    for config_path in PRESERVED_CONFIG_FILES:
        if config_path not in file_paths:
            raise InstallerError(f"bundle is missing preserved config default: {config_path}")
    if "SKILL.md" not in file_paths:
        raise InstallerError("bundle is missing SKILL.md")

    return BundleManifest(
        version=version,
        source_repository=source_repository,
        source_commit=source_commit.lower(),
        required_paths=required_paths,
        files=tuple(records),
        raw=raw,
    )


def validate_bundle(path: Path, *, expected_sha256: str | None = None) -> ValidatedBundle:
    path = path.expanduser()
    if path.is_symlink() or not path.is_file():
        raise InstallerError(f"bundle is not a regular file: {path}")
    try:
        archive_bytes = path.read_bytes()
    except OSError as exc:
        raise InstallerError(f"cannot read bundle: {path}: {exc}") from exc
    if not archive_bytes or len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise InstallerError("bundle archive size is outside the safety limit")
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    if expected_sha256 is not None:
        if not _HEX_DIGEST.fullmatch(expected_sha256):
            raise InstallerError("expected bundle digest is not a lowercase SHA-256 digest")
        if archive_sha256 != expected_sha256:
            raise InstallerError("bundle archive digest does not match its trusted sidecar")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise InstallerError("bundle is not a valid gzip-compressed tar archive") from exc
    with archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_FILES + 1:
            raise InstallerError("bundle contains an invalid number of archive members")
        member_by_relative: dict[str, tarfile.TarInfo] = {}
        manifest_member: tarfile.TarInfo | None = None
        seen_names: set[str] = set()
        for member in members:
            name = member.name
            if name in seen_names:
                raise InstallerError(f"bundle contains duplicate archive member: {name}")
            seen_names.add(name)
            if not member.isreg():
                raise InstallerError(f"bundle member is not a regular file: {name}")
            if not name.startswith(BUNDLE_PREFIX):
                raise InstallerError(f"bundle member is outside {BUNDLE_PREFIX}: {name}")
            relative = _safe_relative_path(name[len(BUNDLE_PREFIX) :], "archive member")
            if relative == BUNDLE_MANIFEST:
                manifest_member = member
            else:
                member_by_relative[relative] = member
        if manifest_member is None:
            raise InstallerError(f"bundle is missing {BUNDLE_PREFIX}{BUNDLE_MANIFEST}")
        if manifest_member.mode & 0o7777 != 0o644:
            raise InstallerError("bundle manifest must have mode 0644")
        if manifest_member.size > MAX_MANIFEST_BYTES:
            raise InstallerError("bundle manifest is too large")
        manifest_stream = archive.extractfile(manifest_member)
        if manifest_stream is None:
            raise InstallerError("cannot read bundle manifest")
        manifest_bytes = manifest_stream.read(MAX_MANIFEST_BYTES + 1)
        if len(manifest_bytes) != manifest_member.size:
            raise InstallerError("bundle manifest size does not match its archive member")
        manifest = parse_manifest(manifest_bytes)
        records = manifest.file_map
        if set(records) != set(member_by_relative):
            unexpected = sorted(set(member_by_relative) - set(records))
            missing = sorted(set(records) - set(member_by_relative))
            if unexpected:
                raise InstallerError(f"bundle contains unexpected member: {unexpected[0]}")
            raise InstallerError(f"bundle is missing declared member: {missing[0]}")
        payload: dict[str, bytes] = {}
        for relative, record in records.items():
            member = member_by_relative[relative]
            archive_mode = member.mode & 0o7777
            if archive_mode != record.mode:
                raise InstallerError(f"bundle mode mismatch for {relative}")
            if member.size != record.size:
                raise InstallerError(f"bundle size mismatch for {relative}")
            stream = archive.extractfile(member)
            if stream is None:
                raise InstallerError(f"cannot read bundle member: {relative}")
            content = stream.read(record.size + 1)
            if len(content) != record.size:
                raise InstallerError(f"bundle size mismatch for {relative}")
            if hashlib.sha256(content).hexdigest() != record.sha256:
                raise InstallerError(f"bundle digest mismatch for {relative}")
            payload[relative] = content
    skill = payload["SKILL.md"].decode("utf-8", errors="replace")
    if not re.search(r"(?m)^name:[ \t]*startup-factory[ \t]*$", skill):
        raise InstallerError("SKILL.md does not identify Startup Factory")
    return ValidatedBundle(
        archive_path=path.absolute(),
        archive_sha256=archive_sha256,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        payload=payload,
    )


def _canonical_target(raw_target: Path) -> Path:
    expanded = raw_target.expanduser()
    if ".." in expanded.parts:
        raise InstallerError("install directory must not contain '..' path components")
    absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
    absolute = Path(os.path.abspath(absolute))
    if os.path.lexists(absolute) and absolute.is_symlink():
        raise InstallerError("install directory must not be a symlink; use its canonical path")
    target = absolute.resolve(strict=False)
    root = Path(target.anchor)
    if target == root:
        raise InstallerError("refusing to install at filesystem root")
    try:
        home = Path.home().resolve(strict=True)
    except OSError:
        home = Path.home().resolve(strict=False)
    if target == home:
        raise InstallerError("refusing to install at the home directory")
    if target.exists() and not target.is_dir():
        raise InstallerError(f"install destination exists and is not a directory: {target}")
    if target.is_dir():
        normal_git_root = os.path.lexists(target / ".git")
        bare_git_root = (
            (target / "HEAD").is_file()
            and (target / "objects").is_dir()
            and (target / "refs").is_dir()
        )
        if normal_git_root or bare_git_root:
            raise InstallerError("refusing to install at a Git repository root")
    return target


def _project_scoped_target(project: Path, relative: Path) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise InstallerError("project-relative install directory must remain inside --project")
    if not relative.parts or any(part in {"", "."} for part in relative.parts):
        raise InstallerError("project-relative install directory is invalid")
    candidate = project
    for part in relative.parts:
        candidate = candidate / part
        if os.path.lexists(candidate) and candidate.is_symlink():
            raise InstallerError(
                f"project-relative install directory contains a symlink component: {candidate}"
            )
    target = _canonical_target(candidate)
    if target == project or not target.is_relative_to(project):
        raise InstallerError("project-relative install directory resolves outside --project")
    return target


def resolve_target(
    *,
    project: Path,
    install_dir: Path | None,
    agent: str | None,
    command: str,
) -> Path:
    project_raw = project.expanduser()
    project_absolute = project_raw if project_raw.is_absolute() else Path.cwd() / project_raw
    if not project_absolute.exists() or not project_absolute.is_dir():
        raise InstallerError(f"project directory does not exist: {project_absolute}")
    project_path = project_absolute.resolve(strict=True)
    if install_dir is not None:
        if install_dir.is_absolute():
            return _canonical_target(install_dir)
        return _project_scoped_target(project_path, install_dir)

    normalized_agent = agent.lower() if agent else None
    mappings = {
        "codex": Path(".agents/skills/startup-factory"),
        "aider": Path(".agents/skills/startup-factory"),
        "claude": Path(".claude/skills/startup-factory"),
        "claude-code": Path(".claude/skills/startup-factory"),
    }
    if normalized_agent:
        try:
            relative = mappings[normalized_agent]
        except KeyError as exc:
            raise InstallerError(f"unsupported agent: {agent}") from exc
        return _project_scoped_target(project_path, relative)

    candidates = [
        project_path / mappings["codex"],
        project_path / mappings["claude"],
    ]
    existing = [candidate for candidate in candidates if os.path.lexists(candidate)]
    if command == "install" and not existing:
        return _project_scoped_target(project_path, mappings["codex"])
    if len(existing) == 1:
        relative = existing[0].relative_to(project_path)
        return _project_scoped_target(project_path, relative)
    if not existing:
        raise InstallerError("no Startup Factory installation found; pass --agent or --install-dir")
    raise InstallerError("multiple Startup Factory installations found; pass --agent or --install-dir")


def _skill_marker(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    return re.search(r"(?m)^name:[ \t]*startup-factory[ \t]*$", content) is not None


def _top_level_entries(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError as exc:
        raise InstallerError(f"cannot inspect install destination: {path}: {exc}") from exc


def _validate_existing_target(target: Path, command: str) -> tuple[bool, bool]:
    if not target.exists():
        if command == "update":
            raise InstallerError("Startup Factory is not installed at the selected destination")
        return False, False
    entries = _top_level_entries(target)
    if not entries:
        if command == "update":
            raise InstallerError("Startup Factory is not installed at the selected destination")
        return True, False
    if not _skill_marker(target / "SKILL.md"):
        raise InstallerError(f"non-empty install directory is not a Startup Factory installation: {target}")
    others = [entry for entry in entries if entry.name != "SKILL.md"]
    complete_marker = target / "bin/update-installed-skill.sh"
    if not complete_marker.is_file() or complete_marker.is_symlink():
        if others:
            raise InstallerError(
                "Startup Factory marker found, but destination is neither a complete "
                "installation nor a SKILL.md-only repair target"
            )
        return True, True
    if command == "install":
        raise InstallerError("Startup Factory is already installed; use the update command")
    return True, False


def _load_legacy_ownership(target: Path) -> tuple[bool, set[str]]:
    path = target / OWNERSHIP_MANIFEST
    if not os.path.lexists(path):
        return False, set()
    if path.is_symlink() or not path.is_file():
        raise InstallerError("installed ownership manifest is not a regular file")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise InstallerError("cannot read installed ownership manifest") from exc
    owned: set[str] = set()
    for line in text.splitlines():
        if not line:
            continue
        normalized = _safe_relative_path(line, "installed ownership path")
        if normalized in owned:
            raise InstallerError("installed ownership manifest contains duplicates")
        owned.add(normalized)
    return True, owned


def _walk_extension_files(root: Path) -> Iterator[tuple[str, Path]]:
    if not root.exists():
        return
    if root.is_symlink() or not root.is_dir():
        raise InstallerError(f"extension root is not a directory: {root.name}")
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        retained_directories: list[str] = []
        for name in directories:
            candidate = current_path / name
            if candidate.is_symlink():
                relative = candidate.relative_to(root.parent).as_posix()
                yield relative, candidate
            else:
                retained_directories.append(name)
        directories[:] = retained_directories
        for name in files:
            candidate = current_path / name
            relative = candidate.relative_to(root.parent).as_posix()
            yield relative, candidate


def _regular_file_bytes(path: Path) -> bytes | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError as exc:
        raise InstallerError(f"cannot read existing extension file: {path}") from exc


def _existing_relative_files(target: Path) -> set[str]:
    result: set[str] = set()
    for current, directories, files in os.walk(target, followlinks=False):
        current_path = Path(current)
        retained: list[str] = []
        for name in directories:
            candidate = current_path / name
            if candidate.is_symlink():
                result.add(candidate.relative_to(target).as_posix())
            else:
                retained.append(name)
        directories[:] = retained
        for name in files:
            result.add((current_path / name).relative_to(target).as_posix())
    return result


def make_plan(
    bundle: ValidatedBundle,
    target: Path,
    *,
    command: str,
    overwrite_config: bool,
) -> SyncPlan:
    had_target, repair = _validate_existing_target(target, command)
    has_manifest, old_owned = _load_legacy_ownership(target) if had_target else (False, set())
    new_files = set(bundle.payload)
    preserved_configs: list[str] = []
    if had_target and not overwrite_config:
        for relative in PRESERVED_CONFIG_FILES:
            path = target / relative
            if os.path.lexists(path):
                if path.is_symlink() or not path.is_file():
                    raise InstallerError(f"preserved config is not a regular file: {relative}")
                preserved_configs.append(relative)

    preserved_extensions: list[str] = []
    adopted_extensions: list[str] = []
    if had_target:
        for extension_root in EXTENSION_ROOTS:
            root = target / extension_root
            for relative, local_path in _walk_extension_files(root):
                if local_path.is_symlink() or not local_path.is_file():
                    raise InstallerError(f"project extension is not a regular file: {relative}")
                if relative not in new_files:
                    if not has_manifest or relative not in old_owned:
                        prefix = relative + "/"
                        if any(path.startswith(prefix) for path in new_files):
                            raise InstallerError(
                                "new upstream extension directory collides with "
                                f"project-owned file: {relative}"
                            )
                        parts = PurePosixPath(relative).parts
                        for index in range(1, len(parts)):
                            ancestor = "/".join(parts[:index])
                            if ancestor in new_files:
                                raise InstallerError(
                                    "new upstream extension file collides with "
                                    f"project-owned directory: {ancestor}"
                                )
                        preserved_extensions.append(relative)
                    continue
                if has_manifest and relative not in old_owned:
                    local_bytes = _regular_file_bytes(local_path)
                    if local_bytes is not None and local_bytes == bundle.payload[relative]:
                        adopted_extensions.append(relative)
                        continue
                    raise InstallerError(
                        f"new upstream extension collides with project-owned path: {relative}"
                    )

    existing_files = _existing_relative_files(target) if had_target else set()
    metadata = {BUNDLE_MANIFEST, OWNERSHIP_MANIFEST, INSTALL_PROVENANCE}
    preserved = set(preserved_configs) | set(preserved_extensions)
    desired = new_files | preserved | metadata
    deletes = sorted(existing_files - desired)
    writes: list[str] = []
    for relative in sorted(new_files):
        if relative in preserved_configs:
            continue
        destination = target / relative
        record = bundle.manifest.file_map[relative]
        if destination.is_symlink() or not destination.is_file():
            writes.append(relative)
            continue
        try:
            same_bytes = destination.read_bytes() == bundle.payload[relative]
            same_mode = stat.S_IMODE(destination.stat().st_mode) == record.mode
        except OSError:
            same_bytes = False
            same_mode = False
        if not same_bytes or not same_mode:
            writes.append(relative)
    writes.extend(sorted(metadata))
    return SyncPlan(
        target=target,
        command=command,
        writes=tuple(dict.fromkeys(writes)),
        deletes=tuple(deletes),
        preserved_configs=tuple(sorted(preserved_configs)),
        preserved_extensions=tuple(sorted(preserved_extensions)),
        adopted_extensions=tuple(sorted(adopted_extensions)),
        had_target=had_target,
        repair=repair,
    )


def _copy_preserved(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink() or not source.is_file():
        raise InstallerError(f"preserved path is not a regular file: {source}")
    shutil.copy2(source, destination, follow_symlinks=False)


def _write_file(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode, follow_symlinks=False)
    finally:
        os.close(descriptor)


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def _provenance(bundle: ValidatedBundle) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "name": SKILL_NAME,
        "version": bundle.manifest.version,
        "sourceRepository": bundle.manifest.source_repository,
        "sourceCommit": bundle.manifest.source_commit,
        "archiveSha256": bundle.archive_sha256,
        "manifestSha256": hashlib.sha256(bundle.manifest_bytes).hexdigest(),
        "installerVersion": __version__,
        "installedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "preservationPolicyVersion": POLICY_VERSION,
        "preservedConfigFiles": list(PRESERVED_CONFIG_FILES),
    }


def _build_stage(bundle: ValidatedBundle, plan: SyncPlan, stage: Path) -> None:
    for record in bundle.manifest.files:
        _write_file(stage / record.path, bundle.payload[record.path], record.mode)
    for relative in plan.preserved_configs + plan.preserved_extensions:
        destination = stage / relative
        if os.path.lexists(destination):
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        _copy_preserved(plan.target / relative, destination)
    _write_file(stage / BUNDLE_MANIFEST, bundle.manifest_bytes, 0o644)
    ownership = "".join(f"{path}\n" for path in sorted(bundle.payload)).encode("utf-8")
    _write_file(stage / OWNERSHIP_MANIFEST, ownership, 0o644)
    _write_file(stage / INSTALL_PROVENANCE, _canonical_json(_provenance(bundle)), 0o644)


def _verify_stage(bundle: ValidatedBundle, plan: SyncPlan, stage: Path) -> None:
    preserved_configs = set(plan.preserved_configs)
    for record in bundle.manifest.files:
        path = stage / record.path
        if path.is_symlink() or not path.is_file():
            raise InstallerError(f"staged bundle file is not regular: {record.path}")
        if record.path in preserved_configs:
            continue
        try:
            content = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError as exc:
            raise InstallerError(f"cannot verify staged bundle file: {record.path}") from exc
        if len(content) != record.size or hashlib.sha256(content).hexdigest() != record.sha256:
            raise InstallerError(f"staged bundle digest mismatch: {record.path}")
        if mode != record.mode:
            raise InstallerError(f"staged bundle mode mismatch: {record.path}")
    for relative in plan.preserved_extensions:
        path = stage / relative
        if path.is_symlink() or not path.is_file():
            raise InstallerError(f"staged bundle lost regular project extension: {relative}")


@contextlib.contextmanager
def _parent_lock(target: Path) -> Iterator[None]:
    if fcntl is None:
        raise InstallerError("Startup Factory installation requires a POSIX file-locking host")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not no_follow:
        raise InstallerError("Startup Factory installation requires secure no-follow file opens")
    lock_path = target.parent / f".{target.name}.startup-factory.lock"
    flags = os.O_RDWR | os.O_CREAT | no_follow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise InstallerError(f"cannot create installer lock: {lock_path}: {exc}") from exc
    acquired = False
    try:
        lock_stat = os.fstat(descriptor)
        if not stat.S_ISREG(lock_stat.st_mode):
            raise InstallerError(f"installer lock is not a regular file: {lock_path}")
        if lock_stat.st_uid != os.geteuid():
            raise InstallerError(f"installer lock is not owned by the current user: {lock_path}")
        if lock_stat.st_nlink != 1:
            raise InstallerError(f"installer lock has an unsafe link count: {lock_path}")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise InstallerError(f"another installer is already updating: {target}") from exc
            raise
        # The lock file intentionally remains content-free. Even after the
        # checks above, another process with write access to the parent could
        # add a hard link; never mutating the inode keeps that race harmless.
        yield
    finally:
        if acquired:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        if acquired:
            with contextlib.suppress(OSError):
                lock_path.unlink()


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _ensure_parent_directory(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if os.path.lexists(current):
            if current.is_symlink() or not current.is_dir():
                raise InstallerError(f"install parent contains a non-directory or symlink: {current}")
            continue
        try:
            current.mkdir()
        except FileExistsError:
            if current.is_symlink() or not current.is_dir():
                raise InstallerError(
                    f"install parent changed to a non-directory or symlink: {current}"
                )
        except OSError as exc:
            raise InstallerError(f"cannot create install parent: {current}: {exc}") from exc


def _swap_stage(stage: Path, target: Path) -> None:
    backup = target.parent / f".{target.name}.backup.{uuid.uuid4().hex}"
    moved_old = False
    installed_new = False
    try:
        if target.exists():
            os.replace(target, backup)
            moved_old = True
        os.replace(stage, target)
        installed_new = True
    except BaseException as original:
        rollback_errors: list[str] = []
        if installed_new and target.exists():
            try:
                os.replace(target, stage)
            except OSError as exc:
                rollback_errors.append(f"could not retire replacement: {exc}")
        if moved_old and backup.exists():
            try:
                os.replace(backup, target)
            except OSError as exc:
                rollback_errors.append(f"could not restore original: {exc}")
        if rollback_errors:
            raise InstallerError(
                "installation swap failed and rollback was incomplete: " + "; ".join(rollback_errors)
            ) from original
        raise
    if moved_old:
        try:
            _remove_path(backup)
        except OSError as exc:
            raise InstallerError(f"update succeeded but old backup could not be removed: {backup}: {exc}") from exc


def install_or_update(
    bundle: ValidatedBundle,
    target: Path,
    *,
    command: str,
    overwrite_config: bool,
    dry_run: bool,
) -> OperationResult:
    if command not in {"install", "update"}:
        raise ValueError(f"unsupported command: {command}")
    target = _canonical_target(target)
    plan = make_plan(
        bundle,
        target,
        command=command,
        overwrite_config=overwrite_config,
    )
    if not dry_run:
        _ensure_parent_directory(target.parent)
        with _parent_lock(target):
            # Recompute after acquiring authority; a concurrent operation may have
            # changed ownership or project configuration before the lock existed.
            locked_target = _canonical_target(target)
            if locked_target != target:
                raise InstallerError("install destination changed while acquiring the installer lock")
            plan = make_plan(
                bundle,
                target,
                command=command,
                overwrite_config=overwrite_config,
            )
            stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.stage.", dir=target.parent))
            try:
                try:
                    _build_stage(bundle, plan, stage)
                    _verify_stage(bundle, plan, stage)
                    _swap_stage(stage, target)
                except InstallerError:
                    raise
                except OSError as exc:
                    raise InstallerError(f"installation transaction failed: {exc}") from exc
            finally:
                if os.path.lexists(stage):
                    with contextlib.suppress(OSError):
                        _remove_path(stage)
    return OperationResult(
        action=command,
        target=target,
        version=bundle.manifest.version,
        source_repository=bundle.manifest.source_repository,
        source_commit=bundle.manifest.source_commit,
        archive_sha256=bundle.archive_sha256,
        dry_run=dry_run,
        plan=plan,
    )


def _load_json_file(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise InstallerError(f"{label} is missing or not a regular file")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InstallerError(f"cannot read {label}") from exc
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    except InstallerError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise InstallerError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise InstallerError(f"{label} must be a JSON object")
    return value


def verify_installation(target: Path) -> OperationResult:
    target = _canonical_target(target)
    _validate_existing_target(target, "update")
    manifest_path = target / BUNDLE_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise InstallerError("installed bundle manifest is missing or not a regular file")
    try:
        manifest = parse_manifest(manifest_path.read_bytes())
    except OSError as exc:
        raise InstallerError("installed bundle manifest is missing or unreadable") from exc
    provenance = _load_json_file(target / INSTALL_PROVENANCE, "install provenance")
    expected_provenance = {
        "schemaVersion": SCHEMA_VERSION,
        "name": SKILL_NAME,
        "version": manifest.version,
        "sourceRepository": manifest.source_repository,
        "sourceCommit": manifest.source_commit,
    }
    for key, expected in expected_provenance.items():
        if provenance.get(key) != expected:
            raise InstallerError(f"install provenance does not match the bundle manifest: {key}")
    archive_digest = provenance.get("archiveSha256")
    if not isinstance(archive_digest, str) or not _HEX_DIGEST.fullmatch(archive_digest):
        raise InstallerError("install provenance has an invalid archive digest")
    manifest_digest = provenance.get("manifestSha256")
    if not isinstance(manifest_digest, str) or not _HEX_DIGEST.fullmatch(manifest_digest):
        raise InstallerError("install provenance has an invalid manifest digest")
    try:
        installed_manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise InstallerError("cannot hash installed bundle manifest") from exc
    if installed_manifest_digest != manifest_digest:
        raise InstallerError("installed bundle manifest does not match install provenance")
    has_ownership, owned = _load_legacy_ownership(target)
    expected_owned = {record.path for record in manifest.files}
    if not has_ownership or owned != expected_owned:
        raise InstallerError("installed ownership manifest does not match the bundle manifest")

    preserved = set(PRESERVED_CONFIG_FILES)
    verified = 0
    for record in manifest.files:
        path = target / record.path
        if record.path in preserved:
            if path.is_symlink() or not path.is_file():
                raise InstallerError(f"preserved config is missing or not regular: {record.path}")
            continue
        if path.is_symlink() or not path.is_file():
            raise InstallerError(f"installed bundle file is missing or not regular: {record.path}")
        try:
            content = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError as exc:
            raise InstallerError(f"cannot verify installed file: {record.path}") from exc
        if len(content) != record.size or hashlib.sha256(content).hexdigest() != record.sha256:
            raise InstallerError(f"installed file digest mismatch: {record.path}")
        if mode != record.mode:
            raise InstallerError(f"installed file mode mismatch: {record.path}")
        verified += 1
    return OperationResult(
        action="verify",
        target=target,
        version=manifest.version,
        source_repository=manifest.source_repository,
        source_commit=manifest.source_commit,
        archive_sha256=archive_digest,
        dry_run=False,
        verified_files=verified,
        preserved_configs=PRESERVED_CONFIG_FILES,
    )
