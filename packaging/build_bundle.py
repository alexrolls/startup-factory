#!/usr/bin/env python3
"""Build a deterministic Startup Factory release bundle from Git objects."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


BUNDLE_NAME = "startup-factory"
ARCHIVE_PREFIX = f"{BUNDLE_NAME}/"
MANIFEST_PATH = ".startup-factory-bundle.json"
DEFAULT_SPEC_PATH = "packaging/bundle-spec.json"
REGULAR_GIT_MODES = {"100644": 0o644, "100755": 0o755}
EXPECTED_PRESERVED_CONFIGS = {
    "config/project-management.config.md",
    "config/planning.config.md",
    "config/team.config.md",
    "config/statuses.config.json",
    "config/automation.config.json",
    "config/deployment.config.json",
    "config/guardrails.config.json",
}


class BundleError(RuntimeError):
    """Raised when a source commit cannot produce a safe bundle."""


@dataclass(frozen=True)
class GitEntry:
    path: str
    mode: str
    kind: str
    object_id: str


@dataclass(frozen=True)
class BundleFile:
    path: str
    mode: int
    data: bytes


@dataclass(frozen=True)
class BuildResult:
    archive: Path
    sidecar: Path
    sha256: str
    source_commit: str


def _run_git(repo: Path, arguments: Sequence[str]) -> bytes:
    process = subprocess.run(
        ["git", "-C", os.fspath(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        detail = process.stderr.decode("utf-8", "replace").strip()
        raise BundleError(f"git {' '.join(arguments)} failed: {detail or 'unknown error'}")
    return process.stdout


def _validate_relative_path(path: str, *, label: str) -> str:
    if not isinstance(path, str) or not path:
        raise BundleError(f"{label} must be a non-empty string")
    if path.startswith("/") or path.endswith("/"):
        raise BundleError(f"{label} must be a normalized relative file path: {path!r}")
    if "\\" in path:
        raise BundleError(f"{label} must use POSIX separators: {path!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise BundleError(f"{label} contains a control or newline character: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BundleError(f"{label} contains an unsafe path component: {path!r}")
    return path


def _validate_directory_path(path: str, *, label: str) -> str:
    return _validate_relative_path(path, label=label)


def _validate_required_path(path: str) -> tuple[str, bool]:
    if not isinstance(path, str) or not path:
        raise BundleError("requiredPaths entries must be non-empty strings")
    is_directory = path.endswith("/")
    normalized = path[:-1] if is_directory else path
    _validate_relative_path(normalized, label="required path")
    return normalized, is_directory


def _decode_git_path(raw_path: bytes) -> str:
    if b"\n" in raw_path or b"\r" in raw_path:
        raise BundleError("Git tree contains a newline in a path")
    try:
        path = raw_path.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise BundleError("Git tree contains a non-UTF-8 path") from exc
    return _validate_relative_path(path, label="Git tree path")


def _resolve_commit(repo: Path, revision: str) -> str:
    if not isinstance(revision, str) or not revision or any(
        ord(character) < 32 or ord(character) == 127 for character in revision
    ):
        raise BundleError("commit must be a non-empty revision without control characters")
    resolved = _run_git(
        repo,
        ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
    ).decode("ascii", "strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", resolved):
        raise BundleError(f"Git returned an invalid commit object id: {resolved!r}")
    return resolved


def _read_tree(repo: Path, commit: str) -> dict[str, GitEntry]:
    raw_tree = _run_git(repo, ["ls-tree", "-r", "-z", "--full-tree", commit])
    entries: dict[str, GitEntry] = {}
    for record in raw_tree.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_kind, raw_object_id = metadata.split(b" ", 2)
            mode = raw_mode.decode("ascii", "strict")
            kind = raw_kind.decode("ascii", "strict")
            object_id = raw_object_id.decode("ascii", "strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise BundleError("Git returned a malformed tree entry") from exc
        path = _decode_git_path(raw_path)
        if path in entries:
            raise BundleError(f"Git tree contains a duplicate path: {path}")
        entries[path] = GitEntry(path, mode, kind, object_id)
    return entries


def _read_blob(repo: Path, entry: GitEntry, *, label: str) -> bytes:
    if entry.kind != "blob" or entry.mode not in REGULAR_GIT_MODES:
        if entry.mode == "120000":
            entry_type = "symlink"
        elif entry.mode == "160000" or entry.kind == "commit":
            entry_type = "submodule"
        else:
            entry_type = f"non-regular Git entry ({entry.mode} {entry.kind})"
        raise BundleError(f"{label} must be a regular Git file, not a {entry_type}: {entry.path}")
    return _run_git(repo, ["cat-file", "blob", entry.object_id])


def _object_without_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"bundle spec contains duplicate key: {key}")
        result[key] = value
    return result


def _string_list(value: Any, *, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise BundleError(f"{label} must be an array of strings")
    if len(value) != len(set(value)):
        raise BundleError(f"{label} must not contain duplicates")
    return list(value)


def _load_spec(repo: Path, entries: dict[str, GitEntry], spec_path: str) -> dict[str, Any]:
    _validate_relative_path(spec_path, label="bundle spec path")
    entry = entries.get(spec_path)
    if entry is None:
        raise BundleError(f"bundle spec does not exist in the source commit: {spec_path}")
    raw_spec = _read_blob(repo, entry, label="bundle spec")
    try:
        spec = json.loads(raw_spec.decode("utf-8"), object_pairs_hook=_object_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"bundle spec is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(spec, dict):
        raise BundleError("bundle spec must be a JSON object")
    expected_keys = {
        "schemaVersion",
        "sourceRepository",
        "include",
        "requiredPaths",
        "preservationPolicy",
    }
    if set(spec) != expected_keys:
        raise BundleError(
            "bundle spec must contain exactly: " + ", ".join(sorted(expected_keys))
        )
    if type(spec["schemaVersion"]) is not int or spec["schemaVersion"] != 1:
        raise BundleError("unsupported bundle spec schemaVersion")

    source_repository = spec["sourceRepository"]
    if (
        not isinstance(source_repository, str)
        or not source_repository
        or any(ord(character) < 32 or ord(character) == 127 for character in source_repository)
    ):
        raise BundleError("sourceRepository must be a non-empty string without control characters")

    include = spec["include"]
    if not isinstance(include, dict) or set(include) != {"files", "roots", "excludeRoots"}:
        raise BundleError("include must contain exactly files, roots, and excludeRoots")
    include_files = _string_list(include["files"], label="include.files")
    include_roots = _string_list(include["roots"], label="include.roots")
    exclude_roots = _string_list(include["excludeRoots"], label="include.excludeRoots")
    if not include_files or not include_roots:
        raise BundleError("include.files and include.roots must not be empty")
    for path in include_files:
        _validate_relative_path(path, label="included file")
    for path in include_roots:
        _validate_directory_path(path, label="included root")
    for path in exclude_roots:
        _validate_directory_path(path, label="excluded root")
        if not any(path.startswith(root + "/") for root in include_roots):
            raise BundleError(
                f"excluded root must be a strict descendant of an included root: {path}"
            )
    if set(include_files) & set(include_roots):
        raise BundleError("included files and roots must not overlap exactly")

    def is_excluded(path: str) -> bool:
        return any(path == root or path.startswith(root + "/") for root in exclude_roots)

    for path in include_files:
        if is_excluded(path):
            raise BundleError(f"included file is also excluded: {path}")

    required_paths = _string_list(spec["requiredPaths"], label="requiredPaths")
    if not required_paths:
        raise BundleError("requiredPaths must not be empty")
    parsed_required = [_validate_required_path(path) for path in required_paths]

    preservation = spec["preservationPolicy"]
    preservation_keys = {"version", "preservedConfigFiles", "extensionRoots"}
    if not isinstance(preservation, dict) or set(preservation) != preservation_keys:
        raise BundleError(
            "preservationPolicy must contain exactly version, preservedConfigFiles, and extensionRoots"
        )
    if type(preservation["version"]) is not int or preservation["version"] != 1:
        raise BundleError("unsupported preservation policy version")
    preserved_configs = _string_list(
        preservation["preservedConfigFiles"], label="preservedConfigFiles"
    )
    if set(preserved_configs) != EXPECTED_PRESERVED_CONFIGS:
        raise BundleError("preservedConfigFiles must contain the seven supported project configs")
    extension_roots = _string_list(preservation["extensionRoots"], label="extensionRoots")
    if not extension_roots:
        raise BundleError("extensionRoots must not be empty")
    for path in preserved_configs:
        _validate_relative_path(path, label="preserved config file")
    for path in extension_roots:
        _validate_directory_path(path, label="extension root")
    if not set(extension_roots).issubset(include_roots):
        raise BundleError("every extension root must also be an included root")

    required_files = {path for path, is_directory in parsed_required if not is_directory}
    required_directories = {path for path, is_directory in parsed_required if is_directory}
    for path in required_files | required_directories:
        if is_excluded(path):
            raise BundleError(f"required path is excluded from the bundle: {path}")
    if not EXPECTED_PRESERVED_CONFIGS.issubset(required_files):
        raise BundleError("all preserved config files must also be required paths")
    if not set(include_roots).issubset(required_directories):
        raise BundleError("every included root must also be a required directory path")

    def is_included(path: str) -> bool:
        return path in include_files or any(path.startswith(root + "/") for root in include_roots)

    for path in required_files:
        if not is_included(path):
            raise BundleError(f"required file is outside the included bundle surface: {path}")
    for path in required_directories:
        if path not in include_roots and not any(
            path.startswith(root + "/") for root in include_roots
        ):
            raise BundleError(f"required directory is outside the included bundle surface: {path}/")

    return spec


def _collect_files(
    repo: Path,
    entries: dict[str, GitEntry],
    spec: dict[str, Any],
) -> list[BundleFile]:
    include_files = spec["include"]["files"]
    include_roots = spec["include"]["roots"]
    exclude_roots = spec["include"]["excludeRoots"]
    selected: set[str] = set()

    def is_excluded(path: str) -> bool:
        return any(path == root or path.startswith(root + "/") for root in exclude_roots)

    for path in include_files:
        if path not in entries:
            raise BundleError(f"included file is missing from the source commit: {path}")
        selected.add(path)
    for root in include_roots:
        matches = {
            path
            for path in entries
            if path.startswith(root + "/") and not is_excluded(path)
        }
        if not matches:
            raise BundleError(f"included root is missing or empty in the source commit: {root}/")
        selected.update(matches)

    for required_path in spec["requiredPaths"]:
        normalized, is_directory = _validate_required_path(required_path)
        if is_directory:
            if not any(path.startswith(normalized + "/") for path in selected):
                raise BundleError(f"required directory is missing from the bundle: {required_path}")
        elif normalized not in selected:
            raise BundleError(f"required file is missing from the bundle: {normalized}")

    files: list[BundleFile] = []
    for path in sorted(selected):
        entry = entries[path]
        data = _read_blob(repo, entry, label="bundle member")
        files.append(BundleFile(path, REGULAR_GIT_MODES[entry.mode], data))
    return files


def _manifest_bytes(
    *,
    version: str,
    source_repository: str,
    source_commit: str,
    spec: dict[str, Any],
    files: Sequence[BundleFile],
) -> bytes:
    manifest = {
        "schemaVersion": 1,
        "name": BUNDLE_NAME,
        "version": version,
        "sourceRepository": source_repository,
        "sourceCommit": source_commit,
        "preservationPolicy": spec["preservationPolicy"],
        "requiredPaths": spec["requiredPaths"],
        "files": [
            {
                "path": item.path,
                "size": len(item.data),
                "mode": f"{item.mode:04o}",
                "sha256": hashlib.sha256(item.data).hexdigest(),
            }
            for item in files
        ],
    }
    return (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _tar_info(path: str, *, mode: int, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(ARCHIVE_PREFIX + path)
    info.type = tarfile.REGTYPE
    info.size = size
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _write_archive(path: Path, manifest: bytes, files: Sequence[BundleFile]) -> None:
    with path.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=9,
            fileobj=raw_output,
            mtime=0,
        ) as gzip_output:
            with tarfile.open(
                mode="w",
                fileobj=gzip_output,
                format=tarfile.PAX_FORMAT,
            ) as archive:
                manifest_info = _tar_info(MANIFEST_PATH, mode=0o644, size=len(manifest))
                archive.addfile(manifest_info, io.BytesIO(manifest))
                for item in files:
                    info = _tar_info(item.path, mode=item.mode, size=len(item.data))
                    archive.addfile(info, io.BytesIO(item.data))


def _validate_version(version: str) -> str:
    if not isinstance(version, str) or not re.fullmatch(
        r"[0-9A-Za-z][0-9A-Za-z._+\-]{0,127}", version
    ):
        raise BundleError(
            "version must be 1-128 ASCII letters, digits, dots, underscores, pluses, or hyphens"
        )
    return version


def build_bundle(
    *,
    repo: str | os.PathLike[str],
    commit: str,
    version: str,
    output: str | os.PathLike[str],
    spec_path: str = DEFAULT_SPEC_PATH,
) -> BuildResult:
    """Build an archive and SHA256 sidecar from one committed Git tree."""

    repository = Path(repo).resolve()
    if not repository.is_dir():
        raise BundleError(f"repository does not exist or is not a directory: {repository}")
    version = _validate_version(version)
    output_path = Path(output).resolve()
    if not output_path.name.endswith(".tar.gz"):
        raise BundleError("output path must end with .tar.gz")
    sidecar_path = Path(os.fspath(output_path) + ".sha256")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    source_commit = _resolve_commit(repository, commit)
    entries = _read_tree(repository, source_commit)
    spec = _load_spec(repository, entries, spec_path)
    files = _collect_files(repository, entries, spec)
    manifest = _manifest_bytes(
        version=version,
        source_repository=spec["sourceRepository"],
        source_commit=source_commit,
        spec=spec,
        files=files,
    )

    archive_fd, archive_tmp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    os.close(archive_fd)
    archive_tmp = Path(archive_tmp_name)
    sidecar_tmp: Path | None = None
    try:
        _write_archive(archive_tmp, manifest, files)
        archive_digest = hashlib.sha256(archive_tmp.read_bytes()).hexdigest()
        sidecar_fd, sidecar_tmp_name = tempfile.mkstemp(
            prefix=f".{sidecar_path.name}.", suffix=".tmp", dir=sidecar_path.parent
        )
        sidecar_tmp = Path(sidecar_tmp_name)
        with os.fdopen(sidecar_fd, "w", encoding="ascii", newline="\n") as sidecar_file:
            sidecar_file.write(f"{archive_digest}  {output_path.name}\n")
        os.replace(archive_tmp, output_path)
        os.replace(sidecar_tmp, sidecar_path)
    finally:
        archive_tmp.unlink(missing_ok=True)
        if sidecar_tmp is not None:
            sidecar_tmp.unlink(missing_ok=True)

    return BuildResult(output_path, sidecar_path, archive_digest, source_commit)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a deterministic Startup Factory tar.gz from one Git commit."
    )
    parser.add_argument("--repo", default=".", help="Git repository (default: current directory)")
    parser.add_argument("--commit", required=True, help="Commit or revision to resolve and package")
    parser.add_argument("--version", required=True, help="Release version recorded in the manifest")
    parser.add_argument("--output", required=True, help="Destination .tar.gz path")
    parser.add_argument(
        "--spec",
        default=DEFAULT_SPEC_PATH,
        help="Repository-relative bundle spec path read from the source commit",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    try:
        result = build_bundle(
            repo=arguments.repo,
            commit=arguments.commit,
            version=arguments.version,
            output=arguments.output,
            spec_path=arguments.spec,
        )
    except BundleError as exc:
        parser.exit(2, f"error: {exc}\n")
    print(f"archive={result.archive}")
    print(f"sha256={result.sha256}")
    print(f"sidecar={result.sidecar}")
    print(f"sourceCommit={result.source_commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
