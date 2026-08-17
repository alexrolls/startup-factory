#!/usr/bin/env python3
"""Conservative, diagnostic-only delivery profile assessment.

The assessment never removes a review, validation, or integration gate.  A
``micro`` result only describes a small, ordinary documentation change.  Any
unknown or risky input fails closed to ``standard``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from task_metadata import contains_strong_risk, parse_task_metadata, requires_strong_model


SCHEMA_VERSION = 1
MAX_MICRO_FILES = 3
MAX_MICRO_CHANGED_LINES = 200
MAX_GIT_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_PATCH_BYTES = 512 * 1024
DOC_SUFFIXES = {".adoc", ".md", ".rst", ".txt"}
ROOT_DOC_STEMS = {"changelog", "contributing", "license", "notice", "readme"}
CONTROL_COMPONENTS = {
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".github",
    ".gitlab",
    ".openai",
    ".teamwork",
    "adapters",
    "app",
    "apps",
    "bin",
    "config",
    "configs",
    "deploy",
    "deployment",
    "extensions",
    "infra",
    "infrastructure",
    "lib",
    "packages",
    "packaging",
    "plans",
    "policies",
    "policy",
    "reference",
    "roles",
    "runbooks",
    "scripts",
    "src",
    "superpowers",
    "teams",
    "test",
    "tests",
    "workflows",
}
CONTROL_NAMES = {
    "agents.md",
    "claude.md",
    "codeowners",
    "dockerfile",
    "makefile",
    "skill.md",
}
class DeliveryProfileError(ValueError):
    """Raised for malformed assessor inputs or an unusable Git repository."""


def _safe_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    if value.startswith("/") or value.endswith("/"):
        return None
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        return None
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or str(parsed) != value:
        return None
    return value


def is_ordinary_documentation_path(value: object) -> bool:
    """Return true only for allowlisted, non-control documentation paths."""
    path = _safe_relative_path(value)
    if path is None:
        return False
    parsed = PurePosixPath(path)
    lowered_parts = tuple(part.casefold() for part in parsed.parts)
    if any(part.startswith(".") or part in CONTROL_COMPONENTS for part in lowered_parts):
        return False
    name = lowered_parts[-1]
    if name in CONTROL_NAMES:
        return False
    suffix = parsed.suffix.casefold()
    stem = parsed.stem.casefold()
    if len(parsed.parts) == 1:
        return stem in ROOT_DOC_STEMS and suffix in DOC_SUFFIXES | {""}
    return lowered_parts[0] in {"doc", "docs", "documentation"} and suffix in DOC_SUFFIXES


def _task_shape(task: dict, metadata: dict) -> tuple[bool, list[str], list[str]]:
    reasons: list[str] = []
    files = metadata.get("files") or []
    if not isinstance(files, list) or any(not isinstance(path, str) for path in files):
        return False, [], ["invalid-declared-files"]
    if metadata.get("resources"):
        reasons.append("declared-shared-resources")
    if not files:
        reasons.append("files-not-declared")
    elif len(files) > MAX_MICRO_FILES:
        reasons.append("too-many-files")
    if len(files) != len(set(files)):
        reasons.append("duplicate-declared-files")
    if files and not all(is_ordinary_documentation_path(path) for path in files):
        reasons.append("non-ordinary-documentation-path")
    if requires_strong_model(task):
        reasons.append("strong-risk-language")
    return not reasons, sorted(files), reasons


def assess_task(task: dict, metadata: dict | None = None) -> dict:
    """Assess a tracker task using declared scope; ambiguity is standard."""
    if not isinstance(task, dict):
        raise DeliveryProfileError("task must be an object")
    if metadata is None:
        metadata = parse_task_metadata(task.get("description"), task.get("title"))
    requested = metadata.get("deliveryProfile", "auto")
    if requested not in {"auto", "micro", "standard"}:
        raise DeliveryProfileError("delivery profile must be auto, micro, or standard")
    eligible, files, reasons = _task_shape(task, metadata)
    if requested == "standard":
        reasons = ["standard-requested", *reasons]
    effective = "micro" if eligible and requested != "standard" else "standard"
    if effective == "micro":
        reasons = ["bounded-ordinary-documentation"]
    elif not reasons:
        reasons = ["ambiguous-task"]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "phase": "task",
        "requestedProfile": requested,
        "effectiveProfile": effective,
        "files": files,
        "changedLines": None,
        "reasons": reasons,
        "diagnosticOnly": True,
    }


def _git(
    repo: Path, *arguments: str, max_output_bytes: int = MAX_GIT_OUTPUT_BYTES
) -> bytes:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(repo),
        *arguments,
    ]
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            result = subprocess.run(
                command,
                check=False,
                stdout=stdout,
                stderr=stderr,
                env=environment,
            )
            if stdout.tell() > max_output_bytes:
                raise DeliveryProfileError("git output exceeds the safety cap")
            if stderr.tell() > 65_536:
                raise DeliveryProfileError("git error output exceeds the safety cap")
            stdout.seek(0)
            stderr.seek(0)
            output = stdout.read(max_output_bytes + 1)
            error_output = stderr.read(65_537)
    except OSError as exc:
        raise DeliveryProfileError("git could not be executed") from exc
    if result.returncode:
        message = error_output.decode("utf-8", "replace").strip()
        raise DeliveryProfileError("git command failed: %s" % (message or result.returncode))
    return output


def _patch_risk(repo: Path, base: str, head: str) -> list[str]:
    try:
        patch = _git(
            repo,
            "diff",
            "--patch",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            base,
            head,
            "--",
            max_output_bytes=MAX_PATCH_BYTES,
        )
        text = patch.decode("utf-8", "strict")
    except (DeliveryProfileError, UnicodeError):
        return ["unreadable-or-oversized-patch"]
    return ["strong-risk-diff-content"] if contains_strong_risk(text) else []


def _repository_root(repo: Path) -> Path:
    if repo.is_symlink() or not repo.is_dir():
        raise DeliveryProfileError("repository must be a non-symlink directory")
    resolved = repo.resolve()
    reported = _git(resolved, "rev-parse", "--show-toplevel")
    try:
        root = Path(reported.rstrip(b"\n").decode("utf-8", "strict")).resolve()
    except UnicodeError as exc:
        raise DeliveryProfileError("repository root is not UTF-8") from exc
    if root != resolved:
        raise DeliveryProfileError("repository path must be the Git top level")
    return resolved


def _resolve_commit(repo: Path, reference: str) -> str:
    if not isinstance(reference, str) or not reference or "\x00" in reference:
        raise DeliveryProfileError("revision must be a non-empty string")
    output = _git(repo, "rev-parse", "--verify", "--end-of-options", reference + "^{commit}")
    value = output.strip().decode("ascii", "strict")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        raise DeliveryProfileError("revision did not resolve to a commit")
    return value.lower()


def _decode_path(value: bytes) -> str:
    try:
        return value.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise DeliveryProfileError("diff contains a non-UTF-8 path") from exc


def _raw_diff(repo: Path, base: str, head: str) -> tuple[list[str], list[str]]:
    tokens = _git(
        repo,
        "diff",
        "--raw",
        "-z",
        "--no-ext-diff",
        "--find-renames=50%",
        base,
        head,
        "--",
    ).split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    files: list[str] = []
    reasons: list[str] = []
    index = 0
    while index < len(tokens):
        header = tokens[index]
        index += 1
        fields = header.split()
        if len(fields) != 5 or not fields[0].startswith(b":"):
            return [], ["unrecognized-raw-diff"]
        old_mode = fields[0][1:].decode("ascii", "replace")
        new_mode = fields[1].decode("ascii", "replace")
        status = fields[4].decode("ascii", "replace")
        if index >= len(tokens):
            return [], ["unrecognized-raw-diff"]
        first_path = _decode_path(tokens[index])
        index += 1
        path = first_path
        if status.startswith(("R", "C")):
            if index >= len(tokens):
                return [], ["unrecognized-raw-diff"]
            path = _decode_path(tokens[index])
            index += 1
        files.append(path)
        if status not in {"A", "M"}:
            reasons.append("unsupported-change-status:%s" % (status or "unknown"))
        if old_mode != new_mode and old_mode != "000000":
            reasons.append("file-mode-change")
        if new_mode != "100644":
            reasons.append("non-regular-file-mode")
    if len(files) != len(set(files)):
        reasons.append("duplicate-diff-path")
    return files, reasons


def _numstat_diff(repo: Path, base: str, head: str) -> tuple[dict[str, int], list[str]]:
    tokens = _git(
        repo,
        "diff",
        "--numstat",
        "-z",
        "--no-ext-diff",
        "--find-renames=50%",
        base,
        head,
        "--",
    ).split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    counts: dict[str, int] = {}
    reasons: list[str] = []
    index = 0
    while index < len(tokens):
        fields = tokens[index].split(b"\t", 2)
        index += 1
        if len(fields) != 3:
            return {}, ["unrecognized-numstat"]
        added, deleted, raw_path = fields
        # Rename/copy numstat encodes an empty path followed by old and new paths.
        if raw_path == b"":
            if index + 1 >= len(tokens):
                return {}, ["unrecognized-numstat"]
            index += 1
            raw_path = tokens[index]
            index += 1
        path = _decode_path(raw_path)
        if added == b"-" or deleted == b"-":
            reasons.append("binary-content")
            continue
        try:
            changed = int(added) + int(deleted)
        except ValueError:
            return {}, ["unrecognized-numstat"]
        if changed < 0 or path in counts:
            reasons.append("invalid-numstat")
        else:
            counts[path] = changed
    return counts, reasons


def assess_diff(
    repo: str | os.PathLike[str],
    base: str,
    head: str,
    task: dict,
    metadata: dict | None = None,
) -> dict:
    """Assess the actual committed Git diff, failing closed to standard."""
    if not isinstance(task, dict):
        raise DeliveryProfileError("task must be an object")
    if metadata is None:
        metadata = parse_task_metadata(task.get("description"), task.get("title"))
    requested = metadata.get("deliveryProfile", "auto")
    if requested not in {"auto", "micro", "standard"}:
        raise DeliveryProfileError("delivery profile must be auto, micro, or standard")
    root = _repository_root(Path(repo))
    resolved_base = _resolve_commit(root, base)
    resolved_head = _resolve_commit(root, head)
    files, reasons = _raw_diff(root, resolved_base, resolved_head)
    counts, numstat_reasons = _numstat_diff(root, resolved_base, resolved_head)
    reasons.extend(numstat_reasons)
    if not files:
        reasons.append("empty-diff")
    if len(files) > MAX_MICRO_FILES:
        reasons.append("too-many-files")
    if set(files) != set(counts):
        reasons.append("diff-accounting-mismatch")
    if files and not all(is_ordinary_documentation_path(path) for path in files):
        reasons.append("non-ordinary-documentation-path")
    if files and contains_strong_risk("\n".join(files)):
        reasons.append("strong-risk-diff-path")
    reasons.extend(_patch_risk(root, resolved_base, resolved_head))
    changed_lines = sum(counts.values())
    if changed_lines > MAX_MICRO_CHANGED_LINES:
        reasons.append("too-many-changed-lines")
    declared = metadata.get("files") or []
    if declared and set(declared) != set(files):
        reasons.append("declared-files-mismatch")
    if metadata.get("resources"):
        reasons.append("declared-shared-resources")
    if requires_strong_model(task):
        reasons.append("strong-risk-language")
    if requested == "standard":
        reasons.insert(0, "standard-requested")
    reasons = list(dict.fromkeys(reasons))
    effective = "micro" if not reasons and requested != "standard" else "standard"
    if effective == "micro":
        reasons = ["bounded-ordinary-documentation-diff"]
    elif not reasons:
        reasons = ["ambiguous-diff"]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "phase": "diff",
        "requestedProfile": requested,
        "effectiveProfile": effective,
        "files": sorted(files),
        "changedLines": changed_lines,
        "baseCommit": resolved_base,
        "headCommit": resolved_head,
        "reasons": reasons,
        "diagnosticOnly": True,
    }


def _read_task(path: str) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DeliveryProfileError("task file must contain valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise DeliveryProfileError("task file must contain an object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    task = subparsers.add_parser("task", help="assess declared task scope")
    task.add_argument("--task", required=True, help="task JSON file")
    diff = subparsers.add_parser("diff", help="assess an actual committed Git diff")
    diff.add_argument("--repo", required=True)
    diff.add_argument("--base", required=True)
    diff.add_argument("--head", required=True)
    diff.add_argument("--task", required=True, help="task JSON file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        task = _read_task(args.task)
        result = (
            assess_task(task)
            if args.command == "task"
            else assess_diff(args.repo, args.base, args.head, task)
        )
    except DeliveryProfileError as exc:
        print("delivery-profile: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
