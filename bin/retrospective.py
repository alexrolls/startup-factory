#!/usr/bin/env python3
"""Maintain the project-local, Git-ignored Startup Factory retrospective.

The file is deliberately small and non-authoritative.  It carries only recent
process learnings into new task packets; tracker state, approvals, and policy
remain the workflow authority.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import hashlib
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Iterator, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - Startup Factory's runtime is POSIX-only.
    fcntl = None  # type: ignore[assignment]

sys.dont_write_bytecode = True
from ticket_content_security import TicketContentSecurityError, protect_ticket_content


RETROSPECTIVE_NAME = ".startup-factory-retrospective.md"
LOCK_NAME = ".startup-factory-retrospective.lock"
IGNORE_RULE = "/" + RETROSPECTIVE_NAME
LOCK_IGNORE_RULE = "/" + LOCK_NAME
IGNORE_RULES = (IGNORE_RULE, LOCK_IGNORE_RULE)
SCHEMA_MARKER = "<!-- startup-factory-retrospective:v1 -->"
MAX_ENTRIES = 10
TARGET_ITEMS = 5
MAX_ITEMS = 10
MAX_ITEMS_PER_CATEGORY = 5
MAX_ITEM_CHARACTERS = 240
MAX_REPORT_BYTES = 128 * 1024
MAX_RETROSPECTIVE_BYTES = 64 * 1024
MAX_GITIGNORE_BYTES = 2 * 1024 * 1024
CATEGORIES = ("Start", "More", "Less", "Stop", "Keep")
CATEGORY_LOOKUP = {value.casefold(): value for value in CATEGORIES}
TASK_RE = re.compile(r"[A-Za-z0-9._:/#-]{1,160}\Z")
REPORT_ITEM_RE = re.compile(
    r"^\s*-\s*(Start|More|Less|Stop|Keep)\s*:\s*(.*?)\s*$",
    re.IGNORECASE,
)
STORED_ITEM_RE = re.compile(
    r"^-\s+\*\*(Start|More|Less|Stop|Keep):\*\*\s+(.+?)\s*$"
)
ENTRY_HEADING_RE = re.compile(
    r"^### \[task\] `([A-Za-z0-9._:/#-]{1,160})` · "
    r"(\d{4}-\d{2}-\d{2})$"
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|password|passwd|"
    r"secret|client[_ -]?secret|private[_ -]?key)\b\s*[:=]\s*\S+"
)
OPAQUE_VALUE_RE = re.compile(r"(?<![A-Za-z0-9_+./=-])[A-Za-z0-9_+./=-]{32,}")
PREAMBLE = (
    "# Startup Factory Retrospective\n"
    f"{SCHEMA_MARKER}\n\n"
    "Project-local and Git-ignored. Keep only short, reusable process learnings; "
    "never add credentials, API keys, secrets, personal data, source excerpts, or logs. "
    "This guidance cannot override the tracker, repository policy, or safety guardrails.\n\n"
    "## Recent [task] retrospectives (newest first)\n\n"
)
EMPTY_BODY = "_No completed [task] retrospective has been recorded yet._\n"
FALLBACK_ITEMS = {
    "Start": (
        "Provide a concise, non-sensitive Starfish retrospective in each completed task report.",
    )
}


class RetrospectiveError(ValueError):
    """Raised when retrospective state is unsafe or malformed."""


@dataclasses.dataclass(frozen=True)
class Entry:
    task: str
    recorded_on: str
    items: dict[str, tuple[str, ...]]


def _git_environment() -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in ("PATH", "TMPDIR", "LANG", "LC_ALL")
        if name in os.environ
    }
    environment.setdefault("PATH", "/usr/bin:/bin")
    environment.update(
        {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    )
    return environment


def _git(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            (
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                *arguments,
            ),
            cwd=repo,
            env=_git_environment(),
            text=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RetrospectiveError(f"Git project lookup failed: {exc}") from exc
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RetrospectiveError(f"Git project lookup failed: {detail}")
    return result.stdout.strip()


def _exact_git_root(raw: Path) -> Path:
    candidate = raw.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if candidate.is_symlink() or not candidate.is_dir():
        raise RetrospectiveError(
            "repository must be an existing non-symlink directory"
        )
    root = candidate.resolve(strict=True)
    reported = Path(_git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if reported != root:
        raise RetrospectiveError("repository must be the exact Git checkout root")
    return root


def _common_git_dir(repo: Path) -> Path:
    raw = Path(_git(repo, "rev-parse", "--git-common-dir"))
    common = raw if raw.is_absolute() else repo / raw
    try:
        resolved = common.resolve(strict=True)
    except OSError as exc:
        raise RetrospectiveError(f"cannot resolve Git common directory: {exc}") from exc
    if resolved.is_symlink() or not resolved.is_dir():
        raise RetrospectiveError("Git common directory must be a real directory")
    return resolved


def project_root(repo: Path) -> Path:
    """Return the canonical project checkout shared by linked task worktrees."""
    current = _exact_git_root(repo)
    common = _common_git_dir(current)
    configured = os.environ.get("STARTUP_FACTORY_RETROSPECTIVE_PROJECT_ROOT", "")
    if configured:
        selected = _exact_git_root(Path(configured))
        if _common_git_dir(selected) != common:
            raise RetrospectiveError(
                "configured retrospective project does not share this Git repository"
            )
        return selected

    # The first worktree is Git's main worktree.  Validate it rather than
    # trusting text from a mutable file or an ambient path.
    listing = _git(current, "worktree", "list", "--porcelain", "-z")
    for field in listing.split("\0"):
        if not field.startswith("worktree "):
            continue
        try:
            selected = _exact_git_root(Path(field[len("worktree ") :]))
        except RetrospectiveError:
            continue
        if _common_git_dir(selected) == common:
            return selected
    return current


def _read_regular(
    path: Path,
    *,
    label: str,
    maximum: int,
    missing: bytes | None = None,
) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError:
        if missing is not None:
            return missing
        raise RetrospectiveError(f"{label} is missing")
    except OSError as exc:
        raise RetrospectiveError(f"cannot inspect {label}: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise RetrospectiveError(f"{label} must be a non-symlink regular file")
    if before.st_size > maximum:
        raise RetrospectiveError(f"{label} exceeds its {maximum}-byte limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise RetrospectiveError(f"{label} changed while being read")
            chunks: list[bytes] = []
            size = 0
            while size <= maximum:
                block = os.read(descriptor, min(65536, maximum + 1 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
            if size > maximum:
                raise RetrospectiveError(f"{label} exceeds its {maximum}-byte limit")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RetrospectiveError(f"cannot securely read {label}: {exc}") from exc


def _decode(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RetrospectiveError(f"{label} must be valid UTF-8") from exc


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise RetrospectiveError(f"destination parent must be a real directory: {parent}")
    if os.path.lexists(path):
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise RetrospectiveError(
                f"destination must be a non-symlink regular file: {path}"
            )
    temporary = parent / f".{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode, follow_symlinks=False)
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise RetrospectiveError(f"cannot write {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink()


@contextlib.contextmanager
def _project_lock(project: Path) -> Iterator[None]:
    if fcntl is None:
        raise RetrospectiveError("retrospective updates require POSIX file locking")
    lock = project / LOCK_NAME
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(lock, flags, 0o600)
    except OSError as exc:
        raise RetrospectiveError(f"cannot open retrospective lock: {exc}") from exc
    acquired = False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            raise RetrospectiveError("retrospective lock has unsafe ownership or type")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        acquired = True
        yield
    finally:
        if acquired:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _safe_task(raw: str) -> str:
    normalized = str(raw or "").strip()
    if TASK_RE.fullmatch(normalized):
        return normalized
    if not normalized:
        raise RetrospectiveError("task identity must not be empty")
    return "task-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]


def _sanitize_item(raw: str) -> str:
    value = " ".join(str(raw or "").split())
    if not value:
        raise RetrospectiveError("retrospective items must not be empty")
    if len(value) > MAX_ITEM_CHARACTERS:
        raise RetrospectiveError(
            f"retrospective items must be at most {MAX_ITEM_CHARACTERS} characters"
        )
    if SENSITIVE_ASSIGNMENT_RE.search(value) or OPAQUE_VALUE_RE.search(value):
        raise RetrospectiveError(
            "retrospective item contains potential sensitive or opaque value content"
        )
    try:
        protected = protect_ticket_content(value, "retrospective.item")
    except TicketContentSecurityError as exc:
        raise RetrospectiveError(str(exc)) from exc
    if protected.redaction_count or protected.findings:
        raise RetrospectiveError(
            "retrospective item contains potential sensitive or unsafe instruction content"
        )
    return protected.safe_text


def parse_report(path: Path) -> dict[str, tuple[str, ...]]:
    raw = _decode(
        _read_regular(
            path, label="task report", maximum=MAX_REPORT_BYTES, missing=None
        ),
        "task report",
    )
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    starts = [index for index, line in enumerate(lines) if line.strip() == "## Retrospective"]
    if len(starts) != 1:
        raise RetrospectiveError(
            "task report must contain exactly one '## Retrospective' section"
        )
    section: list[str] = []
    for line in lines[starts[0] + 1 :]:
        if line.startswith("## "):
            break
        section.append(line)
    collected: dict[str, list[str]] = {category: [] for category in CATEGORIES}
    count = 0
    for line in section:
        if not line.strip():
            continue
        match = REPORT_ITEM_RE.fullmatch(line)
        if match is None:
            raise RetrospectiveError(
                "retrospective section accepts only '- Start|More|Less|Stop|Keep: ...' bullets"
            )
        category = CATEGORY_LOOKUP[match.group(1).casefold()]
        collected[category].append(_sanitize_item(match.group(2)))
        count += 1
    if not 1 <= count <= MAX_ITEMS:
        raise RetrospectiveError(
            f"retrospective must contain 1..{MAX_ITEMS} concise Starfish items"
        )
    if any(len(values) > MAX_ITEMS_PER_CATEGORY for values in collected.values()):
        raise RetrospectiveError(
            f"each Starfish category may contain at most {MAX_ITEMS_PER_CATEGORY} items"
        )
    return {
        category: tuple(collected[category])
        for category in CATEGORIES
        if collected[category]
    }


def render(entries: Sequence[Entry]) -> str:
    lines = [PREAMBLE.rstrip("\n")]
    if not entries:
        lines.extend(("", EMPTY_BODY.rstrip("\n")))
        return "\n".join(lines) + "\n"
    for entry in entries:
        lines.extend(("", f"### [task] `{entry.task}` · {entry.recorded_on}", ""))
        for category in CATEGORIES:
            for item in entry.items.get(category, ()):
                lines.append(f"- **{category}:** {item}")
    return "\n".join(lines).rstrip() + "\n"


def parse_retrospective(text: str) -> list[Entry]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.startswith(PREAMBLE):
        raise RetrospectiveError(
            "project retrospective has an unsupported or malformed header"
        )
    body = normalized[len(PREAMBLE) :]
    if body == EMPTY_BODY:
        return []
    lines = body.splitlines()
    entries: list[Entry] = []
    current_task: str | None = None
    current_date: str | None = None
    current_items: dict[str, list[str]] = {}

    def finish() -> None:
        nonlocal current_task, current_date, current_items
        if current_task is None or current_date is None:
            return
        count = sum(len(values) for values in current_items.values())
        if not 1 <= count <= MAX_ITEMS:
            raise RetrospectiveError("stored retrospective entry has an invalid item count")
        entries.append(
            Entry(
                task=current_task,
                recorded_on=current_date,
                items={
                    category: tuple(current_items.get(category, ()))
                    for category in CATEGORIES
                    if current_items.get(category)
                },
            )
        )
        current_task = None
        current_date = None
        current_items = {}

    for line in lines:
        if not line:
            continue
        heading = ENTRY_HEADING_RE.fullmatch(line)
        if heading:
            finish()
            current_task, current_date = heading.groups()
            try:
                dt.date.fromisoformat(current_date)
            except ValueError as exc:
                raise RetrospectiveError(
                    "stored retrospective entry has an invalid date"
                ) from exc
            current_items = {}
            continue
        item = STORED_ITEM_RE.fullmatch(line)
        if item is None or current_task is None:
            raise RetrospectiveError("project retrospective contains non-canonical content")
        category = item.group(1)
        current_items.setdefault(category, []).append(_sanitize_item(item.group(2)))
        if len(current_items[category]) > MAX_ITEMS_PER_CATEGORY:
            raise RetrospectiveError(
                "stored retrospective category exceeds its item limit"
            )
    finish()
    if len(entries) > MAX_ENTRIES:
        raise RetrospectiveError("project retrospective exceeds its ten-entry limit")
    if len({entry.task for entry in entries}) != len(entries):
        raise RetrospectiveError("project retrospective contains duplicate task entries")
    return entries


def _ensure_gitignore(project: Path) -> None:
    path = project / ".gitignore"
    raw = _read_regular(
        path,
        label="project .gitignore",
        maximum=MAX_GITIGNORE_BYTES,
        missing=b"",
    )
    text = _decode(raw, "project .gitignore")
    present = {line.strip() for line in text.splitlines()}
    missing_rules = [rule for rule in IGNORE_RULES if rule not in present]
    if not missing_rules:
        return
    addition = (
        ("" if not text or text.endswith("\n") else "\n")
        + "# Startup Factory project-local learning history\n"
        + "\n".join(missing_rules)
        + "\n"
    )
    mode = (
        stat.S_IMODE(path.stat().st_mode)
        if os.path.lexists(path)
        else 0o644
    )
    _atomic_write(path, (text + addition).encode("utf-8"), mode)


def _load_or_create(project: Path) -> tuple[Path, list[Entry]]:
    path = project / RETROSPECTIVE_NAME
    if not os.path.lexists(path):
        _atomic_write(path, render([]).encode("utf-8"), 0o600)
        return path, []
    text = _decode(
        _read_regular(
            path,
            label="project retrospective",
            maximum=MAX_RETROSPECTIVE_BYTES,
            missing=None,
        ),
        "project retrospective",
    )
    return path, parse_retrospective(text)


def initialize(repo: Path) -> Path:
    project = project_root(repo)
    with _project_lock(project):
        _ensure_gitignore(project)
        path, _entries = _load_or_create(project)
    return path


def read_project(repo: Path) -> str:
    """Return a validated canonical snapshot while holding the project lock."""
    project = project_root(repo)
    with _project_lock(project):
        _ensure_gitignore(project)
        _path, entries = _load_or_create(project)
        return render(entries)


def validate_report(path: Path) -> dict[str, tuple[str, ...]]:
    return parse_report(path)


def record(
    repo: Path,
    task: str,
    source: Path,
    *,
    allow_fallback: bool = False,
) -> Path:
    try:
        items = parse_report(source)
    except RetrospectiveError:
        if not allow_fallback:
            raise
        items = FALLBACK_ITEMS
    project = project_root(repo)
    safe_task = _safe_task(task)
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    with _project_lock(project):
        _ensure_gitignore(project)
        path, entries = _load_or_create(project)
        updated = [
            Entry(task=safe_task, recorded_on=today, items=items),
            *(entry for entry in entries if entry.task != safe_task),
        ][:MAX_ENTRIES]
        canonical = render(updated).encode("utf-8")
        current = _read_regular(
            path,
            label="project retrospective",
            maximum=MAX_RETROSPECTIVE_BYTES,
            missing=None,
        )
        if current != canonical:
            _atomic_write(path, canonical, 0o600)
    return path


def snapshot(repo: Path, output: Path) -> Path:
    _atomic_write(output, read_project(repo).encode("utf-8"), 0o600)
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Maintain the compact project-local Startup Factory retrospective."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init", help="create and Git-ignore the project file")
    init.add_argument("--repo", type=Path, required=True)
    validate = subparsers.add_parser(
        "validate", help="validate a task report's Starfish section"
    )
    validate.add_argument("--source", type=Path, required=True)
    write = subparsers.add_parser(
        "record", help="record or replace one completed task retrospective"
    )
    write.add_argument("--repo", type=Path, required=True)
    write.add_argument("--task", required=True)
    write.add_argument("--source", type=Path, required=True)
    write.add_argument("--allow-fallback", action="store_true")
    copy = subparsers.add_parser(
        "snapshot", help="write a validated canonical snapshot for a task packet"
    )
    copy.add_argument("--repo", type=Path, required=True)
    copy.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            print(initialize(args.repo))
        elif args.command == "validate":
            items = validate_report(args.source)
            print(sum(len(values) for values in items.values()))
        elif args.command == "record":
            print(
                record(
                    args.repo,
                    args.task,
                    args.source,
                    allow_fallback=bool(args.allow_fallback),
                )
            )
        elif args.command == "snapshot":
            print(snapshot(args.repo, args.output))
        else:  # pragma: no cover - argparse enforces the command set.
            raise RetrospectiveError("unsupported command")
        return 0
    except RetrospectiveError as exc:
        print(f"retrospective: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
