#!/usr/bin/env python3
"""Evaluate strict, exact-commit beta-readiness evidence without network access.

The checker validates structure, bindings, freshness, digests, and objective
criterion mechanics. Producer identities are retained as asserted metadata; an
offline digest does not authenticate a person or external service. Release
owners must obtain evidence from protected systems before running this check.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import errno
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from startup_factory_cli.secret_safety import (  # noqa: E402
    contains_secret_like,
    redact_secret_like,
)


SCHEMA_VERSION = 1
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_CRITERIA = 32
MAX_JSON_DEPTH = 12
MAX_JSON_VALUES = 4096
MAX_JSON_CONTAINER_ITEMS = 256
MAX_JSON_STRING = 4096
MAX_GIT_STDERR_BYTES = 64 * 1024
DEFAULT_MAX_AGE_DAYS = 14
DEFAULT_EVIDENCE_PATH = ".startup-factory/beta-readiness-evidence.json"
ARTIFACT_DIRECTORY = PurePosixPath(".startup-factory/beta-evidence")

_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z\Z"
)
_ARTIFACT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
_INTEGRATION_ID = re.compile(r"integration-[0-9a-f]{32}\Z")
_PRODUCER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{1,127}\Z")
_RUN_ID = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}\Z")
_VERSION = re.compile(r"\d+\.\d+\.\d+\Z")
_BUNDLE_NAME = re.compile(r"startup-factory-(\d+\.\d+\.\d+)\.tar\.gz\Z")
_WHEEL_NAME = re.compile(
    r"startup_factory-(\d+\.\d+\.\d+)-py3-none-any\.whl\Z"
)
_SDIST_NAME = re.compile(r"startup_factory-(\d+\.\d+\.\d+)\.tar\.gz\Z")
_PYTHON_VERSION = re.compile(r"3\.(10|14)\.(0|[1-9][0-9]*)\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
def _resolved_git_executable() -> str | None:
    # Do not let an untrusted caller-controlled PATH select executable code.
    # Tests that need a probe binary patch GIT_EXECUTABLE only after import.
    candidate = shutil.which("git", path=os.defpath)
    if candidate is None:
        return None
    try:
        resolved = Path(candidate).resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        return None
    return os.fspath(resolved)


GIT_EXECUTABLE = _resolved_git_executable()

CANONICAL_VALIDATION_CHECKS = (
    (
        "runtime-suite",
        ("/bin/bash", "tests/run-all.sh"),
        (),
    ),
    (
        "packaging-source-suite",
        (
            "python",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests/packaging",
            "-p",
            "test_*.py",
            "-v",
        ),
        (),
    ),
    (
        "packaging-built-distribution-suite",
        (
            "python",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests/packaging",
            "-p",
            "test_*.py",
            "-v",
        ),
        ("STARTUP_FACTORY_BUNDLE", "STARTUP_FACTORY_DIST_DIR"),
    ),
)


class BetaReadinessError(ValueError):
    """Raised when readiness inputs are malformed or unsafe."""

    def __init__(self, message: str) -> None:
        # Parser, filesystem, and Git failures can contain attacker-controlled
        # text. Retain no recognized secret bytes in the exception itself.
        super().__init__(redact_secret_like(str(message)))


class RepositoryPathMissing(BetaReadinessError):
    """Raised only for an absent repository-relative path."""


@dataclasses.dataclass(frozen=True)
class DocumentCriterion:
    id: str
    path: str
    markers: tuple[str, ...]
    description: str
    forbidden_markers: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class EvidenceCriterion:
    id: str
    description: str
    producer_role: str


@dataclasses.dataclass(frozen=True)
class ValidatedArtifact:
    artifact_id: str
    path: str
    digest: str
    release_set_digest: str | None
    bindings: tuple[tuple[str, str], ...] = ()


DOCUMENT_CRITERIA = (
    DocumentCriterion(
        "security-policy",
        "SECURITY.md",
        (
            "## Reporting a vulnerability",
            "## Response targets",
            "## Safe harbor",
            (
                "Published-beta channel contract: available only after "
                "exact-candidate protected verification"
            ),
            "available for a published beta only",
            (
                "Unreleased-candidate status: current channel availability "
                "is not asserted"
            ),
        ),
        "A responsible disclosure policy and response process are documented.",
        forbidden_markers=("Current channel status: unavailable until verified",),
    ),
    DocumentCriterion(
        "quickstart",
        "reference/quickstart.md",
        (
            "# Quickstart",
            "15 minutes",
            "doctor",
            "uvx --version",
            ".agents/skills/startup-factory/config/project-management.config.md",
        ),
        "A concise, time-bounded first-delivery quickstart is available.",
    ),
    DocumentCriterion(
        "compatibility-matrix",
        "reference/compatibility.md",
        (
            "# Compatibility",
            "Claimed",
            "Tested",
            "Experimental",
            "Untested",
            "Windows",
            "WSL",
            "contains no exact-candidate run result",
        ),
        "Tested, untested, and unsupported environments are distinguished.",
    ),
    DocumentCriterion(
        "reproducible-walkthrough",
        "reference/governed-delivery-example.md",
        (
            "# Reproducible governed delivery",
            "Expected result",
            "No release",
            "build==1.3.0",
            "SOURCE_DATE_EPOCH",
            "contains no execution result",
            "authenticated review",
        ),
        "A reproducible, non-production walkthrough is documented.",
    ),
    DocumentCriterion(
        "benchmark-methodology",
        "reference/benchmarks.md",
        (
            "# Delivery benchmark methodology",
            "p50",
            "p95",
            "unknown",
            "release-set",
            "unavailability reason",
        ),
        "A reproducible latency and usage measurement method is documented.",
    ),
    DocumentCriterion(
        "objective-beta-criteria",
        "reference/beta-readiness.md",
        (
            "# Beta readiness",
            "Required evidence",
            "not ready",
            "Canonical release set",
            "packaging-built-distribution-suite",
        ),
        "Objective beta entry and exit criteria are documented.",
    ),
)

EVIDENCE_CRITERIA = (
    EvidenceCriterion(
        "private-disclosure-channel",
        "A release owner recorded a secret-free private-intake and acknowledgement check.",
        "release-owner",
    ),
    EvidenceCriterion(
        "full-validation",
        "Runtime and package suites passed for the exact candidate and release set.",
        "qa-engineer",
    ),
    EvidenceCriterion(
        "reproducible-package",
        "Two clean builds produced the same bundle, wheel, and sdist release set.",
        "integrator",
    ),
    EvidenceCriterion(
        "independent-exact-package-review",
        "Distinct architecture, QA, and security reviewers approved the release set.",
        "review-board-recorder",
    ),
    EvidenceCriterion(
        "exact-candidate-compatibility",
        "Typed minimum/current Python compatibility runs passed for the exact candidate and release set.",
        "compatibility-tester",
    ),
    EvidenceCriterion(
        "governed-walkthrough-execution",
        "A non-production walkthrough produced authenticated exact-package review and integration evidence.",
        "walkthrough-operator",
    ),
    EvidenceCriterion(
        "first-governed-delivery-under-15m",
        "At least five cold and warm successful runs support the validated percentiles.",
        "benchmark-operator",
    ),
    EvidenceCriterion(
        "runtime-usage-observability",
        "Runtime usage metrics or explicit per-metric unavailability reasons were recorded.",
        "usage-recorder",
    ),
)

EVIDENCE_BY_ID = {criterion.id: criterion for criterion in EVIDENCE_CRITERIA}


def _reject_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BetaReadinessError("duplicate JSON key is forbidden")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BetaReadinessError(f"non-finite JSON number is forbidden: {value}")


def _validate_json_tree(value: object, *, label: str) -> None:
    total = 0

    def visit(item: object, depth: int) -> None:
        nonlocal total
        total += 1
        if total > MAX_JSON_VALUES:
            raise BetaReadinessError(f"{label} contains too many JSON values")
        if depth > MAX_JSON_DEPTH:
            raise BetaReadinessError(f"{label} nesting exceeds {MAX_JSON_DEPTH}")
        if isinstance(item, dict):
            if len(item) > MAX_JSON_CONTAINER_ITEMS:
                raise BetaReadinessError(f"{label} object contains too many keys")
            for key, child in item.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key) > 128
                    or _CONTROL.search(key)
                ):
                    raise BetaReadinessError(f"{label} contains an invalid JSON key")
                if contains_secret_like(key):
                    raise BetaReadinessError(f"{label} contains secret-like material")
                visit(child, depth + 1)
            return
        if isinstance(item, list):
            if len(item) > MAX_JSON_CONTAINER_ITEMS:
                raise BetaReadinessError(f"{label} array contains too many values")
            for child in item:
                visit(child, depth + 1)
            return
        if isinstance(item, str):
            if contains_secret_like(item):
                raise BetaReadinessError(f"{label} contains secret-like material")
            if len(item) > MAX_JSON_STRING or _CONTROL.search(item):
                raise BetaReadinessError(f"{label} contains an invalid string")
            return
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int) and not isinstance(item, bool):
            return
        raise BetaReadinessError(f"{label} contains an unsupported JSON value")

    visit(value, 0)


def _decode_json(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except BetaReadinessError:
        raise
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise BetaReadinessError(
            f"{label} is not strict bounded UTF-8 JSON: {exc}"
        ) from exc
    _validate_json_tree(value, label=label)
    if not isinstance(value, dict):
        raise BetaReadinessError(f"{label} root must be an object")
    return value


def _safe_relative(value: str, *, label: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or "\\" in value
        or _CONTROL.search(value)
        or contains_secret_like(value)
    ):
        raise BetaReadinessError(f"{label} must be a bounded POSIX relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise BetaReadinessError(
            f"{label} must be a normalized repository-relative path"
        )
    return path


def _identity(metadata: os.stat_result, *, stable_file: bool) -> tuple[int, ...]:
    base = (metadata.st_dev, metadata.st_ino, metadata.st_mode)
    if not stable_file:
        return base
    return (*base, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


class SafeRepositoryReader:
    """Root-fd-anchored, no-follow reader with post-read identity checks."""

    def __init__(self, project: Path) -> None:
        requested = project.expanduser()
        try:
            requested_metadata = requested.lstat()
            resolved = requested.resolve(strict=True)
        except OSError as exc:
            raise BetaReadinessError(f"project is unavailable: {exc}") from exc
        if stat.S_ISLNK(requested_metadata.st_mode) or not stat.S_ISDIR(
            requested_metadata.st_mode
        ):
            raise BetaReadinessError("project must be a non-symlink directory")
        if resolved != requested.absolute():
            raise BetaReadinessError(
                "project path must not traverse ambiguous or symbolic-link components"
            )
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        nonblocking = getattr(os, "O_NONBLOCK", 0)
        if not no_follow or not directory or not nonblocking:
            raise BetaReadinessError(
                "secure no-follow and nonblocking opens are unavailable"
            )
        self.root = resolved
        self._directory_flags = (
            os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)
        )
        self._file_flags = (
            os.O_RDONLY | no_follow | nonblocking | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            self._root_fd = os.open(self.root, self._directory_flags)
            opened = os.fstat(self._root_fd)
            named = self.root.lstat()
        except OSError as exc:
            descriptor = getattr(self, "_root_fd", -1)
            if descriptor >= 0:
                os.close(descriptor)
                self._root_fd = -1
            raise BetaReadinessError(f"cannot anchor project root: {exc}") from exc
        if _identity(opened, stable_file=False) != _identity(named, stable_file=False):
            os.close(self._root_fd)
            raise BetaReadinessError("project root changed while it was opened")
        self._root_identity = _identity(opened, stable_file=False)

    def __enter__(self) -> "SafeRepositoryReader":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        descriptor = getattr(self, "_root_fd", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._root_fd = -1

    def _verify_root(self) -> None:
        try:
            opened = os.fstat(self._root_fd)
            named = self.root.lstat()
        except OSError as exc:
            raise BetaReadinessError(
                f"project root changed during evaluation: {exc}"
            ) from exc
        if (
            _identity(opened, stable_file=False) != self._root_identity
            or _identity(named, stable_file=False) != self._root_identity
        ):
            raise BetaReadinessError("project root changed during evaluation")

    def read_regular(self, relative: str, *, limit: int, label: str) -> bytes:
        pure = _safe_relative(relative, label=label)
        directories: list[int] = []
        file_descriptor = -1
        try:
            directories.append(os.dup(self._root_fd))
            for part in pure.parts[:-1]:
                try:
                    child = os.open(part, self._directory_flags, dir_fd=directories[-1])
                except FileNotFoundError as exc:
                    raise RepositoryPathMissing(f"{label} is absent") from exc
                except OSError as exc:
                    raise BetaReadinessError(
                        f"{label} traverses an unsafe component"
                    ) from exc
                directories.append(child)
                opened = os.fstat(child)
                named = os.stat(part, dir_fd=directories[-2], follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(named.st_mode)
                    or _identity(opened, stable_file=False)
                    != _identity(named, stable_file=False)
                ):
                    raise BetaReadinessError(
                        f"{label} traverses a symlink or non-directory"
                    )
            name = pure.parts[-1]
            try:
                file_descriptor = os.open(
                    name, self._file_flags, dir_fd=directories[-1]
                )
            except FileNotFoundError as exc:
                raise RepositoryPathMissing(f"{label} is absent") from exc
            except OSError as exc:
                raise BetaReadinessError(f"cannot open {label}") from exc
            before = os.fstat(file_descriptor)
            named_before = os.stat(name, dir_fd=directories[-1], follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(named_before.st_mode)
                or _identity(before, stable_file=False)
                != _identity(named_before, stable_file=False)
            ):
                raise BetaReadinessError(f"{label} is not a stable regular file")
            if before.st_size > limit:
                raise BetaReadinessError(f"{label} exceeds {limit} bytes")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(file_descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(file_descriptor)
            named_after = os.stat(name, dir_fd=directories[-1], follow_symlinks=False)
            if len(payload) > limit:
                raise BetaReadinessError(f"{label} exceeds {limit} bytes")
            if (
                len(payload) != after.st_size
                or _identity(before, stable_file=True)
                != _identity(after, stable_file=True)
                or _identity(after, stable_file=False)
                != _identity(named_after, stable_file=False)
            ):
                raise BetaReadinessError(f"{label} changed while it was read")
            for index, part in enumerate(pure.parts[:-1]):
                opened = os.fstat(directories[index + 1])
                named = os.stat(part, dir_fd=directories[index], follow_symlinks=False)
                if stat.S_ISLNK(named.st_mode) or _identity(
                    opened, stable_file=False
                ) != _identity(named, stable_file=False):
                    raise BetaReadinessError(
                        f"{label} parent changed while it was read"
                    )
            self._verify_root()
            return payload
        except RepositoryPathMissing:
            raise
        except BetaReadinessError:
            raise
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise RepositoryPathMissing(f"{label} is absent") from exc
            raise BetaReadinessError(f"cannot safely read {label}") from exc
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)
            for descriptor in reversed(directories):
                os.close(descriptor)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill the isolated Git process group and reap its direct child."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    label: str,
    timeout: float = 10,
    stdout_limit: int = MAX_DOCUMENT_BYTES,
    stderr_limit: int = MAX_GIT_STDERR_BYTES,
) -> bytes:
    if GIT_EXECUTABLE is None:
        raise BetaReadinessError("Git is unavailable")
    if timeout <= 0 or stdout_limit < 0 or stderr_limit < 0:
        raise BetaReadinessError("Git resource bounds are invalid")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "protocol.allow",
        "GIT_CONFIG_VALUE_0": "never",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "NO_COLOR": "1",
        "TERM": "dumb",
    }
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    streams: dict[int, tuple[str, int, bytearray]] = {}
    try:
        process = subprocess.Popen(
            [GIT_EXECUTABLE, "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
            close_fds=True,
        )
        assert process.stdout is not None and process.stderr is not None
        for name, stream, limit in (
            ("stdout", process.stdout, stdout_limit),
            ("stderr", process.stderr, stderr_limit),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
            streams[stream.fileno()] = (name, limit, bytearray())

        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise BetaReadinessError(f"Git timed out while reading {label}")
            events = selector.select(remaining)
            if not events:
                _kill_process_group(process)
                raise BetaReadinessError(f"Git timed out while reading {label}")
            for key, _ in events:
                descriptor = key.fileobj.fileno()
                name, limit, buffer = streams[descriptor]
                try:
                    chunk = os.read(descriptor, min(64 * 1024, limit - len(buffer) + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > limit:
                    _kill_process_group(process)
                    raise BetaReadinessError(
                        f"Git {name} exceeds {limit} bytes while reading {label}"
                    )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_process_group(process)
            raise BetaReadinessError(f"Git timed out while reading {label}")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _kill_process_group(process)
            raise BetaReadinessError(f"Git timed out while reading {label}") from exc
    except BetaReadinessError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        if process is not None:
            _kill_process_group(process)
        raise BetaReadinessError(f"cannot read {label} from Git") from exc
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    stdout = bytes(next(value[2] for value in streams.values() if value[0] == "stdout"))
    stderr = bytes(next(value[2] for value in streams.values() if value[0] == "stderr"))
    if return_code != 0:
        # Git stderr can include repository-controlled path or configuration
        # text. Its bytes are intentionally consumed but never reflected.
        del stderr
        raise BetaReadinessError(f"cannot read {label} from exact candidate")
    return stdout


def _head_commit(root: Path) -> str:
    raw = _git(
        root,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        label="HEAD commit",
        stdout_limit=128,
    )
    try:
        commit = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise BetaReadinessError("Git returned a non-ASCII candidate commit") from exc
    if _COMMIT.fullmatch(commit) is None:
        raise BetaReadinessError("Git returned an invalid candidate commit")
    return commit


def _git_blob(root: Path, candidate: str, relative: str, *, limit: int) -> bytes:
    path = _safe_relative(relative, label="document path")
    path_text = path.as_posix()
    tree_raw = _git(
        root,
        [
            "ls-tree",
            "-z",
            "--full-tree",
            candidate,
            "--",
            f":(literal){path_text}",
        ],
        label="exact candidate document",
        stdout_limit=1024,
    )
    records = [record for record in tree_raw.split(b"\0") if record]
    if len(records) != 1:
        raise BetaReadinessError("exact candidate document is absent or ambiguous")
    try:
        metadata, raw_path = records[0].split(b"\t", 1)
        raw_mode, raw_kind, raw_object = metadata.split(b" ", 2)
        mode = raw_mode.decode("ascii")
        kind = raw_kind.decode("ascii")
        object_id = raw_object.decode("ascii")
        returned_path = raw_path.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise BetaReadinessError("Git returned a malformed exact tree entry") from exc
    if returned_path != path_text:
        raise BetaReadinessError("Git returned the wrong exact tree path")
    if mode not in {"100644", "100755"} or kind != "blob":
        raise BetaReadinessError("exact candidate document must be a regular Git file")
    if _COMMIT.fullmatch(object_id) is None:
        raise BetaReadinessError("Git returned an invalid exact-candidate blob id")
    size_raw = _git(
        root,
        ["cat-file", "-s", object_id],
        label="exact candidate document",
        stdout_limit=64,
    )
    try:
        size = int(size_raw.decode("ascii").strip())
    except (UnicodeError, ValueError) as exc:
        raise BetaReadinessError("Git returned an invalid blob size") from exc
    if size < 0 or size > limit:
        raise BetaReadinessError(
            f"exact candidate document exceeds {limit} bytes"
        )
    payload = _git(
        root,
        ["cat-file", "blob", object_id],
        label="exact candidate document",
        stdout_limit=limit,
    )
    if len(payload) != size:
        raise BetaReadinessError("Git blob size changed for exact candidate document")
    return payload


def _project_version_from_pyproject(payload: bytes) -> str:
    """Read one static numeric ``project.version`` without a TOML dependency.

    Startup Factory supports Python 3.10, where ``tomllib`` is unavailable.  The
    release contract intentionally permits only the simple, static assignment
    used by this repository and fails closed for dynamic or ambiguous metadata.
    """

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BetaReadinessError("exact candidate pyproject.toml is not UTF-8") from exc
    in_project = False
    version: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                raise BetaReadinessError("exact candidate pyproject.toml has an invalid table")
            in_project = line == "[project]"
            continue
        if not in_project or not re.match(r"version\s*=", line):
            continue
        match = re.fullmatch(
            r'version\s*=\s*"(\d+\.\d+\.\d+)"(?:\s*#.*)?', line
        )
        if match is None or version is not None:
            raise BetaReadinessError(
                "exact candidate project.version must be one static numeric SemVer"
            )
        version = match.group(1)
    if version is None or _VERSION.fullmatch(version) is None:
        raise BetaReadinessError(
            "exact candidate pyproject.toml has no static numeric project.version"
        )
    return version


def _candidate_version(root: Path, candidate: str) -> str:
    return _project_version_from_pyproject(
        _git_blob(root, candidate, "pyproject.toml", limit=64 * 1024)
    )


def _parse_timestamp(value: object, *, label: str) -> dt.datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise BetaReadinessError(
            f"{label} must use UTC format YYYY-MM-DDTHH:MM:SS[.mmm]Z"
        )
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BetaReadinessError(f"{label} is not a valid UTC timestamp") from exc


def _exact_keys(value: Mapping[str, Any], expected: set[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise BetaReadinessError(f"{label} has invalid keys: {'; '.join(details)}")


def _text(value: object, *, label: str, maximum: int = 1000) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or _CONTROL.search(value)
        or contains_secret_like(value)
    ):
        raise BetaReadinessError(f"{label} must contain 1 to {maximum} safe characters")
    return value


def _identifies_wsl(value: str, *, microsoft_marker: bool = False) -> bool:
    """Return whether a bounded environment identity declares WSL."""

    folded = value.casefold()
    parts = re.findall(r"[a-z0-9]+", folded)
    tokens = set(parts)
    return (
        (microsoft_marker and "microsoft" in tokens)
        or any(
            token == "wsl" or (token.startswith("wsl") and token[3:].isdigit())
            for token in tokens
        )
        or "windows subsystem for linux" in " ".join(parts)
    )


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise BetaReadinessError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _nonnegative_int(
    value: object,
    *,
    label: str,
    positive: bool = False,
    maximum: int | None = None,
) -> int:
    if type(value) is not int or value < (1 if positive else 0):
        qualifier = "positive" if positive else "non-negative"
        raise BetaReadinessError(f"{label} must be a {qualifier} integer")
    if maximum is not None and value > maximum:
        raise BetaReadinessError(f"{label} exceeds the permitted maximum {maximum}")
    return value


def _validate_release_set(
    value: object, *, label: str, expected_version: str
) -> str:
    if not isinstance(value, dict):
        raise BetaReadinessError(f"{label} must be an object")
    _exact_keys(
        value,
        {"schemaVersion", "artifacts", "sha256"},
        label=label,
    )
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        raise BetaReadinessError(f"{label} schemaVersion must equal 1")
    artifacts = value["artifacts"]
    expected_kinds = ("bundle", "wheel", "sdist")
    if not isinstance(artifacts, list) or len(artifacts) != len(expected_kinds):
        raise BetaReadinessError(f"{label} must contain bundle, wheel, and sdist")
    normalized: list[dict[str, str]] = []
    names: set[str] = set()
    digests: set[str] = set()
    versions: set[str] = set()
    for index, (artifact, expected_kind) in enumerate(zip(artifacts, expected_kinds)):
        artifact_label = f"{label} artifact {index}"
        if not isinstance(artifact, dict):
            raise BetaReadinessError(f"{artifact_label} must be an object")
        _exact_keys(artifact, {"kind", "name", "sha256"}, label=artifact_label)
        if artifact["kind"] != expected_kind:
            raise BetaReadinessError(
                f"{artifact_label} kind must be exactly {expected_kind}"
            )
        name = artifact["name"]
        if not isinstance(name, str) or _ARTIFACT_NAME.fullmatch(name) is None:
            raise BetaReadinessError(f"{artifact_label} name is invalid")
        pattern = {
            "bundle": _BUNDLE_NAME,
            "wheel": _WHEEL_NAME,
            "sdist": _SDIST_NAME,
        }[expected_kind]
        match = pattern.fullmatch(name)
        if match is None:
            raise BetaReadinessError(
                f"{artifact_label} has an invalid {expected_kind} name"
            )
        versions.add(match.group(1))
        if name in names:
            raise BetaReadinessError(f"{label} artifact names must be distinct")
        digest = _sha256(artifact["sha256"], label=f"{artifact_label} sha256")
        if digest in digests:
            raise BetaReadinessError(f"{label} artifact digests must be distinct")
        names.add(name)
        digests.add(digest)
        normalized.append({"kind": expected_kind, "name": name, "sha256": digest})
    if len(versions) != 1:
        raise BetaReadinessError(f"{label} artifact versions must match")
    if versions != {expected_version}:
        actual = next(iter(versions))
        raise BetaReadinessError(
            f"{label} artifact version {actual} does not match exact candidate "
            f"project.version {expected_version}"
        )
    manifest = {"schemaVersion": 1, "artifacts": normalized}
    calculated = hashlib.sha256(
        json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()
    claimed = _sha256(value["sha256"], label=f"{label} sha256")
    if claimed != calculated:
        raise BetaReadinessError(f"{label} sha256 does not match its canonical manifest")
    return claimed


def _producer(value: object, *, expected_role: str, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BetaReadinessError(f"{label} producer must be an object")
    _exact_keys(value, {"identity", "role"}, label=f"{label} producer")
    identity = value["identity"]
    role = value["role"]
    if not isinstance(identity, str) or _PRODUCER_ID.fullmatch(identity) is None:
        raise BetaReadinessError(f"{label} producer identity is invalid")
    if role != expected_role:
        raise BetaReadinessError(
            f"{label} producer role must be exactly {expected_role}"
        )
    return {"identity": identity, "role": role}


def _validate_private_disclosure(payload: Mapping[str, Any]) -> str | None:
    _exact_keys(
        payload,
        {"channel", "intakeVerified", "acknowledgementVerified", "secretFreeTest"},
        label="private-disclosure payload",
    )
    if payload["channel"] != "github-private-vulnerability-reporting":
        raise BetaReadinessError("private-disclosure channel is unsupported")
    for key in ("intakeVerified", "acknowledgementVerified", "secretFreeTest"):
        if payload[key] is not True:
            raise BetaReadinessError(f"private-disclosure {key} must be true")
    return None


def _validate_full_validation(
    payload: Mapping[str, Any], *, expected_version: str
) -> str:
    _exact_keys(
        payload,
        {"cleanCheckout", "checks", "releaseSet"},
        label="full-validation payload",
    )
    if payload["cleanCheckout"] is not True:
        raise BetaReadinessError("full-validation must come from a clean checkout")
    checks = payload["checks"]
    if not isinstance(checks, list) or len(checks) != len(
        CANONICAL_VALIDATION_CHECKS
    ):
        raise BetaReadinessError(
            "full-validation requires the runtime, packaging-source, and "
            "built-distribution checks"
        )
    for index, (check, expected) in enumerate(
        zip(checks, CANONICAL_VALIDATION_CHECKS)
    ):
        label = f"full-validation check {index}"
        if not isinstance(check, dict):
            raise BetaReadinessError(f"{label} must be an object")
        _exact_keys(
            check,
            {
                "id",
                "argv",
                "requiredEnvironment",
                "exitCode",
                "testsPassed",
                "testsFailed",
                "testsSkipped",
            },
            label=label,
        )
        expected_id, expected_argv, expected_environment = expected
        if check["id"] != expected_id:
            raise BetaReadinessError(f"{label} id must be exactly {expected_id}")
        if check["argv"] != list(expected_argv):
            raise BetaReadinessError(f"{label} argv does not match the canonical check")
        if check["requiredEnvironment"] != list(expected_environment):
            raise BetaReadinessError(
                f"{label} requiredEnvironment does not match the canonical check"
            )
        if type(check["exitCode"]) is not int or check["exitCode"] != 0:
            raise BetaReadinessError(f"{label} exitCode must be integer zero")
        _nonnegative_int(check["testsPassed"], label=f"{label} testsPassed", positive=True)
        if type(check["testsFailed"]) is not int or check["testsFailed"] != 0:
            raise BetaReadinessError(f"{label} testsFailed must be integer zero")
        _nonnegative_int(check["testsSkipped"], label=f"{label} testsSkipped")
    return _validate_release_set(
        payload["releaseSet"],
        label="full-validation releaseSet",
        expected_version=expected_version,
    )


def _validate_reproducible_package(
    payload: Mapping[str, Any], *, expected_version: str
) -> str:
    _exact_keys(payload, {"builds"}, label="reproducible-package payload")
    builds = payload["builds"]
    if not isinstance(builds, list) or len(builds) != 2:
        raise BetaReadinessError("reproducible-package requires exactly two builds")
    release_set_digests: list[str] = []
    build_ids: set[str] = set()
    expected = {"buildId", "cleanCheckout", "releaseSet"}
    for index, build in enumerate(builds):
        label = f"reproducible-package build {index}"
        if not isinstance(build, dict):
            raise BetaReadinessError(f"{label} must be an object")
        _exact_keys(build, expected, label=label)
        build_id = build["buildId"]
        if not isinstance(build_id, str) or _RUN_ID.fullmatch(build_id) is None:
            raise BetaReadinessError(f"{label} buildId is invalid")
        if build_id in build_ids:
            raise BetaReadinessError(
                "reproducible-package buildId values must be distinct"
            )
        build_ids.add(build_id)
        if build["cleanCheckout"] is not True:
            raise BetaReadinessError(f"{label} must come from a clean checkout")
        release_set_digests.append(
            _validate_release_set(
                build["releaseSet"],
                label=f"{label} releaseSet",
                expected_version=expected_version,
            )
        )
    if release_set_digests[0] != release_set_digests[1]:
        raise BetaReadinessError(
            "reproducible-package release sets differ between clean builds"
        )
    return release_set_digests[0]


def _validate_reviews(
    payload: Mapping[str, Any],
    *,
    observed_at: dt.datetime,
    cutoff: dt.datetime,
    expected_version: str,
) -> str:
    _exact_keys(
        payload, {"releaseSet", "reviews"}, label="exact-package-review payload"
    )
    release_set = _validate_release_set(
        payload["releaseSet"],
        label="exact-package-review releaseSet",
        expected_version=expected_version,
    )
    reviews = payload["reviews"]
    required_roles = {
        "principal-software-architect",
        "sceptical-architect",
        "senior-qa-engineer",
        "senior-security-engineer",
    }
    if not isinstance(reviews, list) or len(reviews) != len(required_roles):
        raise BetaReadinessError("exact-package-review requires exactly four reviews")
    roles: set[str] = set()
    identities: set[str] = set()
    for index, review in enumerate(reviews):
        label = f"exact-package review {index}"
        if not isinstance(review, dict):
            raise BetaReadinessError(f"{label} must be an object")
        _exact_keys(review, {"role", "identity", "decision", "reviewedAt"}, label=label)
        role = review["role"]
        identity = review["identity"]
        if not isinstance(role, str) or role not in required_roles or role in roles:
            raise BetaReadinessError(
                f"{label} role is missing, duplicated, or unsupported"
            )
        if not isinstance(identity, str) or _PRODUCER_ID.fullmatch(identity) is None:
            raise BetaReadinessError(f"{label} identity is invalid")
        if identity in identities:
            raise BetaReadinessError(
                "exact-package reviewers must have distinct identities"
            )
        if review["decision"] != "approve":
            raise BetaReadinessError(f"{label} decision must be approve")
        reviewed = _parse_timestamp(review["reviewedAt"], label=f"{label} reviewedAt")
        if reviewed < cutoff or reviewed > observed_at:
            raise BetaReadinessError(
                f"{label} timestamp must be fresh and no later than artifact observation"
            )
        roles.add(role)
        identities.add(identity)
    if roles != required_roles:
        raise BetaReadinessError("exact-package-review is missing a mandatory role")
    return release_set


def _validate_compatibility(
    payload: Mapping[str, Any],
    *,
    candidate: str,
    observed_at: dt.datetime,
    cutoff: dt.datetime,
    expected_version: str,
) -> str:
    _exact_keys(
        payload,
        {"releaseSet", "results"},
        label="exact-candidate compatibility payload",
    )
    release_set = _validate_release_set(
        payload["releaseSet"],
        label="exact-candidate compatibility releaseSet",
        expected_version=expected_version,
    )
    results = payload["results"]
    required_scopes = {
        "10": "installed-release-smoke",
        "14": "full-runtime-package",
    }
    if not isinstance(results, list) or len(results) != len(required_scopes):
        raise BetaReadinessError(
            "exact-candidate compatibility requires exactly Python 3.10 and 3.14 results"
        )
    observed_minors: set[str] = set()
    environment_ids: set[str] = set()
    environment_digests: set[str] = set()
    raw_digests: set[str] = set()
    for index, result in enumerate(results):
        label = f"exact-candidate compatibility result {index}"
        if not isinstance(result, dict):
            raise BetaReadinessError(f"{label} must be an object")
        _exact_keys(
            result,
            {
                "environmentId",
                "classification",
                "candidateCommit",
                "releaseSetSha256",
                "platform",
                "operatingSystem",
                "architecture",
                "pythonVersion",
                "gitVersion",
                "bashVersion",
                "validationScope",
                "observedAt",
                "exitCode",
                "testsPassed",
                "testsFailed",
                "testsSkipped",
                "environmentManifestSha256",
                "rawEvidenceSha256",
            },
            label=label,
        )
        environment_id = result["environmentId"]
        if (
            not isinstance(environment_id, str)
            or _RUN_ID.fullmatch(environment_id) is None
            or environment_id in environment_ids
        ):
            raise BetaReadinessError(f"{label} environmentId is invalid or duplicated")
        environment_ids.add(environment_id)
        if result["classification"] != "tested":
            raise BetaReadinessError(f"{label} classification must be exactly tested")
        if result["candidateCommit"] != candidate:
            raise BetaReadinessError(f"{label} candidateCommit does not bind exact HEAD")
        if result["releaseSetSha256"] != release_set:
            raise BetaReadinessError(f"{label} does not bind the exact release set")
        if result["platform"] != "linux":
            raise BetaReadinessError(f"{label} platform must be exactly linux")
        operating_system = _text(
            result["operatingSystem"],
            label=f"{label} operatingSystem",
            maximum=160,
        )
        for identity_field, identity_value, microsoft_marker in (
            ("environmentId", environment_id, False),
            ("operatingSystem", operating_system, True),
        ):
            if _identifies_wsl(
                identity_value, microsoft_marker=microsoft_marker
            ):
                raise BetaReadinessError(
                    f"{label} {identity_field} identifies WSL; required Linux "
                    "compatibility evidence excludes experimental WSL environments"
                )
        for key, maximum in (
            ("architecture", 64),
            ("gitVersion", 96),
            ("bashVersion", 96),
        ):
            _text(result[key], label=f"{label} {key}", maximum=maximum)
        python_version = result["pythonVersion"]
        if not isinstance(python_version, str):
            raise BetaReadinessError(f"{label} pythonVersion is invalid")
        version_match = _PYTHON_VERSION.fullmatch(python_version)
        if version_match is None:
            raise BetaReadinessError(
                f"{label} pythonVersion must be a stable Python 3.10.x or 3.14.x version"
            )
        minor = version_match.group(1)
        if minor in observed_minors:
            raise BetaReadinessError(
                "exact-candidate compatibility Python minors must be distinct"
            )
        observed_minors.add(minor)
        if result["validationScope"] != required_scopes[minor]:
            raise BetaReadinessError(
                f"{label} validationScope does not match Python 3.{minor}"
            )
        timestamp = _parse_timestamp(
            result["observedAt"], label=f"{label} observedAt"
        )
        if timestamp < cutoff or timestamp > observed_at:
            raise BetaReadinessError(
                f"{label} timestamp must be fresh and no later than artifact observation"
            )
        if type(result["exitCode"]) is not int or result["exitCode"] != 0:
            raise BetaReadinessError(f"{label} exitCode must be integer zero")
        _nonnegative_int(
            result["testsPassed"], label=f"{label} testsPassed", positive=True
        )
        if type(result["testsFailed"]) is not int or result["testsFailed"] != 0:
            raise BetaReadinessError(f"{label} testsFailed must be integer zero")
        _nonnegative_int(result["testsSkipped"], label=f"{label} testsSkipped")
        environment_digest = _sha256(
            result["environmentManifestSha256"],
            label=f"{label} environmentManifestSha256",
        )
        raw_digest = _sha256(
            result["rawEvidenceSha256"], label=f"{label} rawEvidenceSha256"
        )
        if environment_digest in environment_digests:
            raise BetaReadinessError(
                "exact-candidate compatibility environment manifests must be distinct"
            )
        if raw_digest in raw_digests:
            raise BetaReadinessError(
                "exact-candidate compatibility raw evidence must be distinct"
            )
        environment_digests.add(environment_digest)
        raw_digests.add(raw_digest)
    if observed_minors != set(required_scopes):
        raise BetaReadinessError(
            "exact-candidate compatibility is missing Python 3.10 or 3.14"
        )
    return release_set


def _validate_walkthrough(
    payload: Mapping[str, Any],
    *,
    candidate: str,
    observed_at: dt.datetime,
    cutoff: dt.datetime,
    expected_version: str,
) -> tuple[str, dict[str, str]]:
    _exact_keys(
        payload,
        {
            "releaseSet",
            "candidateCommit",
            "fixture",
            "profileDecision",
            "selectedPack",
            "reviewOutcome",
            "integrationOutcome",
            "authority",
            "startedAt",
            "completedAt",
            "durationMs",
            "rawEvidenceSha256",
        },
        label="governed-walkthrough payload",
    )
    release_set = _validate_release_set(
        payload["releaseSet"],
        label="governed-walkthrough releaseSet",
        expected_version=expected_version,
    )
    if payload["candidateCommit"] != candidate:
        raise BetaReadinessError(
            "governed-walkthrough candidateCommit does not bind exact HEAD"
        )
    fixture = payload["fixture"]
    if not isinstance(fixture, dict):
        raise BetaReadinessError("governed-walkthrough fixture must be an object")
    _exact_keys(
        fixture,
        {"fixtureCommit", "taskId", "changedFiles", "environmentManifestSha256"},
        label="governed-walkthrough fixture",
    )
    if (
        not isinstance(fixture["fixtureCommit"], str)
        or _COMMIT.fullmatch(fixture["fixtureCommit"]) is None
    ):
        raise BetaReadinessError("governed-walkthrough fixtureCommit is invalid")
    if not isinstance(fixture["taskId"], str) or _RUN_ID.fullmatch(fixture["taskId"]) is None:
        raise BetaReadinessError("governed-walkthrough taskId is invalid")
    if fixture["changedFiles"] != ["README.md"]:
        raise BetaReadinessError(
            "governed-walkthrough fixture changedFiles must be exactly README.md"
        )
    environment_digest = _sha256(
        fixture["environmentManifestSha256"],
        label="governed-walkthrough environmentManifestSha256",
    )

    decision = payload["profileDecision"]
    if not isinstance(decision, dict):
        raise BetaReadinessError(
            "governed-walkthrough profileDecision must be an object"
        )
    _exact_keys(
        decision,
        {
            "profile",
            "decisionSha256",
            "changedFiles",
            "reviewGates",
            "exactPackageRequired",
            "coreReviewRequired",
        },
        label="governed-walkthrough profileDecision",
    )
    if decision["profile"] != "micro":
        raise BetaReadinessError(
            "governed-walkthrough profileDecision profile must be exactly micro"
        )
    _sha256(
        decision["decisionSha256"],
        label="governed-walkthrough profileDecision decisionSha256",
    )
    if decision["changedFiles"] != fixture["changedFiles"]:
        raise BetaReadinessError(
            "governed-walkthrough profileDecision changedFiles contradict the fixture"
        )
    if decision["reviewGates"] != []:
        raise BetaReadinessError(
            "governed-walkthrough micro profile must declare no supporting review gates"
        )
    for key in ("exactPackageRequired", "coreReviewRequired"):
        if decision[key] is not True:
            raise BetaReadinessError(
                f"governed-walkthrough profileDecision {key} must be true"
            )

    selected_pack = payload["selectedPack"]
    if not isinstance(selected_pack, dict):
        raise BetaReadinessError(
            "governed-walkthrough selectedPack must be an object"
        )
    _exact_keys(
        selected_pack,
        {
            "packId",
            "packSha256",
            "planSha256",
            "validationStatus",
            "doctorConfiguredStatus",
            "doctorProofStatus",
        },
        label="governed-walkthrough selectedPack",
    )
    if selected_pack["packId"] != "tracker-markdown":
        raise BetaReadinessError(
            "governed-walkthrough selectedPack packId must be tracker-markdown"
        )
    pack_digest = _sha256(
        selected_pack["packSha256"],
        label="governed-walkthrough selectedPack packSha256",
    )
    _sha256(
        selected_pack["planSha256"],
        label="governed-walkthrough selectedPack planSha256",
    )
    expected_pack_statuses = {
        "validationStatus": "pass",
        "doctorConfiguredStatus": "configured",
        "doctorProofStatus": "unknown",
    }
    for key, expected in expected_pack_statuses.items():
        if selected_pack[key] != expected:
            raise BetaReadinessError(
                f"governed-walkthrough selectedPack {key} must be exactly {expected}"
            )

    review = payload["reviewOutcome"]
    if not isinstance(review, dict):
        raise BetaReadinessError(
            "governed-walkthrough reviewOutcome must be an object"
        )
    _exact_keys(
        review,
        {
            "status",
            "reviewReceiptSchemaVersion",
            "reviewEvidenceSchemaVersion",
            "reviewPackageSha256",
            "approvalEvidenceSha256",
            "publicationReceipts",
        },
        label="governed-walkthrough reviewOutcome",
    )
    if review["status"] != "approved":
        raise BetaReadinessError(
            "governed-walkthrough reviewOutcome status must be approved"
        )
    if review["reviewReceiptSchemaVersion"] != 2:
        raise BetaReadinessError(
            "governed-walkthrough reviewReceiptSchemaVersion must equal 2"
        )
    if review["reviewEvidenceSchemaVersion"] != 8:
        raise BetaReadinessError(
            "governed-walkthrough reviewEvidenceSchemaVersion must equal 8"
        )
    review_package_digest = _sha256(
        review["reviewPackageSha256"],
        label="governed-walkthrough reviewPackageSha256",
    )
    approval_evidence_digest = _sha256(
        review["approvalEvidenceSha256"],
        label="governed-walkthrough approvalEvidenceSha256",
    )
    review_digests = {review_package_digest, approval_evidence_digest}
    if len(review_digests) != 2:
        raise BetaReadinessError(
            "governed-walkthrough review package and approval evidence digests must be distinct"
        )
    receipts = review["publicationReceipts"]
    receipt_markers = {
        "review-request",
        "team-lead-approval",
        "architecture-approval",
        "sceptical-architecture-approval",
    }
    if not isinstance(receipts, dict):
        raise BetaReadinessError(
            "governed-walkthrough publicationReceipts must be an object"
        )
    _exact_keys(receipts, receipt_markers, label="governed-walkthrough publicationReceipts")
    receipt_digests = {
        _sha256(value, label=f"governed-walkthrough {marker} receipt")
        for marker, value in receipts.items()
    }
    if len(receipt_digests) != len(receipt_markers):
        raise BetaReadinessError(
            "governed-walkthrough publication receipt digests must be distinct"
        )
    if review_digests & receipt_digests:
        raise BetaReadinessError(
            "governed-walkthrough review and receipt digests must be distinct"
        )

    integration = payload["integrationOutcome"]
    if not isinstance(integration, dict):
        raise BetaReadinessError(
            "governed-walkthrough integrationOutcome must be an object"
        )
    _exact_keys(
        integration,
        {
            "status",
            "transactionSchemaVersion",
            "transactionId",
            "commit",
            "reviewPackageSha256",
            "approvalEvidenceSha256",
            "transactionSha256",
        },
        label="governed-walkthrough integrationOutcome",
    )
    if integration["status"] != "completed":
        raise BetaReadinessError(
            "governed-walkthrough integrationOutcome status must be completed"
        )
    if integration["transactionSchemaVersion"] != 2:
        raise BetaReadinessError(
            "governed-walkthrough integration transactionSchemaVersion must equal 2"
        )
    if (
        not isinstance(integration["transactionId"], str)
        or _INTEGRATION_ID.fullmatch(integration["transactionId"]) is None
    ):
        raise BetaReadinessError(
            "governed-walkthrough integrationOutcome transactionId is invalid"
        )
    if (
        not isinstance(integration["commit"], str)
        or _COMMIT.fullmatch(integration["commit"]) is None
    ):
        raise BetaReadinessError(
            "governed-walkthrough integrationOutcome commit is invalid"
        )
    if integration["reviewPackageSha256"] != review_package_digest:
        raise BetaReadinessError(
            "governed-walkthrough integrationOutcome does not bind the reviewed package"
        )
    if integration["approvalEvidenceSha256"] != approval_evidence_digest:
        raise BetaReadinessError(
            "governed-walkthrough integrationOutcome does not bind the authenticated approval evidence"
        )
    transaction_digest = _sha256(
        integration["transactionSha256"],
        label="governed-walkthrough integrationOutcome transactionSha256",
    )
    if transaction_digest in review_digests or transaction_digest in receipt_digests:
        raise BetaReadinessError(
            "governed-walkthrough integration transaction digest must be distinct"
        )

    authority = payload["authority"]
    if not isinstance(authority, dict):
        raise BetaReadinessError("governed-walkthrough authority must be an object")
    authority_keys = {
        "releaseEnabled",
        "deploymentEnabled",
        "releaseAttempted",
        "deploymentAttempted",
    }
    _exact_keys(authority, authority_keys, label="governed-walkthrough authority")
    if any(authority[key] is not False for key in authority_keys):
        raise BetaReadinessError(
            "governed-walkthrough release and deployment must remain disabled and unattempted"
        )

    started = _parse_timestamp(
        payload["startedAt"], label="governed-walkthrough startedAt"
    )
    completed = _parse_timestamp(
        payload["completedAt"], label="governed-walkthrough completedAt"
    )
    if started < cutoff or completed > observed_at or completed <= started:
        raise BetaReadinessError(
            "governed-walkthrough timestamps must be fresh, ordered, and no later than artifact observation"
        )
    duration = _nonnegative_int(
        payload["durationMs"],
        label="governed-walkthrough durationMs",
        positive=True,
        maximum=86_400_000,
    )
    elapsed = completed - started
    calculated = (
        elapsed.days * 86_400_000
        + elapsed.seconds * 1000
        + elapsed.microseconds // 1000
    )
    if duration != calculated:
        raise BetaReadinessError(
            "governed-walkthrough durationMs does not match its timestamps"
        )
    _sha256(
        payload["rawEvidenceSha256"],
        label="governed-walkthrough rawEvidenceSha256",
    )
    bindings = {
        "fixtureCommit": fixture["fixtureCommit"],
        "taskId": fixture["taskId"],
        "packId": selected_pack["packId"],
        "packSha256": pack_digest,
        "environmentManifestSha256": environment_digest,
    }
    return release_set, bindings


def _nearest_rank(values: Sequence[int], percentile: int) -> int:
    ordered = sorted(values)
    rank = math.ceil(percentile / 100 * len(ordered))
    return ordered[rank - 1]


def _validate_benchmark(
    payload: Mapping[str, Any],
    *,
    observed_at: dt.datetime,
    cutoff: dt.datetime,
    expected_version: str,
) -> tuple[str, dict[str, str]]:
    _exact_keys(
        payload,
        {
            "releaseSet",
            "fixture",
            "allAttemptsRecorded",
            "percentileMethod",
            "targetMs",
            "coldRuns",
            "warmRuns",
            "failures",
            "coldP50Ms",
            "coldP95Ms",
            "warmP50Ms",
            "warmP95Ms",
        },
        label="delivery-benchmark payload",
    )
    release_set = _validate_release_set(
        payload["releaseSet"],
        label="delivery-benchmark releaseSet",
        expected_version=expected_version,
    )
    fixture = payload["fixture"]
    if not isinstance(fixture, dict):
        raise BetaReadinessError("benchmark fixture must be an object")
    _exact_keys(
        fixture,
        {
            "fixtureCommit",
            "taskId",
            "packId",
            "packSha256",
            "environmentManifestSha256",
        },
        label="benchmark fixture",
    )
    if (
        not isinstance(fixture["fixtureCommit"], str)
        or _COMMIT.fullmatch(fixture["fixtureCommit"]) is None
    ):
        raise BetaReadinessError("benchmark fixtureCommit is invalid")
    for key in ("taskId", "packId"):
        value = fixture[key]
        if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
            raise BetaReadinessError(f"benchmark fixture {key} is invalid")
    _sha256(fixture["packSha256"], label="benchmark fixture packSha256")
    _sha256(
        fixture["environmentManifestSha256"],
        label="benchmark fixture environmentManifestSha256",
    )
    if payload["allAttemptsRecorded"] is not True:
        raise BetaReadinessError("benchmark allAttemptsRecorded must be true")
    if payload["percentileMethod"] != "nearest-rank":
        raise BetaReadinessError("benchmark percentileMethod must be nearest-rank")
    if type(payload["targetMs"]) is not int or payload["targetMs"] != 900_000:
        raise BetaReadinessError("benchmark targetMs must be exactly 900000")
    all_ids: set[str] = set()
    raw_evidence_digests: set[str] = set()
    phase_order = ("setup", "implementation-rework", "review", "integration")

    def validate_phase_timings(
        value: object,
        *,
        label: str,
        run_started: dt.datetime,
        run_completed: dt.datetime,
        run_duration: int,
        status: str,
    ) -> None:
        if not isinstance(value, list) or not 2 <= len(value) <= len(phase_order) + 1:
            raise BetaReadinessError(
                f"{label} phaseTimings must contain a completed phase prefix and total"
            )
        expected_phases = phase_order if status == "pass" else phase_order[: len(value) - 1]
        names: list[str] = []
        intervals: list[tuple[dt.datetime, dt.datetime, int]] = []
        for index, phase in enumerate(value):
            phase_label = f"{label} phaseTimings entry {index}"
            if not isinstance(phase, dict):
                raise BetaReadinessError(f"{phase_label} must be an object")
            _exact_keys(
                phase,
                {"phase", "startedAt", "completedAt", "durationMs"},
                label=phase_label,
            )
            name = phase["phase"]
            if not isinstance(name, str):
                raise BetaReadinessError(f"{phase_label} phase is invalid")
            names.append(name)
            phase_started = _parse_timestamp(
                phase["startedAt"], label=f"{phase_label} startedAt"
            )
            phase_completed = _parse_timestamp(
                phase["completedAt"], label=f"{phase_label} completedAt"
            )
            if phase_completed <= phase_started:
                raise BetaReadinessError(
                    f"{phase_label} timestamps must be strictly ordered"
                )
            phase_duration = _nonnegative_int(
                phase["durationMs"],
                label=f"{phase_label} durationMs",
                positive=True,
                maximum=86_400_000,
            )
            elapsed = phase_completed - phase_started
            calculated = (
                elapsed.days * 86_400_000
                + elapsed.seconds * 1000
                + elapsed.microseconds // 1000
            )
            if phase_duration != calculated:
                raise BetaReadinessError(
                    f"{phase_label} durationMs does not match its timestamps"
                )
            intervals.append((phase_started, phase_completed, phase_duration))
        expected_names = [*expected_phases, "total"]
        if names != expected_names:
            raise BetaReadinessError(
                f"{label} phaseTimings must follow the objective phase order"
            )
        total_started, total_completed, total_duration = intervals[-1]
        if (
            total_started != run_started
            or total_completed != run_completed
            or total_duration != run_duration
        ):
            raise BetaReadinessError(
                f"{label} total phase must equal the run timestamps and duration"
            )
        observed = intervals[:-1]
        if observed[0][0] != total_started or observed[-1][1] != total_completed:
            raise BetaReadinessError(
                f"{label} phaseTimings must span the entire total interval"
            )
        for previous, current in zip(observed, observed[1:]):
            if previous[1] != current[0]:
                raise BetaReadinessError(
                    f"{label} phaseTimings must be contiguous and ordered"
                )
        if sum(item[2] for item in observed) != total_duration:
            raise BetaReadinessError(
                f"{label} phase durations must sum exactly to total"
            )

    def validate_run(run: object, *, label: str, state: str, status: str) -> int:
        if not isinstance(run, dict):
            raise BetaReadinessError(f"{label} must be an object")
        _exact_keys(
            run,
            {
                "runId",
                "state",
                "startedAt",
                "completedAt",
                "durationMs",
                "phaseTimings",
                "status",
                "retryCount",
                "rawEvidenceSha256",
                "failureReason",
            },
            label=label,
        )
        run_id = run["runId"]
        if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
            raise BetaReadinessError(f"{label} runId is invalid")
        if run_id in all_ids:
            raise BetaReadinessError("benchmark runId values must be globally distinct")
        all_ids.add(run_id)
        if run["state"] != state:
            raise BetaReadinessError(f"{label} state must be exactly {state}")
        if run["status"] != status:
            raise BetaReadinessError(f"{label} status must be exactly {status}")
        started = _parse_timestamp(run["startedAt"], label=f"{label} startedAt")
        completed = _parse_timestamp(run["completedAt"], label=f"{label} completedAt")
        if started < cutoff or completed > observed_at or completed <= started:
            raise BetaReadinessError(
                f"{label} timestamps must be fresh, ordered, and no later than artifact observation"
            )
        duration = _nonnegative_int(
            run["durationMs"],
            label=f"{label} durationMs",
            positive=True,
            maximum=86_400_000,
        )
        elapsed = completed - started
        calculated_duration = (
            elapsed.days * 86_400_000
            + elapsed.seconds * 1000
            + elapsed.microseconds // 1000
        )
        if duration != calculated_duration:
            raise BetaReadinessError(
                f"{label} durationMs does not match its timestamps"
            )
        validate_phase_timings(
            run["phaseTimings"],
            label=label,
            run_started=started,
            run_completed=completed,
            run_duration=duration,
            status=status,
        )
        _nonnegative_int(
            run["retryCount"], label=f"{label} retryCount", maximum=100
        )
        raw_digest = _sha256(
            run["rawEvidenceSha256"], label=f"{label} rawEvidenceSha256"
        )
        if raw_digest in raw_evidence_digests:
            raise BetaReadinessError(
                "benchmark attempts must bind distinct raw evidence digests"
            )
        raw_evidence_digests.add(raw_digest)
        if status == "pass":
            if run["failureReason"] is not None:
                raise BetaReadinessError(f"{label} successful run must have null failureReason")
        else:
            _text(run["failureReason"], label=f"{label} failureReason", maximum=500)
        return duration

    def runs(name: str, state: str) -> list[int]:
        value = payload[name]
        if not isinstance(value, list) or not 5 <= len(value) <= 100:
            raise BetaReadinessError(f"benchmark {name} must contain 5 to 100 runs")
        durations: list[int] = []
        for index, run in enumerate(value):
            label = f"benchmark {name} run {index}"
            durations.append(validate_run(run, label=label, state=state, status="pass"))
        return durations

    cold = runs("coldRuns", "cold")
    warm = runs("warmRuns", "warm")
    failures = payload["failures"]
    if not isinstance(failures, list) or len(failures) > 100:
        raise BetaReadinessError("benchmark failures must contain at most 100 attempts")
    for index, run in enumerate(failures):
        if not isinstance(run, dict) or run.get("state") not in {"cold", "warm"}:
            raise BetaReadinessError(
                f"benchmark failure {index} state must be cold or warm"
            )
        validate_run(
            run,
            label=f"benchmark failure {index}",
            state=run["state"],
            status="fail",
        )
    expected = {
        "coldP50Ms": _nearest_rank(cold, 50),
        "coldP95Ms": _nearest_rank(cold, 95),
        "warmP50Ms": _nearest_rank(warm, 50),
        "warmP95Ms": _nearest_rank(warm, 95),
    }
    for key, calculated in expected.items():
        if type(payload[key]) is not int or payload[key] != calculated:
            raise BetaReadinessError(
                f"benchmark {key} does not match the nearest-rank raw-run calculation"
            )
    if expected["coldP50Ms"] >= payload["targetMs"]:
        raise BetaReadinessError(
            "benchmark cold p50 does not meet the below-15-minute target"
        )
    return release_set, {
        "fixtureCommit": fixture["fixtureCommit"],
        "taskId": fixture["taskId"],
        "packId": fixture["packId"],
        "packSha256": fixture["packSha256"],
        "environmentManifestSha256": fixture["environmentManifestSha256"],
    }


def _validate_metric(
    value: object,
    *,
    label: str,
    positive: bool = False,
    maximum: int = 2**63 - 1,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BetaReadinessError(f"{label} must be an object")
    _exact_keys(value, {"value", "unavailableReason"}, label=label)
    metric = value["value"]
    reason = value["unavailableReason"]
    if metric is None:
        _text(reason, label=f"{label} unavailableReason", maximum=240)
    else:
        _nonnegative_int(
            metric,
            label=f"{label} value",
            positive=positive,
            maximum=maximum,
        )
        if reason is not None:
            raise BetaReadinessError(
                f"{label} with a value must use null unavailableReason"
            )
    return {"value": metric, "unavailableReason": reason}


def _validate_text_observation(
    value: object, *, label: str, maximum: int
) -> dict[str, str | None]:
    if not isinstance(value, dict):
        raise BetaReadinessError(f"{label} must be an object")
    _exact_keys(value, {"value", "unavailableReason"}, label=label)
    observation = value["value"]
    reason = value["unavailableReason"]
    if observation is None:
        _text(reason, label=f"{label} unavailableReason", maximum=240)
    else:
        observation = _text(observation, label=f"{label} value", maximum=maximum)
        if reason is not None:
            raise BetaReadinessError(
                f"{label} with a value must use null unavailableReason"
            )
    return {"value": observation, "unavailableReason": reason}


def _validate_pricing_date(
    value: object, *, label: str, observed_at: dt.datetime
) -> dict[str, str | None]:
    result = _validate_text_observation(value, label=label, maximum=10)
    price_date = result["value"]
    if price_date is None:
        return result
    if _DATE.fullmatch(price_date) is None:
        raise BetaReadinessError(f"{label} value must use YYYY-MM-DD")
    try:
        parsed = dt.date.fromisoformat(price_date)
    except ValueError as exc:
        raise BetaReadinessError(f"{label} value is not a valid date") from exc
    if parsed > observed_at.date():
        raise BetaReadinessError(f"{label} value cannot postdate the usage record")
    return result


def _validate_usage(
    payload: Mapping[str, Any], *, observed_at: dt.datetime, expected_version: str
) -> tuple[str, dict[str, str]]:
    _exact_keys(
        payload,
        {"releaseSet", "coverage", "records"},
        label="runtime-usage payload",
    )
    release_set = _validate_release_set(
        payload["releaseSet"],
        label="runtime-usage releaseSet",
        expected_version=expected_version,
    )
    coverage = payload["coverage"]
    if not isinstance(coverage, dict):
        raise BetaReadinessError("runtime-usage coverage must be an object")
    _exact_keys(
        coverage,
        {
            "allAgentRunsRecorded",
            "fixtureCommit",
            "taskId",
            "packId",
            "packSha256",
            "environmentManifestSha256",
            "expectedAgentRunIds",
        },
        label="runtime-usage coverage",
    )
    if coverage["allAgentRunsRecorded"] is not True:
        raise BetaReadinessError(
            "runtime-usage coverage allAgentRunsRecorded must be true"
        )
    fixture_commit = coverage["fixtureCommit"]
    if not isinstance(fixture_commit, str) or _COMMIT.fullmatch(fixture_commit) is None:
        raise BetaReadinessError("runtime-usage coverage fixtureCommit is invalid")
    task_id = _text(
        coverage["taskId"], label="runtime-usage coverage taskId", maximum=256
    )
    pack_id = coverage["packId"]
    if not isinstance(pack_id, str) or _RUN_ID.fullmatch(pack_id) is None:
        raise BetaReadinessError("runtime-usage coverage packId is invalid")
    pack_digest = _sha256(
        coverage["packSha256"], label="runtime-usage coverage packSha256"
    )
    environment_digest = _sha256(
        coverage["environmentManifestSha256"],
        label="runtime-usage coverage environmentManifestSha256",
    )
    expected_runs = coverage["expectedAgentRunIds"]
    if not isinstance(expected_runs, list) or not 1 <= len(expected_runs) <= 96:
        raise BetaReadinessError(
            "runtime-usage expectedAgentRunIds must contain 1 to 96 entries"
        )
    if any(
        not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None
        for run_id in expected_runs
    ):
        raise BetaReadinessError(
            "runtime-usage expectedAgentRunIds contains an invalid run id"
        )
    if len(expected_runs) != len(set(expected_runs)):
        raise BetaReadinessError(
            "runtime-usage expectedAgentRunIds must not contain duplicates"
        )
    if expected_runs != sorted(expected_runs):
        raise BetaReadinessError(
            "runtime-usage expectedAgentRunIds must use deterministic sorted order"
        )
    records = payload["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= 96:
        raise BetaReadinessError("runtime-usage records must contain 1 to 96 entries")
    agent_runs: list[str] = []
    for index, record in enumerate(records):
        label = f"runtime-usage record {index}"
        if not isinstance(record, dict):
            raise BetaReadinessError(f"{label} must be an object")
        _exact_keys(
            record,
            {
                "agentRunId",
                "agentId",
                "runtime",
                "model",
                "provider",
                "wallTimeMs",
                "inputTokens",
                "outputTokens",
                "cacheTokens",
                "providerCostMicros",
                "currency",
                "pricingDate",
                "costCalculation",
            },
            label=label,
        )
        agent_run = record["agentRunId"]
        if not isinstance(agent_run, str) or _RUN_ID.fullmatch(agent_run) is None:
            raise BetaReadinessError(f"{label} agentRunId is invalid")
        if agent_run in agent_runs:
            raise BetaReadinessError(
                "runtime-usage agentRunId values must be distinct"
            )
        agent_runs.append(agent_run)
        agent = record["agentId"]
        if not isinstance(agent, str) or _PRODUCER_ID.fullmatch(agent) is None:
            raise BetaReadinessError(f"{label} agentId is invalid")
        _text(record["runtime"], label=f"{label} runtime", maximum=96)
        _text(record["model"], label=f"{label} model", maximum=128)
        _validate_text_observation(
            record["provider"], label=f"{label} provider", maximum=128
        )
        _validate_metric(
            record["wallTimeMs"],
            label=f"{label} wallTimeMs",
            positive=True,
            maximum=86_400_000,
        )
        _validate_metric(record["inputTokens"], label=f"{label} inputTokens")
        _validate_metric(record["outputTokens"], label=f"{label} outputTokens")
        _validate_metric(record["cacheTokens"], label=f"{label} cacheTokens")
        cost = _validate_metric(
            record["providerCostMicros"], label=f"{label} providerCostMicros"
        )
        _validate_pricing_date(
            record["pricingDate"],
            label=f"{label} pricingDate",
            observed_at=observed_at,
        )
        _validate_text_observation(
            record["costCalculation"],
            label=f"{label} costCalculation",
            maximum=500,
        )
        currency = record["currency"]
        if cost["value"] is None:
            if currency is not None:
                raise BetaReadinessError(
                    f"{label} currency must be null when provider cost is unavailable"
                )
        elif not isinstance(currency, str) or _CURRENCY.fullmatch(currency) is None:
            raise BetaReadinessError(
                f"{label} currency must be a three-letter code when cost is recorded"
            )
    if agent_runs != expected_runs:
        raise BetaReadinessError(
            "runtime-usage records must exactly cover expectedAgentRunIds in sorted order"
        )
    return release_set, {
        "fixtureCommit": fixture_commit,
        "taskId": task_id,
        "packId": pack_id,
        "packSha256": pack_digest,
        "environmentManifestSha256": environment_digest,
    }


def _validate_artifact(
    raw: bytes,
    *,
    criterion: EvidenceCriterion,
    candidate: str,
    observed_at: dt.datetime,
    observed_text: str,
    path: str,
    digest: str,
    cutoff: dt.datetime,
    expected_version: str,
) -> ValidatedArtifact:
    label = f"{criterion.id} artifact"
    value = _decode_json(raw, label=label)
    _exact_keys(
        value,
        {
            "schemaVersion",
            "artifactId",
            "criterionId",
            "candidateCommit",
            "observedAt",
            "producer",
            "payload",
        },
        label=label,
    )
    if (
        type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != SCHEMA_VERSION
    ):
        raise BetaReadinessError(f"{label} schemaVersion must equal {SCHEMA_VERSION}")
    artifact_id = value["artifactId"]
    if not isinstance(artifact_id, str) or _ARTIFACT_ID.fullmatch(artifact_id) is None:
        raise BetaReadinessError(f"{label} artifactId is invalid")
    if value["criterionId"] != criterion.id:
        raise BetaReadinessError(f"{label} criterionId does not bind the criterion")
    if value["candidateCommit"] != candidate:
        raise BetaReadinessError(f"{label} candidateCommit does not bind exact HEAD")
    if value["observedAt"] != observed_text:
        raise BetaReadinessError(
            f"{label} observedAt does not match its evidence entry"
        )
    _producer(value["producer"], expected_role=criterion.producer_role, label=label)
    payload = value["payload"]
    if not isinstance(payload, dict):
        raise BetaReadinessError(f"{label} payload must be an object")
    bindings: dict[str, str] = {}
    if criterion.id == "private-disclosure-channel":
        release_set = _validate_private_disclosure(payload)
    elif criterion.id == "full-validation":
        release_set = _validate_full_validation(
            payload, expected_version=expected_version
        )
    elif criterion.id == "reproducible-package":
        release_set = _validate_reproducible_package(
            payload, expected_version=expected_version
        )
    elif criterion.id == "independent-exact-package-review":
        release_set = _validate_reviews(
            payload,
            observed_at=observed_at,
            cutoff=cutoff,
            expected_version=expected_version,
        )
    elif criterion.id == "exact-candidate-compatibility":
        release_set = _validate_compatibility(
            payload,
            candidate=candidate,
            observed_at=observed_at,
            cutoff=cutoff,
            expected_version=expected_version,
        )
    elif criterion.id == "governed-walkthrough-execution":
        release_set, bindings = _validate_walkthrough(
            payload,
            candidate=candidate,
            observed_at=observed_at,
            cutoff=cutoff,
            expected_version=expected_version,
        )
    elif criterion.id == "first-governed-delivery-under-15m":
        release_set, bindings = _validate_benchmark(
            payload,
            observed_at=observed_at,
            cutoff=cutoff,
            expected_version=expected_version,
        )
    elif criterion.id == "runtime-usage-observability":
        release_set, bindings = _validate_usage(
            payload,
            observed_at=observed_at,
            expected_version=expected_version,
        )
    else:  # pragma: no cover
        raise BetaReadinessError(f"unsupported evidence criterion: {criterion.id}")
    return ValidatedArtifact(
        artifact_id,
        path,
        digest,
        release_set,
        tuple(sorted(bindings.items())),
    )


def _load_evidence(
    reader: SafeRepositoryReader,
    relative: str,
    candidate: str,
    *,
    effective_now: dt.datetime,
    cutoff: dt.datetime,
    expected_version: str,
) -> tuple[dict[str, dict[str, Any]], dt.datetime, str | None]:
    raw = reader.read_regular(relative, limit=MAX_EVIDENCE_BYTES, label="evidence file")
    value = _decode_json(raw, label="evidence file")
    _exact_keys(
        value,
        {"schemaVersion", "candidateCommit", "generatedAt", "criteria"},
        label="evidence file",
    )
    if (
        type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != SCHEMA_VERSION
    ):
        raise BetaReadinessError(f"evidence schemaVersion must equal {SCHEMA_VERSION}")
    if value["candidateCommit"] != candidate:
        raise BetaReadinessError(
            "evidence candidateCommit does not match exact checked-out HEAD"
        )
    generated_at = _parse_timestamp(value["generatedAt"], label="evidence generatedAt")
    if generated_at > effective_now:
        raise BetaReadinessError("evidence generatedAt is dated in the future")
    if generated_at < cutoff:
        raise BetaReadinessError(
            "evidence generatedAt is older than the permitted window"
        )
    entries = value["criteria"]
    if not isinstance(entries, list) or len(entries) > MAX_CRITERIA:
        raise BetaReadinessError(
            f"evidence criteria must be an array of at most {MAX_CRITERIA} entries"
        )
    parsed: dict[str, dict[str, Any]] = {}
    artifact_ids: set[str] = set()
    artifact_paths: set[str] = set()
    artifact_digests: set[str] = set()
    release_set_digests: dict[str, str] = {}
    expected_keys = {
        "id",
        "status",
        "observedAt",
        "evidencePath",
        "evidenceSha256",
        "detail",
    }
    for index, entry in enumerate(entries):
        label = f"evidence criterion {index}"
        if not isinstance(entry, dict):
            raise BetaReadinessError(f"{label} must be an object")
        _exact_keys(entry, expected_keys, label=label)
        criterion_id = entry["id"]
        if not isinstance(criterion_id, str) or criterion_id not in EVIDENCE_BY_ID:
            raise BetaReadinessError(
                f"{label} has unknown or invalid id: {criterion_id!r}"
            )
        if criterion_id in parsed:
            raise BetaReadinessError(f"duplicate evidence criterion id: {criterion_id}")
        status_value = entry["status"]
        if not isinstance(status_value, str) or status_value not in {
            "pass",
            "fail",
            "unknown",
        }:
            raise BetaReadinessError(f"{label} status must be pass, fail, or unknown")
        observed_text = entry["observedAt"]
        observed = _parse_timestamp(observed_text, label=f"{label} observedAt")
        if observed > generated_at:
            raise BetaReadinessError(
                f"{label} observedAt is later than evidence generatedAt"
            )
        if observed < cutoff:
            raise BetaReadinessError(
                f"{label} observedAt is older than the permitted window"
            )
        _text(entry["detail"], label=f"{label} detail")
        evidence_path = entry["evidencePath"]
        evidence_digest = entry["evidenceSha256"]
        artifact: ValidatedArtifact | None = None
        if status_value == "pass":
            if not isinstance(evidence_path, str):
                raise BetaReadinessError(f"{label} pass requires evidencePath")
            pure = _safe_relative(evidence_path, label=f"{label} evidencePath")
            if pure.parent != ARTIFACT_DIRECTORY:
                raise BetaReadinessError(
                    f"{label} artifact must be directly below {ARTIFACT_DIRECTORY}"
                )
            digest = _sha256(evidence_digest, label=f"{label} evidenceSha256")
            if evidence_path in artifact_paths:
                raise BetaReadinessError(
                    "passing criteria must not reuse an artifact path"
                )
            if digest in artifact_digests:
                raise BetaReadinessError(
                    "passing criteria must not reuse an artifact digest"
                )
            artifact_raw = reader.read_regular(
                evidence_path,
                limit=MAX_ARTIFACT_BYTES,
                label=f"{label} artifact",
            )
            if hashlib.sha256(artifact_raw).hexdigest() != digest:
                raise BetaReadinessError(
                    f"{label} artifact digest does not match evidenceSha256"
                )
            artifact = _validate_artifact(
                artifact_raw,
                criterion=EVIDENCE_BY_ID[criterion_id],
                candidate=candidate,
                observed_at=observed,
                observed_text=observed_text,
                path=evidence_path,
                digest=digest,
                cutoff=cutoff,
                expected_version=expected_version,
            )
            if artifact.artifact_id in artifact_ids:
                raise BetaReadinessError(
                    "passing criteria must not reuse an artifactId"
                )
            artifact_ids.add(artifact.artifact_id)
            artifact_paths.add(evidence_path)
            artifact_digests.add(digest)
            if artifact.release_set_digest is not None:
                release_set_digests[criterion_id] = artifact.release_set_digest
        elif evidence_path is not None or evidence_digest is not None:
            raise BetaReadinessError(
                f"{label} non-pass status must use null artifact fields"
            )
        parsed[criterion_id] = {
            "id": criterion_id,
            "status": status_value,
            "_observed": observed,
            "_artifact": artifact,
        }

    canonical_release_set = release_set_digests.get("reproducible-package")
    if canonical_release_set is not None:
        for criterion_id, digest in release_set_digests.items():
            if digest != canonical_release_set:
                raise BetaReadinessError(
                    f"{criterion_id} does not bind the reproducible exact release set"
                )
    walkthrough = parsed.get("governed-walkthrough-execution", {}).get("_artifact")
    benchmark = parsed.get("first-governed-delivery-under-15m", {}).get("_artifact")
    usage = parsed.get("runtime-usage-observability", {}).get("_artifact")
    if walkthrough is not None and benchmark is not None:
        if walkthrough.bindings != benchmark.bindings:
            raise BetaReadinessError(
                "governed walkthrough and benchmark fixture bindings differ"
            )
    for peer_name, peer in (("walkthrough", walkthrough), ("benchmark", benchmark)):
        if usage is not None and peer is not None and usage.bindings != peer.bindings:
            raise BetaReadinessError(
                f"runtime usage and {peer_name} fixture bindings differ"
            )
    return parsed, generated_at, canonical_release_set


def evaluate(
    project: Path,
    *,
    evidence_path: str = DEFAULT_EVIDENCE_PATH,
    now: dt.datetime | None = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> dict[str, Any]:
    """Return a deterministic readiness report for ``project`` and ``now``."""

    if (
        isinstance(max_age_days, bool)
        or not isinstance(max_age_days, int)
        or not 1 <= max_age_days <= 90
    ):
        raise BetaReadinessError(
            "max evidence age must be an integer from 1 to 90 days"
        )
    _safe_relative(evidence_path, label="evidence path")
    effective_now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if effective_now.tzinfo is None or effective_now.utcoffset() != dt.timedelta(0):
        raise BetaReadinessError("evaluation time must be timezone-aware UTC")
    cutoff = effective_now - dt.timedelta(days=max_age_days)

    with SafeRepositoryReader(project) as reader:
        root = reader.root
        candidate = _head_commit(root)
        candidate_version = _candidate_version(root, candidate)
        results: list[dict[str, Any]] = []
        for criterion in DOCUMENT_CRITERIA:
            try:
                payload = _git_blob(
                    root, candidate, criterion.path, limit=MAX_DOCUMENT_BYTES
                )
                text = payload.decode("utf-8")
                missing = [marker for marker in criterion.markers if marker not in text]
                forbidden = [
                    marker
                    for marker in criterion.forbidden_markers
                    if marker in text
                ]
            except (BetaReadinessError, UnicodeDecodeError) as exc:
                results.append(
                    {
                        "id": criterion.id,
                        "kind": "document",
                        "status": "fail",
                        "message": str(exc),
                    }
                )
                continue
            results.append(
                {
                    "id": criterion.id,
                    "kind": "document",
                    "status": "fail" if missing or forbidden else "pass",
                    "message": (
                        f"{criterion.path} in exact candidate has obsolete "
                        "or missing required content"
                        if missing or forbidden
                        else criterion.description
                    ),
                }
            )

        evidence: dict[str, dict[str, Any]] = {}
        generated_at: dt.datetime | None = None
        canonical_release_set: str | None = None
        evidence_absent = False
        try:
            evidence, generated_at, canonical_release_set = _load_evidence(
                reader,
                evidence_path,
                candidate,
                effective_now=effective_now,
                cutoff=cutoff,
                expected_version=candidate_version,
            )
        except RepositoryPathMissing:
            if evidence_path != DEFAULT_EVIDENCE_PATH:
                raise
            evidence_absent = True

        envelope_stale = generated_at is not None and generated_at < cutoff
        for criterion in EVIDENCE_CRITERIA:
            entry = evidence.get(criterion.id)
            if entry is None:
                status_value = "unknown"
                message = (
                    "No external evidence file was supplied."
                    if evidence_absent
                    else "The evidence file has no entry for this required criterion."
                )
            elif envelope_stale:
                status_value = "fail"
                message = f"Evidence envelope is older than {max_age_days} days."
            elif entry["_observed"] > effective_now:
                status_value = "fail"
                message = "Evidence is dated in the future."
            elif entry["_observed"] < cutoff:
                status_value = "fail"
                message = f"Evidence is older than {max_age_days} days."
            else:
                status_value = entry["status"]
                # Evidence detail is untrusted operator/provider text. Validate
                # it on ingestion, but never tee it into JSON or text output.
                message = (
                    f"External evidence reported {status_value} for this criterion."
                )
            results.append(
                {
                    "id": criterion.id,
                    "kind": "evidence",
                    "status": status_value,
                    "message": message,
                }
            )

        reader._verify_root()
        if _head_commit(root) != candidate:
            raise BetaReadinessError("HEAD changed during beta-readiness evaluation")

    ready = all(item["status"] == "pass" for item in results)
    return {
        "ok": True,
        "action": "beta-readiness",
        "schemaVersion": SCHEMA_VERSION,
        "candidateCommit": candidate,
        "candidateVersion": candidate_version,
        "releaseSetSha256": canonical_release_set,
        "evidencePath": evidence_path,
        "maxEvidenceAgeDays": max_age_days,
        "overall": "ready" if ready else "not-ready",
        "ready": ready,
        "criteria": results,
    }


def _redacted_output(value: Any) -> Any:
    """Return an output-only copy with recognized secrets removed.

    Schema keys are internal constants; every string value is redacted again at
    the final stdout/stderr boundary as defense in depth.
    """

    if isinstance(value, str):
        return redact_secret_like(value)
    if isinstance(value, list):
        return [_redacted_output(item) for item in value]
    if isinstance(value, tuple):
        return [_redacted_output(item) for item in value]
    if isinstance(value, dict):
        return {key: _redacted_output(item) for key, item in value.items()}
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate exact-commit Startup Factory beta readiness"
    )
    parser.add_argument(
        "--project", type=Path, default=Path.cwd(), help="repository root"
    )
    parser.add_argument(
        "--evidence",
        default=DEFAULT_EVIDENCE_PATH,
        help=f"repository-relative evidence JSON (default: {DEFAULT_EVIDENCE_PATH})",
    )
    parser.add_argument(
        "--at",
        metavar="UTC",
        help=(
            "evaluation time as YYYY-MM-DDTHH:MM:SS[.mmm]Z "
            "(useful for reproducible checks)"
        ),
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"maximum evidence age, 1-90 days (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        now = _parse_timestamp(args.at, label="--at") if args.at else None
        report = evaluate(
            args.project,
            evidence_path=args.evidence,
            now=now,
            max_age_days=args.max_age_days,
        )
    except BetaReadinessError as exc:
        safe_error = redact_secret_like(str(exc))
        if args.json:
            print(
                json.dumps(
                    {"ok": False, "error": safe_error},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
            )
        else:
            print(f"beta-readiness: {safe_error}", file=sys.stderr)
        return 2
    report = _redacted_output(report)
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(f"Beta readiness: {report['overall']} ({report['candidateCommit']})")
        for criterion in report["criteria"]:
            print(
                f"  [{criterion['status']}] {criterion['id']}: {criterion['message']}"
            )
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
