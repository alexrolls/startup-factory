#!/usr/bin/env python3
"""Extract the bounded beta evidence set from one exact Git commit.

The release evidence branch is an untrusted transport.  This helper reads only
Git objects, accepts the closed evidence-only tree shape, and creates regular
files beneath an already existing candidate checkout without following links.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Sequence


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from startup_factory_cli.secret_safety import (  # noqa: E402
    contains_secret_like,
    redact_secret_like,
)


ENVELOPE = ".startup-factory/beta-readiness-evidence.json"
ARTIFACT = re.compile(
    r"\.startup-factory/beta-evidence/[A-Za-z0-9][A-Za-z0-9._+-]{0,199}\.json\Z"
)
OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MAX_TREE_BYTES = 256 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 128 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_FILES = 33
GIT = shutil.which("git")


class EvidenceExtractionError(RuntimeError):
    """The protected evidence commit is unsafe or does not match its envelope."""

    def __init__(self, message: object) -> None:
        # Protected-workflow logs must not reflect a token from an untrusted
        # Git error, JSON key, or evidence path.
        super().__init__(redact_secret_like(str(message)))


def _kill(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _git(
    repository: Path,
    arguments: Sequence[str],
    *,
    label: str,
    stdout_limit: int,
    timeout: float = 10,
) -> bytes:
    if GIT is None:
        raise EvidenceExtractionError("Git is unavailable")
    environment = {
        "PATH": "/usr/bin:/bin",
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
            [GIT, "-C", os.fspath(repository), *arguments],
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
            ("stderr", process.stderr, MAX_STDERR_BYTES),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
            streams[stream.fileno()] = (name, limit, bytearray())

        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill(process)
                raise EvidenceExtractionError(f"Git timed out while reading {label}")
            events = selector.select(remaining)
            if not events:
                _kill(process)
                raise EvidenceExtractionError(f"Git timed out while reading {label}")
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
                    _kill(process)
                    raise EvidenceExtractionError(
                        f"Git {name} exceeds {limit} bytes while reading {label}"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill(process)
            raise EvidenceExtractionError(f"Git timed out while reading {label}")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _kill(process)
            raise EvidenceExtractionError(
                f"Git timed out while reading {label}"
            ) from exc
    except EvidenceExtractionError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        if process is not None:
            _kill(process)
        raise EvidenceExtractionError(f"cannot read {label} from Git") from exc
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    stdout = bytes(next(item[2] for item in streams.values() if item[0] == "stdout"))
    stderr = bytes(next(item[2] for item in streams.values() if item[0] == "stderr"))
    if return_code != 0:
        message = stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceExtractionError(
            f"cannot read {label} from exact evidence commit: {message}"
        )
    return stdout


def _unique_object(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _decode_envelope(payload: bytes) -> set[str]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite number: {value}")
            ),
        )
        if not isinstance(value, dict) or set(value) != {
            "schemaVersion",
            "candidateCommit",
            "generatedAt",
            "criteria",
        }:
            raise ValueError("unexpected envelope keys")
        criteria = value["criteria"]
        if not isinstance(criteria, list) or len(criteria) > 32:
            raise ValueError("criteria is not a bounded array")
        referenced: list[str] = []
        for index, entry in enumerate(criteria):
            if not isinstance(entry, dict):
                raise ValueError(f"criterion {index} is not an object")
            if entry.get("status") == "pass":
                path = entry.get("evidencePath")
                if not isinstance(path, str) or ARTIFACT.fullmatch(path) is None:
                    raise ValueError(f"criterion {index} has an invalid evidencePath")
                if contains_secret_like(path):
                    raise ValueError(
                        f"criterion {index} has a secret-like evidencePath"
                    )
                referenced.append(path)
        if len(referenced) != len(set(referenced)):
            raise ValueError("passing criteria reuse an evidencePath")
        return set(referenced)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceExtractionError(
            f"protected readiness envelope is invalid: {exc}"
        ) from exc


def _repository(path: Path) -> Path:
    requested = path.expanduser().absolute()
    try:
        metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise EvidenceExtractionError(f"evidence repository is unavailable: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceExtractionError("evidence repository must be a non-symlink directory")
    return resolved


def _destination(path: Path) -> tuple[Path, int]:
    requested = path.expanduser().absolute()
    try:
        metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise EvidenceExtractionError(f"candidate directory is unavailable: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceExtractionError("candidate must be a non-symlink directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise EvidenceExtractionError(f"cannot anchor candidate directory: {exc}") from exc
    return resolved, descriptor


def _open_directory(parent: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
        metadata = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise EvidenceExtractionError(
            f"candidate evidence directory is unsafe: {name}: {exc}"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
    ):
        os.close(descriptor)
        raise EvidenceExtractionError(f"candidate evidence directory is unsafe: {name}")
    return descriptor


def _write_file(parent: int, name: str, payload: bytes, *, label: str) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent)
    except FileExistsError as exc:
        raise EvidenceExtractionError(
            f"candidate evidence destination already exists: {label}"
        ) from exc
    except OSError as exc:
        raise EvidenceExtractionError(f"cannot create candidate evidence: {label}: {exc}") from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceExtractionError(f"short write for protected evidence: {label}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def extract_evidence(source: Path, commit: str, target: Path) -> dict[str, object]:
    if OBJECT_ID.fullmatch(commit) is None:
        raise EvidenceExtractionError("evidence commit must be a full lowercase object id")
    repository = _repository(source)
    resolved = _git(
        repository,
        ["rev-parse", "--verify", "--end-of-options", f"{commit}^{{commit}}"],
        label="evidence commit",
        stdout_limit=128,
    ).decode("ascii", "strict").strip()
    if resolved != commit:
        raise EvidenceExtractionError("evidence commit did not resolve to itself")
    tree = _git(
        repository,
        ["ls-tree", "-r", "-z", "--full-tree", commit],
        label="evidence tree",
        stdout_limit=MAX_TREE_BYTES,
    )
    selected: list[tuple[str, str]] = []
    seen: set[str] = set()
    for record in tree.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8", "strict")
        except (UnicodeError, ValueError) as exc:
            raise EvidenceExtractionError("protected evidence tree is malformed") from exc
        if path in seen:
            raise EvidenceExtractionError("protected evidence tree repeats a path")
        seen.add(path)
        if path != ENVELOPE and ARTIFACT.fullmatch(path) is None:
            raise EvidenceExtractionError("protected evidence branch contains an unexpected path")
        if contains_secret_like(path):
            raise EvidenceExtractionError(
                "protected evidence branch contains a secret-like path"
            )
        if mode != "100644" or kind != "blob" or OBJECT_ID.fullmatch(object_id) is None:
            raise EvidenceExtractionError(
                "release evidence must contain only regular mode 100644 blobs"
            )
        selected.append((path, object_id))
    if ENVELOPE not in seen:
        raise EvidenceExtractionError("protected evidence commit has no readiness envelope")
    if len(selected) > MAX_FILES:
        raise EvidenceExtractionError("protected evidence commit contains too many files")

    payloads: dict[str, bytes] = {}
    for path, object_id in selected:
        size_raw = _git(
            repository,
            ["cat-file", "-s", object_id],
            label="evidence artifact size",
            stdout_limit=32,
        )
        try:
            size = int(size_raw.decode("ascii").strip())
        except (UnicodeError, ValueError) as exc:
            raise EvidenceExtractionError("Git returned an invalid evidence size") from exc
        limit = MAX_ENVELOPE_BYTES if path == ENVELOPE else MAX_ARTIFACT_BYTES
        if size < 0 or size > limit:
            raise EvidenceExtractionError(
                f"protected evidence blob exceeds {limit} bytes"
            )
        payload = _git(
            repository,
            ["cat-file", "blob", object_id],
            label="evidence artifact blob",
            stdout_limit=limit,
        )
        if len(payload) != size:
            raise EvidenceExtractionError("protected evidence blob size changed")
        payloads[path] = payload

    referenced = _decode_envelope(payloads[ENVELOPE])
    selected_artifacts = set(payloads) - {ENVELOPE}
    if selected_artifacts != referenced:
        raise EvidenceExtractionError(
            "protected evidence artifacts must exactly match envelope pass references"
        )

    target_root, root_descriptor = _destination(target)
    startup_descriptor = evidence_descriptor = -1
    try:
        startup_descriptor = _open_directory(root_descriptor, ".startup-factory")
        evidence_descriptor = _open_directory(startup_descriptor, "beta-evidence")
        for path in sorted(payloads):
            parent, name = path.rsplit("/", 1)
            descriptor = (
                startup_descriptor
                if parent == ".startup-factory"
                else evidence_descriptor
            )
            _write_file(
                descriptor,
                name,
                payloads[path],
                label="protected evidence file",
            )
        os.fsync(evidence_descriptor)
        os.fsync(startup_descriptor)
        os.fsync(root_descriptor)
    finally:
        if evidence_descriptor >= 0:
            os.close(evidence_descriptor)
        if startup_descriptor >= 0:
            os.close(startup_descriptor)
        os.close(root_descriptor)

    return {
        "ok": True,
        "schemaVersion": 1,
        "commit": commit,
        "target": os.fspath(target_root),
        "files": [
            {
                "path": path,
                "size": len(payloads[path]),
                "sha256": hashlib.sha256(payloads[path]).hexdigest(),
            }
            for path in sorted(payloads)
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract one exact bounded release-evidence Git tree"
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = extract_evidence(arguments.source, arguments.commit, arguments.target)
    except EvidenceExtractionError as exc:
        print(f"release-evidence: {exc}", file=__import__("sys").stderr)
        return 2
    if arguments.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(f"Extracted {len(result['files'])} release-evidence files for {result['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
