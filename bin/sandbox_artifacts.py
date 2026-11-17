#!/usr/bin/env python3
"""Bounded regular-file manifests, private quarantine, and authorized ref CAS.

Guest archives, Git packs/configuration and filesystem paths are never imported.
Collection only stages data. Promotion requires a separately supplied trusted
task-authority lock and authorizer; private JSON is not enrollment or approval.
An exact journaled ref update can recover its receipt after a fence, but cannot
restore a ref that has moved to a different projection head.

The operation budget is cooperative: it is checked between bounded native Git
operations and filesystem writes. A trusted bounded authority lock and an outer
controller process/watchdog deadline remain required for a hard wall deadline.
"""

from __future__ import annotations

from contextlib import contextmanager
import copy
import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any, Callable, ContextManager, Iterator, Mapping
import unicodedata
import uuid

from host_git import (
    BASE_MODES, FILE_MODES, HostGit, HostGitError, RefConflict, branch_ref, object_id,
    oid, open_directory, read_regular,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EXPORT_ID = re.compile(r"[0-9a-f]{16,128}\Z")
_RESERVED = frozenset({".git", ".teamwork", ".startup-factory", "startup-factory-broker", ".sf",
                       ".startup-factory-control", ".sf-control"})
_MANIFEST_FIELDS = {"schemaVersion", "id", "baseCommit", "resultingTree", "changes"}
_RECORD_FIELDS = {"manifest", "manifestDigest", "state", "candidateCommit", "commitHex", "receipt"}
_STATE_FIELDS = {"schemaVersion", "assignment", "limits", "exports"}
MAX_STATE_BYTES = 24 * 1024 * 1024


class ArtifactError(ValueError):
    """Untrusted artifact data or an unauthorized/uncertain host operation."""


class ArtifactBusy(ArtifactError):
    """Another trusted operation holds the assignment's staging lock."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise ArtifactError("canonical SHA-256 content identity required")
    return value


def _export_id(value: Any) -> str:
    if type(value) is not str:
        raise ArtifactError("invalid export identity")
    if _EXPORT_ID.fullmatch(value):
        return value
    try:
        if str(uuid.UUID(value)) == value:
            return value
    except (ValueError, AttributeError):
        pass
    raise ArtifactError("invalid export identity")


def _json(raw: bytes, maximum: int) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ArtifactError("artifact metadata byte limit exceeded")
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 12:
                raise ArtifactError("artifact metadata nesting limit exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise ArtifactError("invalid artifact metadata")

    def pairs(items):
        result = {}
        for name, item in items:
            if name in result:
                raise ArtifactError("duplicate artifact metadata field")
            result[name] = item
        return result

    def constant(_value):
        raise ArtifactError("non-finite artifact metadata")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ArtifactError("invalid artifact metadata") from exc
    if type(value) is not dict:
        raise ArtifactError("artifact metadata must be an object")
    return value


def safe_path(value: Any) -> str:
    if type(value) is not str or not value or len(value) > 1024:
        raise ArtifactError("invalid repository-relative artifact path")
    if (
        value.startswith("/") or "\\" in value or ":" in value
        or unicodedata.normalize("NFC", value) != value
        or any(ord(char) < 32 or ord(char) == 127 or unicodedata.category(char) == "Cf" or 0xD800 <= ord(char) <= 0xDFFF for char in value)
        or len(value.encode("utf-8")) > 1024
    ):
        raise ArtifactError("artifact path is not canonical")
    parts = value.split("/")
    if len(parts) > 32:
        raise ArtifactError("artifact path depth limit exceeded")
    for part in parts:
        folded = unicodedata.normalize("NFKC", part).casefold()
        if not part or part in {".", ".."} or part.endswith((" ", ".")) or folded in _RESERVED:
            raise ArtifactError("reserved or ambiguous artifact path")
    return value


def validate_paths(entries: Mapping[str, tuple[str, str]]) -> None:
    folded: dict[str, str] = {}
    leaves = set(entries)
    for path, (mode, identifier) in entries.items():
        safe_path(path)
        if mode not in BASE_MODES:
            raise ArtifactError("unsupported tree mode")
        oid(identifier)
        parts = path.split("/")
        for count in range(1, len(parts) + 1):
            prefix = "/".join(parts[:count])
            normalized = unicodedata.normalize("NFKC", prefix).casefold()
            if normalized in folded and folded[normalized] != prefix:
                raise ArtifactError("case or Unicode normalization collision")
            folded[normalized] = prefix
            if len(folded) > 50_000:
                raise ArtifactError("tree directory-prefix count limit exceeded")
            if count < len(parts) and prefix in leaves:
                raise ArtifactError("a file, symlink, or gitlink is an artifact ancestor")


def tree_objects(entries: Mapping[str, tuple[str, str]]) -> tuple[str, dict[str, bytes]]:
    """Compute raw Git trees without writing paths or invoking Git filters."""
    validate_paths(entries)
    root: dict[str, Any] = {}
    for path, value in entries.items():
        current = root
        parts = path.split("/")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value
    objects: dict[str, bytes] = {}

    def build(directory):
        children = []
        for name, item in directory.items():
            if type(item) is dict:
                mode, identifier, is_directory = "40000", build(item), True
            else:
                mode, identifier = item
                is_directory = False
            encoded = name.encode("utf-8")
            children.append((encoded + (b"/" if is_directory else b"\0"), mode.encode() + b" " + encoded + b"\0" + bytes.fromhex(identifier)))
        raw = b"".join(value for _key, value in sorted(children))
        identifier = object_id("tree", raw)
        objects[identifier] = raw
        return identifier

    return build(root), objects


@dataclasses.dataclass(frozen=True)
class ArtifactLimits:
    max_files: int = 256
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024
    max_manifest_bytes: int = 256 * 1024
    max_exports: int = 64
    max_staged_bytes: int = 64 * 1024 * 1024
    operation_seconds: int = 30

    def __post_init__(self):
        bounds = {
            "max_files": (1, 1024), "max_file_bytes": (1, 16 * 1024 * 1024),
            "max_total_bytes": (1, 64 * 1024 * 1024), "max_manifest_bytes": (512, 1024 * 1024),
            "max_exports": (1, 256), "max_staged_bytes": (1, 256 * 1024 * 1024), "operation_seconds": (1, 120),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ArtifactError("artifact limits must be positive finite bounded integers")

    def as_dict(self):
        return dataclasses.asdict(self)


def parse_manifest(raw: bytes | dict[str, Any], limits: ArtifactLimits) -> dict[str, Any]:
    value = _json(_canonical(raw) if type(raw) is dict else raw, limits.max_manifest_bytes)
    if set(value) != _MANIFEST_FIELDS or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        raise ArtifactError("unsupported artifact manifest schema")
    _export_id(value["id"])
    oid(value["baseCommit"])
    oid(value["resultingTree"])
    if type(value["changes"]) is not list or not 0 <= len(value["changes"]) <= limits.max_files:
        raise ArtifactError("artifact change count exceeds its bound")
    seen = set()
    total = 0
    for change in value["changes"]:
        if type(change) is not dict or type(change.get("operation")) is not str or change["operation"] not in {"add", "replace", "delete"}:
            raise ArtifactError("unsupported artifact change")
        expected = {"operation", "path"} if change["operation"] == "delete" else {"operation", "path", "mode", "size", "sha256"}
        if set(change) != expected:
            raise ArtifactError("artifact change has unexpected fields")
        path = safe_path(change["path"])
        if path in seen:
            raise ArtifactError("duplicate artifact path")
        seen.add(path)
        if change["operation"] != "delete":
            if type(change["mode"]) is not str or change["mode"] not in FILE_MODES:
                raise ArtifactError("only regular-file artifact changes are supported")
            if type(change["size"]) is not int or not 0 <= change["size"] <= limits.max_file_bytes:
                raise ArtifactError("artifact file exceeds its byte limit")
            _digest(change["sha256"])
            total += change["size"]
    if total > limits.max_total_bytes:
        raise ArtifactError("artifact cumulative byte limit exceeded")
    return value


class _Directory:
    def __init__(self, path: Path):
        self.path = path
        self.fd = open_directory(path, private=True)
        info = os.fstat(self.fd)
        self.identity = info.st_dev, info.st_ino

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def check(self):
        other = open_directory(self.path, private=True)
        try:
            info = os.fstat(other)
            if (info.st_dev, info.st_ino) != self.identity:
                raise ArtifactError("quarantine directory identity changed")
        finally:
            os.close(other)

    def child(self, name: str):
        self.check()
        if not re.fullmatch(r"[0-9a-f]{64}", name):
            raise ArtifactError("invalid host quarantine locator")
        try:
            os.mkdir(name, 0o700, dir_fd=self.fd)
            os.fsync(self.fd)
        except FileExistsError:
            pass
        return _Directory(self.path / name)

    def read(self, name: str, maximum: int):
        self.check()
        return read_regular(self.fd, name, maximum)

    def write(self, name: str, raw: bytes, *, immutable: bool, maximum: int):
        self.check()
        if not re.fullmatch(r"[a-z0-9.-]{1,100}", name) or name in {".", ".."} or len(raw) > maximum:
            raise ArtifactError("invalid bounded quarantine write")
        if immutable:
            try:
                existing = self.read(name, maximum)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if existing != raw:
                    raise ArtifactError("immutable quarantine content changed")
                return
        # One fixed pending name per destination bounds SIGKILL/retry leftovers.
        temporary = "." + name + ".pending"
        try:
            self.read(temporary, maximum)
        except FileNotFoundError:
            pass
        else:
            os.unlink(temporary, dir_fd=self.fd)
            os.fsync(self.fd)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(raw):
                size = os.write(descriptor, raw[offset:offset + 65536])
                if size <= 0:
                    raise ArtifactError("incomplete quarantine write")
                offset += size
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.read(temporary, maximum)
        os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)


class ArtifactStore:
    def __init__(self, git: HostGit, private_root: Path, *, assignment_digest: str,
                 target_ref: str, expected_base: str, expected_head: str | None = None,
                 authorize: Callable[[dict, dict], bool] | None = None,
                 authority_lock: Callable[[], ContextManager] | None = None,
                 limits: ArtifactLimits | None = None):
        if not isinstance(git, HostGit):
            raise ArtifactError("host object boundary is required")
        self.git = git
        self.limits = limits if limits is not None else ArtifactLimits()
        if type(self.limits) is not ArtifactLimits:
            raise ArtifactError("validated artifact limits are required")
        base = oid(expected_base)
        head = oid(expected_base if expected_head is None else expected_head)
        if base != head:
            raise ArtifactError("this profile requires the exact approved base as its expected projection head")
        self._assignment = {
            "repository": str(git.repository), "gitDir": str(git.git_dir),
            "assignmentDigest": _digest(assignment_digest), "targetRef": branch_ref(target_ref),
            "baseCommit": base, "expectedHead": head,
        }
        self.authorize = authorize
        self.authority_lock = authority_lock
        self._pid = os.getpid()
        self._poisoned = False
        self.root = _Directory(Path(private_root))
        try:
            self.directory = self.root.child(hashlib.sha256(_canonical(self.assignment)).hexdigest())
        except BaseException:
            self.root.close()
            raise

    @property
    def assignment(self):
        return copy.deepcopy(self._assignment)

    def close(self):
        self.directory.close()
        self.root.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    @contextmanager
    def _locked(self) -> Iterator[dict]:
        if self._poisoned or os.getpid() != self._pid:
            raise ArtifactError("artifact store is uncertain or belongs to another controller process")
        self.directory.check()
        descriptor = os.open("artifacts.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=self.directory.fd)
        acquired = False
        pid = os.getpid()
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size:
                raise ArtifactError("unsafe artifact lock")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ArtifactBusy("artifact assignment is already locked") from exc
            acquired = True
            binding = {"assignment": self.assignment, "limits": self.limits.as_dict()}
            try:
                recorded = self.directory.read("binding.json", 8192)
            except FileNotFoundError:
                if set(os.listdir(self.directory.fd)) != {"artifacts.lock"}:
                    raise ArtifactError("incomplete quarantine initialization requires reconciliation")
                self.directory.write("binding.json", _canonical(binding), immutable=True, maximum=8192)
                initial = {"schemaVersion": 1, **binding, "exports": {}}
                self.directory.write("exports.json", _canonical(initial), immutable=True, maximum=MAX_STATE_BYTES)
                recorded = _canonical(binding)
            if recorded != _canonical(binding):
                raise ArtifactError("quarantine assignment or quota policy changed")
            state = _json(self.directory.read("exports.json", MAX_STATE_BYTES), MAX_STATE_BYTES)
            self._validate_state(state)
            yield state
        except OSError as exc:
            self._poisoned = True
            raise ArtifactError("quarantine I/O is uncertain; reconciliation required") from exc
        finally:
            if acquired and os.getpid() == pid:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _validate_state(self, state):
        if (
            set(state) != _STATE_FIELDS or type(state["schemaVersion"]) is not int or state["schemaVersion"] != 1
            or state["assignment"] != self.assignment or state["limits"] != self.limits.as_dict()
            or type(state["exports"]) is not dict or len(state["exports"]) > self.limits.max_exports
        ):
            raise ArtifactError("unknown or mismatched quarantine state")
        total = 0
        for key, record in state["exports"].items():
            if type(record) is not dict or set(record) != _RECORD_FIELDS:
                raise ArtifactError("invalid export journal record")
            manifest = parse_manifest(record["manifest"], self.limits)
            if key != hashlib.sha256(manifest["id"].encode()).hexdigest() or manifest["baseCommit"] != self.assignment["baseCommit"]:
                raise ArtifactError("export identity is bound to another assignment")
            if record["manifestDigest"] != _sha(_canonical(manifest)) or type(record["state"]) is not str or record["state"] not in {"staging", "collected", "prepared", "promoted"}:
                raise ArtifactError("export journal digest or state is invalid")
            commit = self._commit(manifest)
            if record["commitHex"] != commit.hex() or record["candidateCommit"] != object_id("commit", commit):
                raise ArtifactError("candidate commit differs from the host-assigned bytes")
            if (record["state"] == "promoted") != (record["receipt"] is not None):
                raise ArtifactError("promotion receipt state is inconsistent")
            if record["receipt"] is not None and record["receipt"] != self._receipt(record, promoted=True):
                raise ArtifactError("promotion receipt does not match the immutable candidate")
            total += sum(change.get("size", 0) for change in manifest["changes"])
        if total > self.limits.max_staged_bytes:
            raise ArtifactError("permanent staging budget exceeded")

    def _save(self, state):
        self._validate_state(state)
        raw = _canonical(state)
        if len(raw) > MAX_STATE_BYTES:
            raise ArtifactError("quarantine metadata quota exhausted")
        try:
            self.directory.write("exports.json", raw, immutable=False, maximum=MAX_STATE_BYTES)
        except BaseException:
            self._poisoned = True
            raise

    def _commit(self, manifest):
        return (
            f"tree {manifest['resultingTree']}\nparent {self.assignment['expectedHead']}\n"
            "author Startup Factory <sandbox@startup-factory.invalid> 0 +0000\n"
            "committer Startup Factory <sandbox@startup-factory.invalid> 0 +0000\n\n"
            f"Sandbox export {manifest['id']}\nManifest {_sha(_canonical(manifest))}\n"
            f"Assignment {self.assignment['assignmentDigest']}\n"
        ).encode("utf-8")

    def _receipt(self, record, *, promoted):
        return {
            "schemaVersion": 1, "kind": "sandbox-promotion" if promoted else "sandbox-quarantine",
            "exportId": record["manifest"]["id"], "assignmentDigest": self.assignment["assignmentDigest"],
            "manifestDigest": record["manifestDigest"], "baseCommit": self.assignment["baseCommit"],
            "tree": record["manifest"]["resultingTree"], "commit": record["candidateCommit"],
            "targetRef": self.assignment["targetRef"], "previousHead": self.assignment["expectedHead"],
        }

    def _candidate(self, manifest, blobs, *, check_time=lambda: None):
        check_time()
        entries = self.git.entries(self.assignment["baseCommit"])
        check_time()
        base_tree, _trees = tree_objects(entries)
        check_time()
        approved_tree = self.git.commit_tree(self.assignment["baseCommit"])
        check_time()
        if base_tree != approved_tree:
            raise ArtifactError("approved base tree could not be reproduced exactly")
        for change in manifest["changes"]:
            check_time()
            path, operation = change["path"], change["operation"]
            if operation == "add" and path in entries or operation != "add" and path not in entries:
                raise ArtifactError("artifact operation does not match the exact approved base")
            if operation != "add" and entries[path][0] not in FILE_MODES:
                raise ArtifactError("changes to existing symlinks or submodules are unsupported")
            if operation == "delete":
                del entries[path]
            else:
                content = blobs[change["sha256"]]
                if type(content) is not bytes or len(content) != change["size"] or _sha(content) != change["sha256"]:
                    raise ArtifactError("artifact content size or digest differs from its manifest")
                entries[path] = change["mode"], object_id("blob", content)
        if len(entries) > 10_000:
            raise ArtifactError("resulting tree entry count exceeds the host bound")
        tree, objects = tree_objects(entries)
        check_time()
        if tree != manifest["resultingTree"]:
            raise ArtifactError("guest tree claim differs from the independently computed full tree")
        return objects

    def collect(self, manifest: bytes | dict, blobs: dict[str, bytes]) -> dict:
        deadline = time.monotonic() + self.limits.operation_seconds
        def check_time():
            if time.monotonic() >= deadline:
                raise ArtifactError("artifact collection deadline exceeded")
        check_time()
        manifest = parse_manifest(manifest, self.limits)
        if manifest["baseCommit"] != self.assignment["baseCommit"]:
            raise ArtifactError("manifest uses an unapproved source base")
        required = {change["sha256"] for change in manifest["changes"] if change["operation"] != "delete"}
        if type(blobs) is not dict:
            raise ArtifactError("artifact content must be a plain bounded mapping")
        blobs = dict(blobs)
        if set(blobs) != required:
            raise ArtifactError("artifact content set must exactly match its manifest")
        self._candidate(manifest, blobs, check_time=check_time)
        key = hashlib.sha256(manifest["id"].encode()).hexdigest()
        with self._locked() as state:
            check_time()
            record = state["exports"].get(key)
            if record is None:
                total = sum(change.get("size", 0) for value in state["exports"].values() for change in value["manifest"]["changes"])
                size = sum(change.get("size", 0) for change in manifest["changes"])
                if len(state["exports"]) >= self.limits.max_exports or total + size > self.limits.max_staged_bytes:
                    raise ArtifactError("permanent export or staging quota exhausted")
                commit = self._commit(manifest)
                record = {"manifest": manifest, "manifestDigest": _sha(_canonical(manifest)), "state": "staging",
                          "candidateCommit": object_id("commit", commit), "commitHex": commit.hex(), "receipt": None}
                state["exports"][key] = record
                self._save(state)  # Counts the export before writing content.
            elif record["manifest"] != manifest:
                raise ArtifactError("export ID cannot be reused with different bytes")
            directory = self.directory.child(key)
            try:
                for digest, content in blobs.items():
                    check_time()
                    directory.write(digest[7:], content, immutable=True, maximum=self.limits.max_file_bytes)
                    check_time()
            finally:
                directory.close()
            if record["state"] == "staging":
                record["state"] = "collected"
                self._save(state)
            return self._receipt(record, promoted=False)

    def _read_blobs(self, key, record, *, check_time=lambda: None):
        directory = self.directory.child(key)
        try:
            blobs = {}
            for change in record["manifest"]["changes"]:
                check_time()
                if change["operation"] != "delete":
                    digest = change["sha256"]
                    raw = directory.read(digest[7:], self.limits.max_file_bytes)
                    check_time()
                    if len(raw) != change["size"] or _sha(raw) != digest:
                        raise ArtifactError("quarantined artifact bytes changed")
                    blobs[digest] = raw
            return blobs
        finally:
            directory.close()

    def candidate_source(self, export_id: str, *, contains_secret: Callable[[str], bool]) -> bytes:
        """Build fresh review input without publishing objects or moving refs."""
        from sandbox_source import build_source_package
        key = hashlib.sha256(_export_id(export_id).encode()).hexdigest()
        deadline = time.monotonic() + self.limits.operation_seconds
        def check_time():
            if time.monotonic() >= deadline:
                raise ArtifactError("candidate source deadline exceeded")
        with self._locked() as state:
            record = state["exports"].get(key)
            if record is None or record["state"] == "staging":
                raise ArtifactError("candidate is not completely quarantined")
            blobs = self._read_blobs(key, record, check_time=check_time)
            trees = self._candidate(record["manifest"], blobs, check_time=check_time)
            objects = {object_id("blob", raw): ("blob", raw) for raw in blobs.values()}
            objects.update({identifier: ("tree", raw) for identifier, raw in trees.items()})
            objects[record["candidateCommit"]] = "commit", bytes.fromhex(record["commitHex"])
            def read(kind, identifier):
                check_time()
                if identifier in objects:
                    actual_kind, raw = objects[identifier]
                    if actual_kind != kind:
                        raise ArtifactError("candidate object type differs")
                    return raw
                return self.git.read_object(kind, identifier)
            return build_source_package(record["candidateCommit"], read, contains_secret=contains_secret)

    def promote(self, export_id: str) -> dict:
        if not callable(self.authorize) or not callable(self.authority_lock):
            raise ArtifactError("promotion requires an external task authority lock and authorizer")
        export_id = _export_id(export_id)
        key = hashlib.sha256(export_id.encode()).hexdigest()
        deadline = time.monotonic() + self.limits.operation_seconds
        def check_time():
            if time.monotonic() >= deadline:
                raise ArtifactError("artifact promotion deadline exceeded")
        def authorized(record):
            return self.authorize(copy.deepcopy(self.assignment), copy.deepcopy(self._receipt(record, promoted=False))) is True
        check_time()
        with self.authority_lock():
            check_time()
            with self._locked() as state:
                check_time()
                record = state["exports"].get(key)
                if record is None or record["state"] == "staging":
                    raise ArtifactError("export is not completely quarantined")
                if record["state"] == "promoted":
                    return copy.deepcopy(record["receipt"])
                head = self.git.read_ref(self.assignment["targetRef"])
                check_time()
                commit = bytes.fromhex(record["commitHex"])
                if record["state"] == "prepared" and head == record["candidateCommit"]:
                    if self.git.read_commit(head) != commit:
                        raise ArtifactError("recovery candidate bytes do not match the prepared journal")
                    check_time()
                else:
                    if head != self.assignment["expectedHead"]:
                        raise ArtifactError("assigned host projection moved; refusing to restore or replace it")
                    if not authorized(record):
                        raise ArtifactError("artifact promotion is not currently authorized")
                    check_time()
                    blobs = self._read_blobs(key, record, check_time=check_time)
                    check_time()
                    trees = self._candidate(record["manifest"], blobs, check_time=check_time)
                    check_time()
                    record["state"] = "prepared"
                    self._save(state)  # Stable exact commit precedes object writes/ref CAS.
                    for raw in blobs.values():
                        check_time()
                        self.git.write_object("blob", raw)
                    for identifier, raw in trees.items():
                        check_time()
                        if self.git.write_object("tree", raw) != identifier:
                            raise ArtifactError("written full tree differs from its accepted bytes")
                    check_time()
                    if self.git.write_object("commit", commit) != record["candidateCommit"]:
                        raise ArtifactError("written commit differs from the stable promotion intent")
                    check_time()
                    if not authorized(record):
                        raise ArtifactError("artifact authority changed during collection/promotion")
                    check_time()
                    self.git.compare_and_swap(self.assignment["targetRef"], self.assignment["expectedHead"], record["candidateCommit"])
                record["receipt"] = self._receipt(record, promoted=True)
                record["state"] = "promoted"
                self._save(state)
                return copy.deepcopy(record["receipt"])
