#!/usr/bin/env python3
"""Host-only, durable admission of one sandbox's bounded artifact requests.

This is a library for a trusted native relay, not a guest command or a generic
RPC server. The caller supplies the protected context and current-generation
authorization function. Only the existing publication supervisor signs new
packages; neither signing keys nor producer capabilities are returned to a
guest. Signing already durably admits a package in outbox_capability, so exact
retries may finish queueing after revocation without creating new authority.
"""

from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import json
import os
import re
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from outbox_capability import (
    CapabilityError,
    OUTBOX_CAPABILITY_FIELD,
    OUTBOX_PRODUCER_FIELDS,
    admission_directory,
    producer_envelope,
    request_signature,
    signed_material,
    verify_entry,
)


MAX_BODY_BYTES = 65536
MAX_REQUEST_BYTES = MAX_BODY_BYTES * 2 + 4096
MAX_JOURNAL_BYTES = MAX_REQUEST_BYTES + 32768
MAX_RECOVERY_RECORDS = 10000
DEFAULT_MAX_REQUESTS = 64
DEFAULT_MAX_TOTAL_BODY_BYTES = 4 * 1024 * 1024
_JOURNAL_NAME = re.compile(r"[0-9a-f]{64}\.json\Z")
REQUEST_FIELDS = {"schemaVersion", "id", "operation", "marker", "bodyHex", "targetStatus"}
CAPABILITY_FIELDS = {"schemaVersion", "id", "instance", "expiresAt", "bodySha256", "signature"}
ADMISSION_FIELDS = {
    "schemaVersion", "capabilityId", "capabilityInstance", "capabilityExpiresAt",
    "canonicalRepo", "canonicalWorkspace", "team", "featureId", "executionKind",
    "role", "taskId", "attempt", "entryId", "entryMaterialSha256", "bodySha256",
    "signature", "admittedAt",
}
JOURNAL_FIELDS = {
    "schemaVersion", "context", "requestSha256", "request", "entry", "state",
    "producerCapability",
}
_HEX = re.compile(r"[0-9a-f]*\Z")
_REQUEST_HEX = re.compile(r"[0-9a-f]{16,128}\Z")
_MARKER = re.compile(r"[a-z0-9-]{2,80}\Z")
_ROLE = re.compile(r"[a-z0-9-]{2,80}\Z")
_TEAM = re.compile(r"[A-Za-z0-9._-]{1,63}\Z")
_CAPABILITY_ID = re.compile(r"cap-[0-9a-f]{32}\Z")
_SIGNATURE = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_ADMISSION_NAME = re.compile(r"admission-[0-9a-f]{64}\.json\Z")


class IngestError(RuntimeError):
    """A deliberately generic denial safe to return across the guest boundary."""


def _deny() -> IngestError:
    return IngestError("artifact admission denied")


def _text(value: Any, maximum: int) -> bool:
    return (
        isinstance(value, str) and 0 < len(value) <= maximum
        and not any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
    )


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _deny()
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise _deny()


def _strict_json(raw: bytes, maximum: int) -> Any:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum:
        raise _deny()
    # Bound nesting before the decoder can recurse. Structural correctness is
    # still decided by the JSON decoder, including quoted/escaped delimiters.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                quoted = False
        elif byte == 0x22:
            quoted = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > 12:
                raise _deny()
        elif byte in (0x5D, 0x7D):
            depth -= 1
            if depth < 0:
                raise _deny()
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise _deny() from exc


def _request_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if _REQUEST_HEX.fullmatch(value):
        return True
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def parse_request(raw: bytes | str | dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Validate a closed guest request; mapping callers must decode strictly upstream."""
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="strict")
        if isinstance(raw, bytes):
            value = _strict_json(raw, MAX_REQUEST_BYTES)
        elif type(raw) is dict:
            # Serialize before retaining: callers cannot mutate the request
            # while the native relay is authorizing or journaling it.
            value = _strict_json(_canonical(raw), MAX_REQUEST_BYTES)
        else:
            raise _deny()
        if type(value) is not dict or set(value) != REQUEST_FIELDS:
            raise _deny()
        if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
            raise _deny()
        if not _request_id(value["id"]) or value["operation"] != "artifact.submit":
            raise _deny()
        marker = value["marker"]
        if not isinstance(marker, str) or not _MARKER.fullmatch(marker):
            raise _deny()
        target = value["targetStatus"]
        if target is not None and not _text(target, 128):
            raise _deny()
        encoded = value["bodyHex"]
        if not isinstance(encoded, str) or not 2 <= len(encoded) <= MAX_BODY_BYTES * 2 or len(encoded) % 2 or not _HEX.fullmatch(encoded):
            raise _deny()
        body = bytes.fromhex(encoded)
        body.decode("utf-8", errors="strict")
        if b"\x00" in body or not body.startswith(("[" + marker + "]").encode("ascii")):
            raise _deny()
        return value, body
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise _deny() from exc


@dataclasses.dataclass(frozen=True)
class BoundContext:
    """Trusted host binding. Never construct this from a guest request."""

    repository: Path
    workspace: Path
    team: str
    feature: str
    role: str
    task: str
    attempt: int
    generation: str
    transport: str

    def __post_init__(self) -> None:
        try:
            for field in ("repository", "workspace"):
                value = Path(getattr(self, field))
                if not value.is_absolute() or os.path.abspath(value) != str(value):
                    raise _deny()
                object.__setattr__(self, field, value)
            if self.workspace == self.repository:
                raise _deny()
            self.workspace.relative_to(self.repository)
            if not isinstance(self.team, str) or self.team in {".", ".."} or not _TEAM.fullmatch(self.team):
                raise _deny()
            if not isinstance(self.role, str) or not _ROLE.fullmatch(self.role):
                raise _deny()
            if not all(_text(value, limit) for value, limit in ((self.feature, 1024), (self.task, 1024), (self.generation, 256), (self.transport, 4096))):
                raise _deny()
            if type(self.attempt) is not int or self.attempt < 1:
                raise _deny()
            if not self.transport.startswith("/") or os.path.abspath(self.transport) != self.transport or len(os.fsencode(self.transport)) >= 100:
                raise _deny()
        except (ValueError, TypeError, OSError) as exc:
            raise _deny() from exc

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": str(self.repository), "workspace": str(self.workspace),
            "team": self.team, "feature": self.feature, "role": self.role,
            "task": self.task, "attempt": self.attempt,
            "generation": self.generation, "transport": self.transport,
        }


class _Directory:
    """A retained, no-follow directory descriptor with directory-relative IO."""

    def __init__(self, path: Path, descriptor: int):
        self.path = path
        self.fd = descriptor

    @staticmethod
    def _check(info: os.stat_result, *, private: bool) -> None:
        if not stat.S_ISDIR(info.st_mode):
            raise _deny()
        if private:
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _deny()
        else:
            # A root-owned sticky /tmp is a valid ancestor of an exclusively
            # created owner-only root. Other writable ancestors are rejected.
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not sticky_root):
                raise _deny()

    @classmethod
    def open(cls, path: Path, *, private: bool = False, create: bool = False) -> "_Directory":
        path = Path(path)
        if not path.is_absolute() or os.path.abspath(path) != str(path):
            raise _deny()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open("/", flags)
        try:
            cls._check(os.fstat(descriptor), private=False)
            parts = path.parts[1:]
            for index, part in enumerate(parts):
                last = index == len(parts) - 1
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create or not last:
                        raise
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                try:
                    cls._check(os.fstat(child), private=private and last)
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            if not parts and private:
                cls._check(os.fstat(descriptor), private=True)
            return cls(path, descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def child(self, name: str) -> "_Directory":
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise _deny()
        try:
            os.mkdir(name, 0o700, dir_fd=self.fd)
            os.fsync(self.fd)
        except FileExistsError:
            pass
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            self._check(os.fstat(descriptor), private=True)
            return _Directory(self.path / name, descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def read(self, name: str, maximum: int) -> bytes:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) not in {0o400, 0o600} or not 0 < before.st_size <= maximum:
                raise _deny()
            value = bytearray()
            while len(value) <= maximum:
                chunk = os.read(descriptor, min(65536, maximum + 1 - len(value)))
                if not chunk:
                    break
                value.extend(chunk)
            after = os.fstat(descriptor)
            if len(value) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise _deny()
            return bytes(value)
        finally:
            os.close(descriptor)

    def _exclusive(self, name: str, content: bytes) -> None:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise _deny()
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(self.fd)

    def _remove_interrupted(self, name: str, maximum: int) -> None:
        # Remove only this immutable package's interrupted host staging files.
        # Otherwise SIGKILL/retry of an already-admitted request could leave a
        # fresh partial temporary on each retry without consuming a new slot.
        temporary_pattern = re.compile(re.escape("." + name + ".") + r"[0-9a-f]{32}\Z")
        with os.scandir(self.fd) as entries:
            for count, item in enumerate(entries, 1):
                if count > MAX_RECOVERY_RECORDS:
                    raise _deny()
                if not temporary_pattern.fullmatch(item.name):
                    continue
                descriptor = os.open(item.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
                try:
                    opened = os.fstat(descriptor)
                    named = os.stat(item.name, dir_fd=self.fd, follow_symlinks=False)
                    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600 or not 0 <= opened.st_size <= maximum or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                        raise _deny()
                    os.unlink(item.name, dir_fd=self.fd)
                    os.fsync(self.fd)
                finally:
                    os.close(descriptor)

    def ensure(self, name: str, content: bytes) -> None:
        self._remove_interrupted(name, len(content))
        try:
            existing = self.read(name, len(content))
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != content:
                raise _deny()
            return
        # Publish only complete, fsynced files. A crash during a direct write to
        # the final body/entry name would strand a truncated immutable package
        # that an otherwise exact retry could never repair. The request lock
        # serializes this host-assigned UUID; guests cannot access this root.
        temporary = "." + name + "." + uuid.uuid4().hex
        try:
            self._exclusive(temporary, content)
            try:
                existing = self.read(name, len(content))
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if existing != content:
                    raise _deny()
                return
            os.rename(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def replace(self, name: str, content: bytes) -> None:
        # Existing-ID retries intentionally do not allocate another quota slot.
        # Reconcile this journal's bounded crash leftovers under the same
        # context lock before creating another temporary file.
        self._remove_interrupted(name, MAX_JOURNAL_BYTES)
        temporary = "." + name + "." + uuid.uuid4().hex
        try:
            self._exclusive(temporary, content)
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "_Directory":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.close()


def _validated_capability(context: BoundContext, capability: Any, body: bytes) -> dict[str, Any]:
    if type(capability) is not dict or set(capability) != CAPABILITY_FIELDS:
        raise _deny()
    if type(capability["schemaVersion"]) is not int or capability["schemaVersion"] != 1:
        raise _deny()
    if not isinstance(capability["id"], str) or not _CAPABILITY_ID.fullmatch(capability["id"]):
        raise _deny()
    if not _text(capability["instance"], 256) or type(capability["expiresAt"]) is not int or capability["expiresAt"] <= 0:
        raise _deny()
    if capability["bodySha256"] != _digest(body) or not isinstance(capability["signature"], str) or not _SIGNATURE.fullmatch(capability["signature"]):
        raise _deny()
    locator_leaf = hashlib.sha256((str(context.repository) + "\0" + capability["id"]).encode("utf-8")).hexdigest()[:32]
    if Path(context.transport).name != locator_leaf:
        raise _deny()
    return dict(capability)


def recover_exact_admission(context: BoundContext, entry: dict[str, Any], body: bytes) -> dict[str, Any] | None:
    """Recover an existing signature, never mint one or consult an active key.

    The protected admission receipt retains the signature even if a supervisor
    response was lost. Its capability must belong to this transport and its
    complete envelope/body must pass the existing verifier, including the exact
    pre-fence admission check when the capability is inactive.
    """
    found: dict[str, Any] | None = None
    try:
        with _Directory.open(admission_directory(context.repository), private=True) as directory:
            with os.scandir(directory.fd) as records:
                for count, record in enumerate(records, 1):
                    if count > MAX_RECOVERY_RECORDS:
                        raise _deny()
                    if not _ADMISSION_NAME.fullmatch(record.name):
                        raise _deny()
                    receipt = _strict_json(directory.read(record.name, 16384), 16384)
                    if type(receipt) is not dict or set(receipt) != ADMISSION_FIELDS or type(receipt["schemaVersion"]) is not int or receipt["schemaVersion"] != 1:
                        raise _deny()
                    if receipt.get("entryId") != entry["id"]:
                        continue
                    if receipt.get("canonicalRepo") != str(context.repository) or receipt.get("canonicalWorkspace") != str(context.workspace) or receipt.get("team") != context.team or receipt.get("featureId") != context.feature or receipt.get("role") != context.role or receipt.get("bodySha256") != _digest(body):
                        raise _deny()
                    capability = _validated_capability(context, {
                        "schemaVersion": 1, "id": receipt["capabilityId"],
                        "instance": receipt["capabilityInstance"],
                        "expiresAt": receipt["capabilityExpiresAt"],
                        "bodySha256": receipt["bodySha256"], "signature": receipt["signature"],
                    }, body)
                    if type(receipt["admittedAt"]) is not int or not 0 < receipt["admittedAt"] < capability["expiresAt"]:
                        raise _deny()
                    binding = {key: value for key, value in receipt.items() if key != "admittedAt"}
                    if record.name != "admission-" + hashlib.sha256(_canonical(binding)).hexdigest() + ".json":
                        raise _deny()
                    if receipt["entryMaterialSha256"] != _digest(_canonical(signed_material(entry, capability, _digest(body), context.role))):
                        raise _deny()
                    verify_entry(str(context.repository), str(context.workspace), {**entry, OUTBOX_CAPABILITY_FIELD: capability}, _digest(body))
                    if found is not None and found != capability:
                        raise _deny()
                    found = capability
        return found
    except (CapabilityError, OSError, ValueError, TypeError, KeyError) as exc:
        raise _deny() from exc


Signer = Callable[[str, dict[str, Any], bytes], dict[str, Any]]
Authorizer = Callable[[BoundContext, dict[str, Any]], bool]
Recoverer = Callable[[BoundContext, dict[str, Any], bytes], dict[str, Any] | None]


class ArtifactAdmission:
    """Serialize one native context's durable artifact submissions.

    ``authorize`` must check host-owned generation/hold/action policy and return
    literal True for new signing. Existing immutable admissions can recover
    after revocation. The protected root and outbox directories are never made
    visible to the guest. Close the object when the relay session ends.
    """

    def __init__(self, context: BoundContext, protected_root: Path, *, authorize: Authorizer, signer: Signer = request_signature, recover: Recoverer | None = recover_exact_admission, max_requests: int = DEFAULT_MAX_REQUESTS, max_total_body_bytes: int = DEFAULT_MAX_TOTAL_BODY_BYTES):
        self.context = context
        self.authorize = authorize
        self.signer = signer
        self.recover = recover
        self.max_requests = max_requests
        self.max_total_body_bytes = max_total_body_bytes
        self._directories: list[_Directory] = []
        try:
            if not isinstance(context, BoundContext) or not callable(authorize) or not callable(signer) or (recover is not None and not callable(recover)):
                raise _deny()
            if type(max_requests) is not int or not 1 <= max_requests <= 1024 or type(max_total_body_bytes) is not int or not 1 <= max_total_body_bytes <= 64 * 1024 * 1024:
                raise _deny()
            for path in (context.repository, context.workspace):
                with _Directory.open(path):
                    pass
            root = self._keep(_Directory.open(Path(protected_root), private=True, create=True))
            scope = hashlib.sha256(_canonical(context.as_dict())).hexdigest()
            self.journal = self._keep(root.child(scope))
            workspace = self._keep(_Directory.open(context.workspace))
            outbox = self._keep(workspace.child("outbox"))
            self.pending = self._keep(outbox.child("pending"))
            self.bodies = self._keep(outbox.child("bodies"))
        except (OSError, ValueError, TypeError, IngestError) as exc:
            self.close()
            raise _deny() from exc

    def _keep(self, directory: _Directory) -> _Directory:
        self._directories.append(directory)
        return directory

    def close(self) -> None:
        for directory in reversed(self._directories):
            directory.close()
        self._directories.clear()

    def __enter__(self) -> "ArtifactAdmission":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.close()

    def _authorized(self, request: dict[str, Any]) -> bool:
        # Authorizers receive their own value, so a callback cannot change the
        # request already bound to the journal while answering True.
        return self.authorize(self.context, json.loads(_canonical(request))) is True

    def _load(self, filename: str, request: dict[str, Any], request_digest: str) -> dict[str, Any] | None:
        try:
            record = _strict_json(self.journal.read(filename, MAX_JOURNAL_BYTES), MAX_JOURNAL_BYTES)
        except FileNotFoundError:
            return None
        if type(record) is not dict or set(record) != JOURNAL_FIELDS or type(record["schemaVersion"]) is not int or record["schemaVersion"] != 1 or record["context"] != self.context.as_dict() or record["requestSha256"] != request_digest or record["request"] != request or record["state"] not in {"prepared", "signed", "queued"}:
            raise _deny()
        entry = record["entry"]
        if type(entry) is not dict or set(entry) != OUTBOX_PRODUCER_FIELDS:
            raise _deny()
        producer_envelope(entry)
        try:
            entry_id = str(uuid.UUID(entry["id"]))
        except (ValueError, AttributeError):
            raise _deny()
        if entry_id != entry["id"] or entry["bodyPath"] != str(self.bodies.path / (entry_id + ".md")) or entry["team"] != self.context.team or entry["featureId"] != self.context.feature or entry["taskId"] != self.context.task or entry["attempt"] != self.context.attempt or entry["actor"] != self.context.role or entry["marker"] != request["marker"] or entry["targetStatus"] != request["targetStatus"]:
            raise _deny()
        if (record["state"] == "prepared") != (record["producerCapability"] is None):
            raise _deny()
        return record

    def _save(self, filename: str, record: dict[str, Any]) -> None:
        raw = _canonical(record) + b"\n"
        if len(raw) > MAX_JOURNAL_BYTES:
            raise _deny()
        self.journal.replace(filename, raw)

    def _quota_usage(self) -> tuple[int, int]:
        count = total = 0
        with os.scandir(self.journal.fd) as entries:
            for item in entries:
                if item.name in {"context.lock", "quota.policy"}:
                    continue
                if not _JOURNAL_NAME.fullmatch(item.name):
                    # An interrupted/unrecognized journal requires explicit
                    # reconciliation; silently ignoring it allows accumulation.
                    raise _deny()
                value = _strict_json(self.journal.read(item.name, MAX_JOURNAL_BYTES), MAX_JOURNAL_BYTES)
                if type(value) is not dict or "request" not in value:
                    raise _deny()
                request, body = parse_request(value["request"])
                expected_name = hashlib.sha256(request["id"].encode("ascii")).hexdigest() + ".json"
                if item.name != expected_name:
                    raise _deny()
                record = self._load(item.name, request, _digest(_canonical(request)))
                if record is None:
                    raise _deny()
                if record["state"] != "prepared":
                    _validated_capability(self.context, record["producerCapability"], body)
                count += 1
                total += len(body)
                if count > self.max_requests or total > self.max_total_body_bytes:
                    raise _deny()
        return count, total

    def submit(self, raw: bytes | str | dict[str, Any]) -> dict[str, Any]:
        """Admit/queue an exact request or return its original stable receipt."""
        lock: int | None = None
        try:
            request, body = parse_request(raw)
            request_digest = _digest(_canonical(request))
            request_key = hashlib.sha256(request["id"].encode("ascii")).hexdigest()
            filename = request_key + ".json"
            # One durable context lock, before allocation or per-request state.
            # New request IDs cannot accumulate unbounded lock files, and
            # reconnects cannot reset the permanent request/body quotas.
            lock = os.open("context.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.journal.fd)
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise _deny()
            deadline = time.monotonic() + 12
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise _deny()
                    time.sleep(0.01)
            quota = {"schemaVersion": 1, "maxRequests": self.max_requests, "maxTotalBodyBytes": self.max_total_body_bytes}
            self.journal.ensure("quota.policy", _canonical(quota) + b"\n")
            record = self._load(filename, request, request_digest)
            fresh = record is None
            if record is None:
                if not self._authorized(request):
                    raise _deny()
                count, total = self._quota_usage()
                if count >= self.max_requests or total + len(body) > self.max_total_body_bytes:
                    raise _deny()
                identifier = str(uuid.uuid4())
                entry = {
                    "schemaVersion": 1, "id": identifier,
                    "team": self.context.team, "featureId": self.context.feature,
                    "taskId": self.context.task, "attempt": self.context.attempt,
                    "actor": self.context.role, "marker": request["marker"],
                    "bodyPath": str(self.bodies.path / (identifier + ".md")),
                    "targetStatus": request["targetStatus"], "phase": "pending",
                    "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                producer_envelope(entry)
                record = {"schemaVersion": 1, "context": self.context.as_dict(), "requestSha256": request_digest, "request": request, "entry": entry, "state": "prepared", "producerCapability": None}
                # This fsync precedes any call that can sign/durably admit.
                self._save(filename, record)
            entry = record["entry"]
            if record["state"] == "prepared":
                recovered = self.recover(self.context, dict(entry), body) if not fresh and self.recover is not None else None
                if recovered is None:
                    if not self._authorized(request):
                        raise _deny()
                    recovered = self.signer(self.context.transport, dict(entry), body)
                record["producerCapability"] = _validated_capability(self.context, recovered, body)
                record["state"] = "signed"
                self._save(filename, record)
            else:
                _validated_capability(self.context, record["producerCapability"], body)
            if record["state"] == "signed":
                self.bodies.ensure(entry["id"] + ".md", body)
                package = {**entry, OUTBOX_CAPABILITY_FIELD: record["producerCapability"]}
                self.pending.ensure(entry["id"] + ".json", _canonical(package) + b"\n")
                record["state"] = "queued"
                self._save(filename, record)
            return {"schemaVersion": 1, "id": request["id"], "operation": "artifact.submit", "entryId": entry["id"], "status": "admitted"}
        except Exception as exc:
            raise _deny() from exc
        finally:
            if lock is not None:
                try:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                finally:
                    os.close(lock)
