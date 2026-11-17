#!/usr/bin/env python3
"""Closed host relay context and bounded artifact-only framed transport.

No function in this module creates a sandbox or executes a guest-selected
command. Enrollment and the outer watchdog remain controller responsibilities.
The relay is a native child of the existing publication supervisor, and only
that supervisor can authorize a fresh producer signature.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import stat
import struct
import sys
import threading
import time
from typing import Any, Callable
import uuid


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from startup_factory_cli.execution_backend import BackendIdentity, LaunchScope  # noqa: E402
from startup_factory_cli.sandbox_registry import RegistryError, SandboxRegistry  # noqa: E402
from sandbox_ingest import (  # noqa: E402
    ArtifactAdmission, BoundContext, IngestError, _Directory, _strict_json,
    parse_request, recover_exact_admission, request_signature,
)


MAX_REQUEST_FRAME_BYTES = 192 * 1024
MAX_RESPONSE_FRAME_BYTES = 16 * 1024
MAX_CONTEXT_BYTES = 64 * 1024
PUBLICATION_STATES = frozenset({"running", "collecting"})
FORBIDDEN_ARTIFACT_MARKERS = frozenset({"production-approval", "deployment"})
CONTEXT_FIELDS = {
    "schemaVersion", "registryRoot", "registryId", "namespace", "name",
    "generation", "epoch", "sandboxId", "createdAt", "scope", "boundContext",
    "allowedArtifacts", "limits",
    "watchdog",
}
BOUND_FIELDS = {
    "repository", "workspace", "team", "feature", "role", "task", "attempt",
    "generation", "transport",
}
LIMIT_FIELDS = {
    "wallSeconds", "frameSeconds", "writeSeconds", "maxRequests",
    "maxOutputBytes", "maxContextRequests", "maxTotalBodyBytes",
}
_REGISTRY_ID = re.compile(r"reg-[0-9a-f]{32}\Z")
_NAME = re.compile(r"sf-[0-9a-f]{32}\Z")
_GENERATION = re.compile(r"gen-[0-9a-f]{32}\Z")
_NAMESPACE = re.compile(r"sf-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_MARKER = re.compile(r"[a-z0-9-]{2,80}\Z")
_REQUEST_ID = re.compile(r"[0-9a-f]{16,128}\Z")
_RESPONSE_FIELDS = {"schemaVersion", "id", "operation", "entryId", "status"}
ERROR_RESPONSE = {"schemaVersion": 1, "error": "artifact admission denied"}


class RelayError(RuntimeError):
    """Only this generic message may cross the guest boundary."""


class TransportDeadline(BaseException):
    """Unwind a blocked native handler as well as framed reads/writes."""


def verify_watchdog_lease(deployment_path: Path, **bindings: Any) -> bool:
    # Lazy import keeps descriptor parsing independent of a runtime installer.
    # A missing production implementation is a denial, never an allow fallback.
    from startup_factory_cli.sandbox_watchdog import verify_watchdog_lease as verify
    return verify(deployment_path, **bindings) is True


def _deny() -> RelayError:
    return RelayError("relay request denied")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def project_id_for_repository(repository: Path) -> str:
    """Identity convention: SHA-256 of the canonical absolute repo path in UTF-8."""
    return "sha256:" + hashlib.sha256(str(repository).encode("utf-8")).hexdigest()


def _seconds(value: Any, maximum: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0.05 <= value <= maximum:
        raise _deny()
    return float(value)


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _deny()
    return value


@dataclasses.dataclass(frozen=True)
class RelayLimits:
    wall_seconds: float = 1800.0
    frame_seconds: float = 10.0
    write_seconds: float = 10.0
    max_requests: int = 64
    max_output_bytes: int = 1024 * 1024
    max_context_requests: int = 64
    max_total_body_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        _seconds(self.wall_seconds, 86400)
        _seconds(self.frame_seconds, 10)
        _seconds(self.write_seconds, 10)
        _integer(self.max_requests, 1, 4096)
        _integer(self.max_output_bytes, 64, 16 * 1024 * 1024)
        _integer(self.max_context_requests, 1, 1024)
        _integer(self.max_total_body_bytes, 1, 64 * 1024 * 1024)

    def as_dict(self) -> dict[str, Any]:
        def seconds(value):
            return int(value) if float(value).is_integer() else value
        return {
            "wallSeconds": seconds(self.wall_seconds), "frameSeconds": seconds(self.frame_seconds),
            "writeSeconds": seconds(self.write_seconds), "maxRequests": self.max_requests,
            "maxOutputBytes": self.max_output_bytes,
            "maxContextRequests": self.max_context_requests,
            "maxTotalBodyBytes": self.max_total_body_bytes,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RelayLimits":
        if type(value) is not dict or set(value) != LIMIT_FIELDS:
            raise _deny()
        return cls(value["wallSeconds"], value["frameSeconds"], value["writeSeconds"], value["maxRequests"], value["maxOutputBytes"], value["maxContextRequests"], value["maxTotalBodyBytes"])


@dataclasses.dataclass(frozen=True)
class RelayContext:
    registry_root: Path
    registry_id: str
    namespace: str
    name: str
    generation: str
    epoch: int
    sandbox_id: str
    created_at: str
    scope: LaunchScope
    bound: BoundContext
    allowed_artifacts: tuple[tuple[str, tuple[str | None, ...]], ...]
    limits: RelayLimits
    watchdog: tuple[str, str, int]

    @classmethod
    def from_dict(cls, data: Any) -> "RelayContext":
        try:
            if type(data) is not dict or set(data) != CONTEXT_FIELDS or type(data["schemaVersion"]) is not int or data["schemaVersion"] != 1:
                raise _deny()
            registry_root = Path(data["registryRoot"])
            if not registry_root.is_absolute() or os.path.abspath(registry_root) != str(registry_root):
                raise _deny()
            if not isinstance(data["registryId"], str) or not _REGISTRY_ID.fullmatch(data["registryId"]):
                raise _deny()
            if not isinstance(data["namespace"], str) or len(data["namespace"]) > 20 or not _NAMESPACE.fullmatch(data["namespace"]):
                raise _deny()
            if not isinstance(data["name"], str) or not _NAME.fullmatch(data["name"]):
                raise _deny()
            if not isinstance(data["generation"], str) or not _GENERATION.fullmatch(data["generation"]):
                raise _deny()
            _integer(data["epoch"], 1, (1 << 63) - 1)
            identity = BackendIdentity(data["name"], data["sandboxId"], data["createdAt"])
            scope = LaunchScope.from_dict(data["scope"])
            raw_bound = data["boundContext"]
            if type(raw_bound) is not dict or set(raw_bound) != BOUND_FIELDS:
                raise _deny()
            bound = BoundContext(**raw_bound)
            if scope.project_id != project_id_for_repository(bound.repository) or scope.team != bound.team or scope.feature_id != bound.feature or scope.role != bound.role or bound.generation != data["generation"]:
                raise _deny()
            # A gate's VM scope may be '-' / 0, but this relay still has one
            # concrete host-assigned review package and positive attempt.
            if scope.task_id != "-" and (scope.task_id, scope.attempt) != (bound.task, bound.attempt):
                raise _deny()
            policy = data["allowedArtifacts"]
            if type(policy) is not dict or len(policy) > 64:
                raise _deny()
            allowed: list[tuple[str, tuple[str | None, ...]]] = []
            for marker, statuses in sorted(policy.items()):
                if not isinstance(marker, str) or not _MARKER.fullmatch(marker) or marker in FORBIDDEN_ARTIFACT_MARKERS or type(statuses) is not list or not 1 <= len(statuses) <= 16:
                    raise _deny()
                seen: set[str | None] = set()
                for status in statuses:
                    if status is not None and (not isinstance(status, str) or not 0 < len(status) <= 128 or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in status)):
                        raise _deny()
                    if status in seen:
                        raise _deny()
                    seen.add(status)
                allowed.append((marker, tuple(statuses)))
            watchdog = data["watchdog"]
            if type(watchdog) is not dict or set(watchdog) != {"deploymentPath", "leaseId", "deadline"}:
                raise _deny()
            deployment = Path(watchdog["deploymentPath"])
            if not deployment.is_absolute() or str(deployment) != os.path.abspath(deployment) or not isinstance(watchdog["leaseId"], str) or not re.fullmatch(r"[0-9a-f]{32}", watchdog["leaseId"]):
                raise _deny()
            _integer(watchdog["deadline"], 1, (1 << 63) - 1)
            return cls(registry_root, data["registryId"], data["namespace"], data["name"], data["generation"], data["epoch"], identity.sandbox_id, identity.created_at, scope, bound, tuple(allowed), RelayLimits.from_dict(data["limits"]), (str(deployment), watchdog["leaseId"], watchdog["deadline"]))
        except (ValueError, TypeError, OSError, KeyError, IngestError) as exc:
            raise _deny() from exc

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1, "registryRoot": str(self.registry_root),
            "registryId": self.registry_id, "namespace": self.namespace,
            "name": self.name, "generation": self.generation, "epoch": self.epoch,
            "sandboxId": self.sandbox_id, "createdAt": self.created_at,
            "scope": self.scope.as_dict(), "boundContext": self.bound.as_dict(),
            "allowedArtifacts": {marker: list(statuses) for marker, statuses in self.allowed_artifacts},
            "limits": self.limits.as_dict(),
            "watchdog": {"deploymentPath": self.watchdog[0], "leaseId": self.watchdog[1], "deadline": self.watchdog[2]},
        }

    @classmethod
    def from_file(cls, path: Path) -> "RelayContext":
        """Read a single account-owned mode-0600 context inside its registry."""
        descriptor: int | None = None
        try:
            path = Path(path)
            if not path.is_absolute() or os.path.abspath(path) != str(path):
                raise _deny()
            with _Directory.open(path.parent, private=True) as parent:
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent.fd)
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= MAX_CONTEXT_BYTES:
                    raise _deny()
                raw = bytearray()
                while len(raw) <= MAX_CONTEXT_BYTES:
                    block = os.read(descriptor, min(65536, MAX_CONTEXT_BYTES + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                after = os.fstat(descriptor)
                named = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
                identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
                if len(raw) != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
                    raise _deny()
                context = cls.from_dict(_strict_json(bytes(raw), MAX_CONTEXT_BYTES))
                if path.parent != context.registry_root:
                    raise _deny()
                # The registry applies the stricter ancestor contract (shared
                # /tmp is rejected); never initialize it during context loading.
                with SandboxRegistry(context.registry_root, context.namespace) as registry:
                    marker, _ = registry._file("registry.identity", maximum=4096)
                    identity_record = _strict_json(marker, 4096)
                    if type(identity_record) is not dict or identity_record.get("registryId") != context.registry_id or identity_record.get("namespace") != context.namespace:
                        raise _deny()
                return context
        except Exception as exc:
            raise _deny() from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)


class ArtifactRelay:
    """One native context, with namespace→journal→capability lock ordering."""

    def __init__(self, context: RelayContext, registry: SandboxRegistry | None = None, *, signer: Callable = request_signature, recover: Callable | None = recover_exact_admission, admission_factory: Callable = ArtifactAdmission, watchdog_verify: Callable | None = None):
        # The native integration may construct dataclasses directly. Apply the
        # same closed schema and cross-field binding checks as file callers
        # before retaining a registry, opening directories, or signing.
        try:
            if type(context) is not RelayContext:
                raise _deny()
            validated = RelayContext.from_dict(context.as_dict())
            if validated != context:
                raise _deny()
            context = validated
        except Exception as exc:
            raise _deny() from exc
        self.context = context
        self._watchdog_verify = watchdog_verify or verify_watchdog_lease
        self.registry = registry if registry is not None else SandboxRegistry(context.registry_root, context.namespace)
        self._owns_registry = registry is None
        self._transaction: Any = None
        self.admission: ArtifactAdmission | None = None
        try:
            if self.registry.root != context.registry_root or self.registry.namespace != context.namespace:
                raise _deny()
            self.admission = admission_factory(context.bound, context.registry_root / "artifact-admissions", authorize=self._authorize, signer=signer, recover=recover, max_requests=context.limits.max_context_requests, max_total_body_bytes=context.limits.max_total_body_bytes)
        except Exception as exc:
            self.close()
            raise _deny() from exc

    def _authorize(self, bound: BoundContext, request: dict[str, Any]) -> bool:
        transaction = self._transaction
        if transaction is None or bound != self.context.bound or request["marker"] in FORBIDDEN_ARTIFACT_MARKERS:
            return False
        if not self._watchdog_live():
            return False
        if transaction.registry_id != self.context.registry_id or transaction.epoch != self.context.epoch:
            return False
        records = [record for record in transaction.records() if record["name"] == self.context.name]
        if len(records) != 1:
            return False
        record = records[0]
        if record["generation"] != self.context.generation or record["epoch"] != self.context.epoch or record["sandboxId"] != self.context.sandbox_id or record["createdAt"] != self.context.created_at or record["scope"] != self.context.scope.as_dict() or record["state"] not in PUBLICATION_STATES:
            return False
        return any(marker == request["marker"] and request["targetStatus"] in statuses for marker, statuses in self.context.allowed_artifacts)

    def _watchdog_live(self) -> bool:
        try:
            deployment, lease_id, deadline = self.context.watchdog
            return self._watchdog_verify(Path(deployment), name=self.context.name,
                generation=self.context.generation, epoch=self.context.epoch,
                lease_id=lease_id, deadline=deadline) is True
        except Exception:
            return False

    def handle(self, raw: bytes) -> dict[str, Any]:
        try:
            request, _body = parse_request(raw)
            if self.admission is None:
                raise _deny()
            if not self._watchdog_live():
                # No namespace flock is needed to acknowledge or finish an
                # exact prior admission. With no transaction, authorize is
                # unconditionally False, so a fresh package cannot be signed.
                return self.admission.submit(request)
            with self.registry.locked() as transaction:
                if transaction.registry_id != self.context.registry_id:
                    raise _deny()
                # Epoch/liveness deliberately remain inside authorize. Exact
                # durable admissions may finish/ack after a fence or takeover.
                self._transaction = transaction
                try:
                    return self.admission.submit(request)
                finally:
                    self._transaction = None
        except Exception as exc:
            raise _deny() from exc

    def close(self) -> None:
        if self.admission is not None:
            self.admission.close()
            self.admission = None
        if self._owns_registry:
            self.registry.close()

    def __enter__(self) -> "ArtifactRelay":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.close()


def _wait(descriptor: int, *, write: bool, deadline: float) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportDeadline
        try:
            readable, writable, _ = select.select([] if write else [descriptor], [descriptor] if write else [], [], remaining)
        except InterruptedError:
            continue
        if writable if write else readable:
            return


def _read_exact(descriptor: int, size: int, *, deadline: float, clean_eof: bool = False) -> bytes | None:
    value = bytearray()
    while len(value) < size:
        _wait(descriptor, write=False, deadline=deadline)
        try:
            block = os.read(descriptor, size - len(value))
        except (BlockingIOError, InterruptedError):
            continue
        if not block:
            if clean_eof and not value:
                return None
            raise _deny()
        value.extend(block)
    return bytes(value)


def _write_all(descriptor: int, content: bytes, *, deadline: float) -> None:
    offset = 0
    while offset < len(content):
        _wait(descriptor, write=True, deadline=deadline)
        try:
            count = os.write(descriptor, content[offset:])
        except (BlockingIOError, InterruptedError):
            continue
        if count <= 0:
            raise _deny()
        offset += count


def response_frame(value: dict[str, Any]) -> bytes:
    """Reject accidental host data or capability fields before writing stdout."""
    if type(value) is not dict:
        raise _deny()
    if type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        raise _deny()
    if value != ERROR_RESPONSE:
        if set(value) != _RESPONSE_FIELDS or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or value["operation"] != "artifact.submit" or value["status"] != "admitted":
            raise _deny()
        identifier = value["id"]
        try:
            if not isinstance(identifier, str) or not (_REQUEST_ID.fullmatch(identifier) or str(uuid.UUID(identifier)) == identifier) or str(uuid.UUID(value["entryId"])) != value["entryId"]:
                raise _deny()
        except (ValueError, TypeError, AttributeError) as exc:
            raise _deny() from exc
    payload = _canonical(value)
    if not 0 < len(payload) <= MAX_RESPONSE_FRAME_BYTES:
        raise _deny()
    return struct.pack("!I", len(payload)) + payload


def serve_framed(handler: Callable[[bytes], dict[str, Any]], limits: RelayLimits, *, input_fd: int = 0, output_fd: int = 1) -> int:
    """Serve one bounded native process session; no stdout lock is held by handler.

    Idle time before the first byte is allowed within the overall deadline.
    After any header byte arrives, the entire frame has its own short deadline.
    A POSIX process timer also interrupts synchronous host admission work.
    """
    if type(limits) is not RelayLimits or not callable(handler) or threading.current_thread() is not threading.main_thread() or os.isatty(input_fd) or os.isatty(output_fd):
        raise _deny()
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise _deny()
    original_handler = signal.getsignal(signal.SIGALRM)
    original_blocking = {descriptor: os.get_blocking(descriptor) for descriptor in {input_fd, output_fd}}
    deadline = time.monotonic() + limits.wall_seconds
    written = 0
    writing_response = False
    def expired(_signum: int, _frame: Any) -> None:
        raise TransportDeadline
    try:
        for descriptor in original_blocking:
            os.set_blocking(descriptor, False)
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, limits.wall_seconds)
        for _ in range(limits.max_requests):
            first = _read_exact(input_fd, 1, deadline=deadline, clean_eof=True)
            if first is None:
                return 0
            frame_deadline = min(deadline, time.monotonic() + limits.frame_seconds)
            remainder = _read_exact(input_fd, 3, deadline=frame_deadline)
            assert remainder is not None
            size = struct.unpack("!I", first + remainder)[0]
            if not 0 < size <= MAX_REQUEST_FRAME_BYTES:
                raise _deny()
            raw = _read_exact(input_fd, size, deadline=frame_deadline)
            assert raw is not None
            request, _body = parse_request(raw)
            response = handler(raw)
            if response.get("id") != request["id"]:
                raise _deny()
            frame = response_frame(response)
            if written + len(frame) > limits.max_output_bytes:
                raise _deny()
            writing_response = True
            _write_all(output_fd, frame, deadline=min(deadline, time.monotonic() + limits.write_seconds))
            writing_response = False
            written += len(frame)
        return 0
    except TransportDeadline:
        return 124
    except Exception:
        # Never include exception details, paths, request bodies, or capability
        # data in either channel. An error terminates this bounded session.
        frame = response_frame(ERROR_RESPONSE)
        if not writing_response and written + len(frame) <= limits.max_output_bytes:
            try:
                _write_all(output_fd, frame, deadline=min(deadline, time.monotonic() + 0.1))
            except (TransportDeadline, OSError, RelayError):
                pass
        return 64
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original_handler)
        for descriptor, was_blocking in original_blocking.items():
            os.set_blocking(descriptor, was_blocking)
