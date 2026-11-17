"""Closed data contracts for protected execution backends.

Validation, root-owned configuration, and digest equality do not establish
enrollment, containment, qualification, or permission to launch. Those decisions
belong to a separate authority boundary. This module never executes commands,
changes environment variables, or writes configuration.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol, Sequence


SCHEMA_VERSION = 1
PROTOCOL_VERSION = 1
BACKEND = "docker-sandboxes"
GUEST_WORKDIR = "/workspace/project"
MAX_PROFILE_BYTES = 64 * 1024
MAX_RUNTIME_BYTES = 256 * 1024 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_ITEMS = 256
MAX_STRING_BYTES = 4096
FILE_READ_BYTES = 64 * 1024
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_STAT_SUPPORTS_DIR_FD = os.stat in os.supports_dir_fd
_STAT_SUPPORTS_NOFOLLOW = os.stat in os.supports_follow_symlinks
PROFILE_FIELDS = frozenset({
    "schemaVersion", "backend", "protocolVersion", "controllerUid", "sbxPath",
    "sbxSha256", "namespace", "image", "guestWorkdir", "limits", "policyDigest",
    "qualificationDigest",
})
LIMIT_BOUNDS = {
    "cpus": (1, 64),
    "memoryMiB": (512, 262144),
    "rootDiskMiB": (512, 1048576),
    "dockerDiskMiB": (512, 1048576),
    "wallSeconds": (1, 86400),
    "maxOutputBytes": (1, 16 * 1024 * 1024),
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NAMESPACE = re.compile(r"sf-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_TEAM = re.compile(r"[A-Za-z0-9._-]{1,63}\Z")
_ROLE = re.compile(r"[a-z0-9][a-z0-9-]{1,79}\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_CREATED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)
_REGISTRY = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_REPOSITORY_PART = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\Z")


class BackendContractError(ValueError):
    """A backend descriptor is malformed, untrusted, or inconsistent."""


def _exact(value: object, fields: frozenset[str] | set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise BackendContractError(f"{label} requires exactly its supported fields")
    return value


def _text(value: object, label: str, *, maximum: int = MAX_STRING_BYTES) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise BackendContractError(f"{label} must be a bounded nonempty string")
    if any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise BackendContractError(f"{label} contains invalid Unicode or control characters")
    if len(value.encode("utf-8")) > maximum:
        raise BackendContractError(f"{label} exceeds its byte limit")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise BackendContractError(f"{label} must be an integer within its supported limits")
    return value


def _digest(value: object, label: str) -> str:
    result = _text(value, label, maximum=71)
    if not _DIGEST.fullmatch(result):
        raise BackendContractError(f"{label} must be a canonical SHA-256 digest")
    return result


def _absolute_path(value: object, label: str) -> str:
    result = _text(value, label)
    path = PurePosixPath(result)
    if (
        not result.startswith("/") or result.startswith("//") or "\\" in result
        or str(path) != result or ".." in path.parts or result == "/"
    ):
        raise BackendContractError(f"{label} must be a normalized absolute POSIX path")
    return result


def _timestamp(value: object) -> str:
    result = _text(value, "creation timestamp", maximum=40)
    if not _CREATED_AT.fullmatch(result):
        raise BackendContractError("creation timestamp must be RFC3339 with an explicit timezone")
    try:
        calendar_value = re.sub(r"(\.[0-9]{6})[0-9]+(?=Z|[+-])", r"\1", result)
        parsed = datetime.datetime.fromisoformat(calendar_value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BackendContractError("creation timestamp is invalid") from exc
    if parsed.utcoffset() is None:
        raise BackendContractError("creation timestamp requires a timezone")
    return result


def _image(value: object) -> str:
    result = _text(value, "image", maximum=512)
    if result.count("@") != 1:
        raise BackendContractError("image must use an explicit registry and an OCI SHA-256 pin")
    repository, digest = result.split("@")
    _digest(digest, "image digest")
    components = repository.split("/")
    if len(components) < 2 or not _REGISTRY.fullmatch(components[0]):
        raise BackendContractError("image requires a literal registry, without a URL or credentials")
    host, separator, port = components[0].partition(":")
    if (
        "." not in host or not any("a" <= char <= "z" for char in host)
        or len(host) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in host.split("."))
        or (separator and int(port) > 65535)
        or any(not _REPOSITORY_PART.fullmatch(part) for part in components[1:])
    ):
        raise BackendContractError("image must use a canonical fully qualified OCI reference without tags")
    return result


def canonical_digest(value: object) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BackendContractError("descriptor cannot be canonically encoded") from exc
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclasses.dataclass(frozen=True)
class BackendIdentity:
    name: str
    sandbox_id: str
    created_at: str

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(_text(self.name, "sandbox name", maximum=63)):
            raise BackendContractError("sandbox name is invalid")
        try:
            if str(uuid.UUID(self.sandbox_id)) != self.sandbox_id:
                raise ValueError
        except (ValueError, AttributeError, TypeError) as exc:
            raise BackendContractError("sandbox ID must be a canonical UUID") from exc
        _timestamp(self.created_at)

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "sandboxId": self.sandbox_id, "createdAt": self.created_at}

    @classmethod
    def from_dict(cls, value: object) -> BackendIdentity:
        data = _exact(value, {"name", "sandboxId", "createdAt"}, "backend identity")
        return cls(data["name"], data["sandboxId"], data["createdAt"])


@dataclasses.dataclass(frozen=True)
class LaunchScope:
    project_id: str
    team: str
    feature_id: str
    role: str
    task_id: str
    attempt: int

    def __post_init__(self) -> None:
        _digest(self.project_id, "project ID")
        if not _TEAM.fullmatch(_text(self.team, "team", maximum=63)):
            raise BackendContractError("team is invalid")
        if self.team in {".", ".."}:
            raise BackendContractError("team must not be a relative path component")
        _text(self.feature_id, "feature ID", maximum=1024)
        if not _ROLE.fullmatch(_text(self.role, "role", maximum=80)):
            raise BackendContractError("role is invalid")
        _text(self.task_id, "task ID", maximum=1024)
        if self.feature_id.strip() != self.feature_id or self.task_id.strip() != self.task_id:
            raise BackendContractError("feature/task IDs must not have surrounding whitespace")
        _integer(self.attempt, "attempt", 0, 2**31 - 1)
        if (self.task_id == "-") != (self.attempt == 0):
            raise BackendContractError("gate scope requires task '-' and attempt zero; tasks require a positive attempt")

    def as_dict(self) -> dict[str, Any]:
        return {"projectId": self.project_id, "team": self.team, "featureId": self.feature_id,
                "role": self.role, "taskId": self.task_id, "attempt": self.attempt}

    @classmethod
    def from_dict(cls, value: object) -> LaunchScope:
        data = _exact(value, {"projectId", "team", "featureId", "role", "taskId", "attempt"}, "launch scope")
        return cls(data["projectId"], data["team"], data["featureId"], data["role"], data["taskId"], data["attempt"])


@dataclasses.dataclass(frozen=True)
class Limits:
    cpus: int
    memory_mib: int
    root_disk_mib: int
    docker_disk_mib: int
    wall_seconds: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        for name, value in self.as_dict().items():
            _integer(value, name, *LIMIT_BOUNDS[name])

    def as_dict(self) -> dict[str, int]:
        return {"cpus": self.cpus, "memoryMiB": self.memory_mib, "rootDiskMiB": self.root_disk_mib,
                "dockerDiskMiB": self.docker_disk_mib, "wallSeconds": self.wall_seconds,
                "maxOutputBytes": self.max_output_bytes}

    @classmethod
    def from_dict(cls, value: object) -> Limits:
        data = _exact(value, set(LIMIT_BOUNDS), "resource limits")
        return cls(data["cpus"], data["memoryMiB"], data["rootDiskMiB"], data["dockerDiskMiB"],
                   data["wallSeconds"], data["maxOutputBytes"])


@dataclasses.dataclass(frozen=True)
class DockerProfile:
    controller_uid: int
    sbx_path: str
    sbx_sha256: str
    namespace: str
    image: str
    limits: Limits
    policy_digest: str
    qualification_digest: str
    schema_version: int = SCHEMA_VERSION
    backend: str = BACKEND
    protocol_version: int = PROTOCOL_VERSION
    guest_workdir: str = GUEST_WORKDIR

    def __post_init__(self) -> None:
        _integer(self.schema_version, "profile schema version", 1, 1)
        _integer(self.protocol_version, "protocol version", 1, 1)
        if self.backend != BACKEND or self.guest_workdir != GUEST_WORKDIR:
            raise BackendContractError("unsupported backend or guest workspace")
        _integer(self.controller_uid, "controller UID", 1, 2**31 - 1)
        _absolute_path(self.sbx_path, "sbx path")
        if not _SHA256.fullmatch(_text(self.sbx_sha256, "sbx SHA-256", maximum=64)):
            raise BackendContractError("sbx SHA-256 must be 64 lowercase hexadecimal characters")
        if (
            not _NAMESPACE.fullmatch(_text(self.namespace, "namespace", maximum=20))
            or self.namespace == "sf-qualification"
        ):
            raise BackendContractError("namespace must be a dedicated sf-* factory namespace, not the qualification namespace")
        _image(self.image)
        if type(self.limits) is not Limits:
            raise BackendContractError("profile limits require a validated Limits descriptor")
        _digest(self.policy_digest, "policy digest")
        _digest(self.qualification_digest, "qualification digest")

    def as_dict(self) -> dict[str, Any]:
        return {"schemaVersion": self.schema_version, "backend": self.backend,
                "protocolVersion": self.protocol_version, "controllerUid": self.controller_uid,
                "sbxPath": self.sbx_path, "sbxSha256": self.sbx_sha256,
                "namespace": self.namespace, "image": self.image, "guestWorkdir": self.guest_workdir,
                "limits": self.limits.as_dict(), "policyDigest": self.policy_digest,
                "qualificationDigest": self.qualification_digest}

    @property
    def digest(self) -> str:
        """Bind every config field; this digest never confers authorization."""
        return canonical_digest(self.as_dict())

    @classmethod
    def from_dict(cls, value: object) -> DockerProfile:
        data = _exact(value, PROFILE_FIELDS, "Docker profile")
        return cls(controller_uid=data["controllerUid"], sbx_path=data["sbxPath"],
                   sbx_sha256=data["sbxSha256"], namespace=data["namespace"], image=data["image"],
                   limits=Limits.from_dict(data["limits"]), policy_digest=data["policyDigest"],
                   qualification_digest=data["qualificationDigest"], schema_version=data["schemaVersion"],
                   backend=data["backend"], protocol_version=data["protocolVersion"],
                   guest_workdir=data["guestWorkdir"])


def parse_profile(raw: bytes) -> DockerProfile:
    """Validate bounded data only; no ownership or enrollment assertion is made."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROFILE_BYTES:
        raise BackendContractError("profile JSON must be nonempty and within its byte limit")
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
            if depth > MAX_JSON_DEPTH:
                raise BackendContractError("profile JSON exceeds its nesting limit")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise BackendContractError("profile JSON has invalid nesting")

    def pairs(items: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for name, child in items:
            if name in value:
                raise BackendContractError("duplicate profile JSON key")
            value[name] = child
        return value

    def constant(_value: str) -> Any:
        raise BackendContractError("profile JSON contains a non-finite number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise BackendContractError("profile is not strict UTF-8 JSON") from exc
    pending = [value]
    count = 0
    while pending:
        child = pending.pop()
        count += 1
        if count > MAX_JSON_ITEMS:
            raise BackendContractError("profile JSON exceeds its item limit")
        if isinstance(child, dict):
            pending.extend(child.keys())
            pending.extend(child.values())
        elif isinstance(child, list):
            pending.extend(child)
        elif isinstance(child, str):
            _text(child, "profile string")
        elif isinstance(child, float) and not math.isfinite(child):
            raise BackendContractError("profile JSON contains a non-finite number")
    return DockerProfile.from_dict(value)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _protected_metadata(info: os.stat_result, *, directory: bool) -> None:
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise BackendContractError("profile/runtime and every ancestor must be root-owned and not group/world-writable")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise BackendContractError("protected path ancestor must be a real directory")
    if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise BackendContractError("protected input must be a regular file with one link")
    if not directory and info.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise BackendContractError("protected input must not change execution identity via setuid/setgid")


def _writable(path: Path) -> bool:
    try:
        return os.access(path, os.W_OK, effective_ids=True)
    except (NotImplementedError, TypeError) as exc:
        raise BackendContractError("protected profile loading requires effective-identity access checks") from exc


def _read_protected(path: Path, *, maximum: int, capture: bool, executable: bool) -> tuple[bytes | None, str]:
    raw_path = _absolute_path(os.fspath(path), "protected path")
    path = Path(raw_path)
    if (
        not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_NONBLOCK", 0)
        or not getattr(os, "O_DIRECTORY", 0) or not _OPEN_SUPPORTS_DIR_FD
        or not _STAT_SUPPORTS_DIR_FD or not _STAT_SUPPORTS_NOFOLLOW
    ):
        raise BackendContractError("protected profile loading requires secure no-follow dirfd operations")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    parent: int | None = None
    leaf: int | None = None
    try:
        parent = os.open(path.anchor, directory_flags)
        current = Path(path.anchor)
        _protected_metadata(os.fstat(parent), directory=True)
        if _writable(current):
            raise BackendContractError("controller must not be able to write protected ancestors")
        for component in path.parts[1:-1]:
            opened = os.open(component, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = opened
            current /= component
            _protected_metadata(os.fstat(parent), directory=True)
            if _writable(current):
                raise BackendContractError("controller must not be able to write protected ancestors")
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                       | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
        before = os.fstat(leaf)
        _protected_metadata(before, directory=False)
        if _writable(path):
            raise BackendContractError("controller must not be able to write protected inputs")
        if executable and (not before.st_mode & 0o111 or not os.access(path, os.X_OK, effective_ids=True)):
            raise BackendContractError("pinned runtime must be executable by the controller")
        if not 0 < before.st_size <= maximum:
            raise BackendContractError("protected input exceeds its size limit or is empty")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(leaf, min(FILE_READ_BYTES, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        after = os.fstat(leaf)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if total > maximum or _file_identity(before) != _file_identity(after) or _file_identity(after) != _file_identity(named):
            raise BackendContractError("protected input changed while being read")
        return b"".join(chunks) if capture else None, digest.hexdigest()
    except (OSError, NotImplementedError) as exc:
        raise BackendContractError("protected profile/runtime path is unavailable or unsafe") from exc
    finally:
        if leaf is not None:
            os.close(leaf)
        if parent is not None:
            os.close(parent)


def load_profile(path: Path, *, expected_uid: int | None = None) -> DockerProfile:
    """Verify root-protected config/runtime for one nonroot controller identity.

    expected_uid is the controller UID, not the file owner (which is always
    root). A successful load is still not enrollment or launch authorization.
    Future adapters must recheck the protected runtime immediately before use.
    """
    actual_uid = os.geteuid()
    controller_uid = actual_uid if expected_uid is None else expected_uid
    _integer(controller_uid, "expected controller UID", 1, 2**31 - 1)
    if actual_uid != controller_uid:
        raise BackendContractError("running controller UID does not match the expected nonroot identity")
    raw, _digest_value = _read_protected(path, maximum=MAX_PROFILE_BYTES, capture=True, executable=False)
    assert raw is not None
    profile = parse_profile(raw)
    if profile.controller_uid != controller_uid:
        raise BackendContractError("profile controller UID differs from the running controller")
    _content, observed = _read_protected(Path(profile.sbx_path), maximum=MAX_RUNTIME_BYTES,
                                       capture=False, executable=True)
    if observed != profile.sbx_sha256:
        raise BackendContractError("protected runtime does not match the configured SHA-256")
    return profile


@dataclasses.dataclass(frozen=True)
class GuestCommand:
    """Literal guest argv only. Never a host path mapping or a host shell string."""
    argv: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.argv) is not tuple or not 1 <= len(self.argv) <= 128:
            raise BackendContractError("guest command requires a bounded closed tuple of arguments")
        for argument in self.argv:
            _text(argument, "guest argument")
        _absolute_path(self.argv[0], "guest executable")
        if sum(len(argument.encode("utf-8")) for argument in self.argv) > 64 * 1024:
            raise BackendContractError("guest command exceeds its byte limit")

    def as_dict(self) -> dict[str, Any]:
        return {"argv": list(self.argv)}

    @classmethod
    def from_dict(cls, value: object) -> GuestCommand:
        data = _exact(value, {"argv"}, "guest command")
        if type(data["argv"]) is not list:
            raise BackendContractError("guest argv must be a JSON array")
        return cls(tuple(data["argv"]))


@dataclasses.dataclass(frozen=True)
class ArtifactReference:
    """Opaque host-approved content reference; contains no guest-selected path."""
    digest: str

    def __post_init__(self) -> None:
        _digest(self.digest, "artifact digest")


@dataclasses.dataclass(frozen=True)
class LaunchSpec:
    scope: LaunchScope
    profile_digest: str
    command: GuestCommand

    def __post_init__(self) -> None:
        if type(self.scope) is not LaunchScope or type(self.command) is not GuestCommand:
            raise BackendContractError("launch spec requires validated scope and guest command descriptors")
        _digest(self.profile_digest, "profile digest")


@dataclasses.dataclass(frozen=True)
class BackendProbe:
    protocol_version: int
    observations: tuple[str, ...]

    def __post_init__(self) -> None:
        _integer(self.protocol_version, "protocol version", 1, 1)
        if type(self.observations) is not tuple or len(self.observations) > 64:
            raise BackendContractError("backend probe observations must be a bounded tuple")
        for observation in self.observations:
            _text(observation, "backend observation")


@dataclasses.dataclass(frozen=True)
class BackendObservation:
    identity: BackendIdentity
    state: str

    def __post_init__(self) -> None:
        if type(self.identity) is not BackendIdentity or type(self.state) is not str or self.state not in {
            "allocated", "provisioning", "ready", "running", "collecting", "completed",
            "fenced", "stopping", "stopped", "removing", "removed", "cleanup-pending", "lost",
        }:
            raise BackendContractError("backend observation requires an exact identity and supported state")


class BackendSession(Protocol):
    """Live native client and cancellable pipes, never a captured result.

    Cancelling the client stream does not certify that its VM stopped. VM
    lifecycle operations remain explicit and identity-bound in the Backend.
    """
    process: subprocess.Popen[bytes]
    stdin: BinaryIO
    stdout: BinaryIO
    stderr: BinaryIO

    def cancel(self) -> None: ...
    def close(self) -> None: ...


class Backend(Protocol):
    """Contract only; implementations must enforce policy outside these values."""

    def probe(self, profile: DockerProfile) -> BackendProbe: ...
    def create(self, launch_spec: LaunchSpec) -> BackendIdentity: ...
    def inspect(self, identity: BackendIdentity) -> BackendObservation: ...
    def open_session(self, identity: BackendIdentity, guest_command: GuestCommand) -> BackendSession: ...
    def stage_input(self, identity: BackendIdentity, approved_manifest: ArtifactReference) -> ArtifactReference: ...
    def collect_output(self, identity: BackendIdentity, export_request: ArtifactReference) -> ArtifactReference: ...
    def stop(self, identity: BackendIdentity) -> BackendObservation: ...
    def destroy(self, identity: BackendIdentity) -> ArtifactReference: ...
