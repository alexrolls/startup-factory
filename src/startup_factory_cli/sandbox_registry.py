"""Durable controller state for an exclusively owned sandbox namespace.

This module makes no Docker calls and grants no qualification or enrollment.
Callers must separately establish exclusive access to every daemon endpoint.
The lock coordinates trusted controllers; it cannot constrain other clients.

A new controller calls ``takeover`` while locked before issuing commands. This
advances the epoch and fences every surviving record. Names and generations
are permanently retained, including failed creates and removed sandboxes.
Backend observations are statements supplied by the trusted adapter, not
proofs independently verified by this registry.
"""

from __future__ import annotations

from contextlib import contextmanager
import copy
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Any, Iterator, Mapping

from .execution_backend import BackendContractError, BackendIdentity, LaunchScope


SCHEMA_VERSION = 1
DEFAULT_MAX_STATE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_NAMES = 1024
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_NAMES = 100_000
MAX_COUNTER = (1 << 63) - 1
STATE_FILE = "registry.json"
MARKER_FILE = "registry.identity"
LOCK_FILE = "registry.lock"
_NAMESPACE = re.compile(r"[a-z0-9][a-z0-9-]{1,62}\Z")
_NAME = re.compile(r"sf-[0-9a-f]{32}\Z")
_GENERATION = re.compile(r"gen-[0-9a-f]{32}\Z")
_REGISTRY_ID = re.compile(r"reg-[0-9a-f]{32}\Z")
_RECORD_FIELDS = {
    "name", "generation", "epoch", "state", "scope", "sandboxId", "createdAt", "observation"
}
_STATE_FIELDS = {"schemaVersion", "registryId", "namespace", "epoch", "revision", "records"}
_MARKER_FIELDS = {"schemaVersion", "registryId", "namespace"}
_OBSERVATION_FIELDS = {"sandboxId", "createdAt", "state"}
COMMAND_STATES = frozenset({"allocated", "ready", "running", "collecting", "work-complete"})
STATES = COMMAND_STATES | {
    "fenced", "stopping", "stopped", "removing", "removed", "cleanup-pending", "lost"
}
_TRANSITIONS = {
    "allocated": {"ready", "fenced", "cleanup-pending", "lost"},
    "ready": {"running", "fenced", "cleanup-pending", "lost"},
    "running": {"collecting", "fenced", "cleanup-pending", "lost"},
    "collecting": {"running", "work-complete", "fenced", "cleanup-pending", "lost"},
    "work-complete": {"fenced", "cleanup-pending", "lost"},
    "fenced": {"stopping", "cleanup-pending", "lost"},
    "stopping": {"stopped", "cleanup-pending", "lost"},
    "stopped": {"removing", "removed", "cleanup-pending", "lost"},
    "removing": {"removed", "cleanup-pending", "lost"},
    "cleanup-pending": {"fenced", "lost"},
    "lost": {"fenced", "cleanup-pending"},
    "removed": set(),
}


class RegistryError(ValueError):
    """Unsafe, inconsistent, stale, or unsupported controller state."""


class RegistryBusy(RegistryError):
    """Another controller currently owns the namespace lock."""


class RegistryQuotaExceeded(RegistryError):
    """Permanent name history or state bytes reached the enrolled quota."""


class RegistryUncertainWrite(RegistryError):
    """A mutation failed; this registry instance must no longer authorize work."""


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _counter(value: Any, *, positive: bool = False) -> bool:
    return type(value) is int and (1 if positive else 0) <= value <= MAX_COUNTER


def _scope(value: Any) -> dict[str, Any]:
    try:
        return LaunchScope.from_dict(value).as_dict()
    except BackendContractError as exc:
        raise RegistryError("scope must satisfy the closed execution-backend contract") from exc


def _binding(identifier: Any, created_at: Any) -> None:
    if identifier is None and created_at is None:
        return
    try:
        # Use the same validation as the adapter and preserve the exact backend
        # timestamp, including nanoseconds, rather than normalizing identity.
        BackendIdentity("sf-binding", identifier, created_at)
    except BackendContractError as exc:
        raise RegistryError("backend identity must be a canonical UUID and RFC3339 timestamp") from exc


def _observation(value: Any, record: Mapping[str, Any]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _OBSERVATION_FIELDS:
        raise RegistryError("cleanup requires a closed backend observation")
    if (value["sandboxId"], value["createdAt"]) != (record["sandboxId"], record["createdAt"]):
        raise RegistryError("backend observation does not match the pinned identity")
    if not isinstance(value["state"], str) or value["state"] not in {"stopped", "absent"}:
        raise RegistryError("backend observation must establish stopped or absent")
    if record["sandboxId"] is None and value["state"] != "absent":
        raise RegistryError("an unbound create can only be reconciled as absent")
    return copy.deepcopy(value)


def _encode(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def _decode(raw: bytes) -> dict[str, Any]:
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
            if depth > 8:
                raise RegistryError("registry JSON nesting limit exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise RegistryError("invalid registry JSON")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise RegistryError("duplicate registry JSON key")
            result[key] = value
        return result

    def constant(_value: str) -> Any:
        raise RegistryError("non-finite registry JSON number")

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise RegistryError("invalid registry JSON") from exc
    if type(result) is not dict:
        raise RegistryError("registry JSON must be an object")
    return result


def _validate_state(value: Any, *, namespace: str, registry_id: str, max_names: int) -> None:
    if type(value) is not dict or set(value) != _STATE_FIELDS:
        raise RegistryError("unknown or incomplete registry state schema")
    if (
        type(value["schemaVersion"]) is not int or value["schemaVersion"] != SCHEMA_VERSION
        or value["namespace"] != namespace or value["registryId"] != registry_id
        or not _counter(value["epoch"]) or not _counter(value["revision"])
        or type(value["records"]) is not dict
    ):
        raise RegistryError("invalid registry state identity or counters")
    if len(value["records"]) > max_names:
        raise RegistryQuotaExceeded("permanent name quota exceeded")
    generations: set[str] = set()
    backend_ids: set[str] = set()
    for name, record in value["records"].items():
        if (
            not isinstance(name, str) or not _NAME.fullmatch(name)
            or type(record) is not dict or set(record) != _RECORD_FIELDS
            or record["name"] != name
            or not isinstance(record["generation"], str) or not _GENERATION.fullmatch(record["generation"])
            or record["generation"] in generations or not _counter(record["epoch"], positive=True)
            or record["epoch"] > value["epoch"]
            or not isinstance(record["state"], str) or record["state"] not in STATES
        ):
            raise RegistryError("invalid permanent sandbox record")
        if record["state"] != "removed" and record["epoch"] != value["epoch"]:
            raise RegistryError("live record belongs to a stale controller epoch")
        generations.add(record["generation"])
        _scope(record["scope"])
        _binding(record["sandboxId"], record["createdAt"])
        if record["sandboxId"] is not None:
            if record["sandboxId"] in backend_ids:
                raise RegistryError("backend object identity is already reserved")
            backend_ids.add(record["sandboxId"])
        if record["state"] in {"ready", "running", "collecting", "work-complete"} and record["sandboxId"] is None:
            raise RegistryError("active sandbox record has no pinned backend identity")
        if record["observation"] is not None:
            _observation(record["observation"], record)
        if record["state"] == "stopped" and record["observation"] is None:
            raise RegistryError("stopped record has no backend observation")
        if record["state"] == "removed" and (
            record["observation"] is None or record["observation"]["state"] != "absent"
        ):
            raise RegistryError("removed record has no absence observation")


class SandboxRegistry:
    """State below a precreated private directory with protected ancestors."""

    def __init__(
        self, root: Path, namespace: str, *,
        max_state_bytes: int = DEFAULT_MAX_STATE_BYTES, max_names: int = DEFAULT_MAX_NAMES,
    ) -> None:
        self.root = Path(root)
        if not isinstance(namespace, str) or not _NAMESPACE.fullmatch(namespace):
            raise RegistryError("namespace must be a bounded lowercase service name")
        if type(max_state_bytes) is not int or not 512 <= max_state_bytes <= MAX_STATE_BYTES:
            raise RegistryError("invalid registry byte quota")
        if type(max_names) is not int or not 1 <= max_names <= MAX_NAMES:
            raise RegistryError("invalid registry name quota")
        self.namespace = namespace
        self.max_state_bytes = max_state_bytes
        self.max_names = max_names
        self._poisoned = False
        self._transaction_active = False
        self._controller_epoch: int | None = None
        self._creator_pid = os.getpid()
        self._root_fd = self._open_root()
        self._root_identity = _directory_identity(os.fstat(self._root_fd))

    def _open_root(self) -> int:
        if not self.root.is_absolute() or ".." in self.root.parts:
            raise RegistryError("registry root must be an absolute normalized path")
        if not all(getattr(os, name, 0) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")):
            raise RegistryError("registry requires directory-relative no-follow file operations")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor: int | None = None
        try:
            descriptor = os.open("/", flags)
            components = self.root.parts[1:]
            for index in range(len(components) + 1):
                info = os.fstat(descriptor)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
                    raise RegistryError("registry ancestors must be protected root/account-owned directories")
                if index == len(components):
                    if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
                        raise RegistryError("registry root must be account-owned mode 0700")
                    result = descriptor
                    descriptor = None
                    return result
                child = os.open(components[index], flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
        except OSError as exc:
            raise RegistryError("cannot open protected registry directory") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        raise RegistryError("cannot open protected registry directory")

    def _check_root(self) -> None:
        if os.getpid() != self._creator_pid:
            raise RegistryError("inherited registry state requires a new controller instance")
        if self._root_fd < 0 or self._poisoned:
            raise RegistryError("registry is closed or has an uncertain write")
        descriptor = self._open_root()
        try:
            if (
                _directory_identity(os.fstat(descriptor)) != self._root_identity
                or _directory_identity(os.fstat(self._root_fd)) != self._root_identity
            ):
                raise RegistryError("registry root identity changed")
        finally:
            os.close(descriptor)

    def close(self) -> None:
        if self._transaction_active:
            raise RegistryError("cannot close a locked registry")
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> SandboxRegistry:
        self._check_root()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def _file(self, name: str, *, maximum: int) -> tuple[bytes, tuple[int, ...]]:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self._root_fd)
        try:
            before = os.fstat(descriptor)
            self._validate_file(before, maximum=maximum)
            output = bytearray()
            while len(output) <= maximum:
                chunk = os.read(descriptor, min(65536, maximum + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            if (
                len(output) != before.st_size or len(output) > maximum
                or _identity(before) != _identity(after) or _identity(after) != _identity(named)
            ):
                raise RegistryError("registry file changed while being read")
            return bytes(output), _identity(after)
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_file(info: os.stat_result, *, maximum: int) -> None:
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 0 <= info.st_size <= maximum
        ):
            raise RegistryError("registry file must be bounded, owner-only, and singly linked")

    def _write_exclusive(self, name: str, content: bytes) -> tuple[int, ...]:
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=self._root_fd,
        )
        complete = False
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(content):
                count = os.write(descriptor, content[offset:])
                if count <= 0:
                    raise OSError("incomplete registry write")
                offset += count
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            self._validate_file(info, maximum=len(content))
            if info.st_size != len(content):
                raise RegistryError("registry write size changed")
            complete = True
            return _identity(info)
        finally:
            if not complete:
                # A failed pre-replace write must not accumulate unbounded
                # pending files across recovery. Unlink only this opened inode.
                try:
                    opened = os.fstat(descriptor)
                    named = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
                    if (
                        stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                        and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)
                    ):
                        os.unlink(name, dir_fd=self._root_fd)
                except OSError:
                    pass
            os.close(descriptor)

    def _load(self, *, initialize: bool = False) -> tuple[dict[str, Any], tuple[int, ...], tuple[int, ...]]:
        try:
            marker_raw, marker_identity = self._file(MARKER_FILE, maximum=4096)
        except FileNotFoundError:
            if not initialize:
                raise RegistryError("registry identity marker is missing")
            # A marker is written first. A crash during genesis therefore
            # blocks reopening instead of silently forgetting name history.
            entries = set(os.listdir(self._root_fd))
            if entries != {LOCK_FILE}:
                raise RegistryError("uninitialized registry directory is not empty")
            marker = {
                "schemaVersion": SCHEMA_VERSION, "namespace": self.namespace,
                "registryId": "reg-" + secrets.token_hex(16),
            }
            try:
                self._write_exclusive(MARKER_FILE, _encode(marker))
                os.fsync(self._root_fd)
                initial = {
                    **marker, "epoch": 0, "revision": 0, "records": {},
                }
                self._write_exclusive(STATE_FILE, _encode(initial))
                os.fsync(self._root_fd)
            except (OSError, RegistryError) as exc:
                self._poisoned = True
                raise RegistryUncertainWrite("registry initialization is uncertain") from exc
            marker_raw, marker_identity = self._file(MARKER_FILE, maximum=4096)
        marker = _decode(marker_raw)
        if (
            set(marker) != _MARKER_FIELDS or type(marker["schemaVersion"]) is not int
            or marker["schemaVersion"] != SCHEMA_VERSION or marker["namespace"] != self.namespace
            or not isinstance(marker["registryId"], str) or not _REGISTRY_ID.fullmatch(marker["registryId"])
        ):
            raise RegistryError("registry identity marker does not match this namespace")
        try:
            raw, identity = self._file(STATE_FILE, maximum=self.max_state_bytes)
        except FileNotFoundError as exc:
            raise RegistryError("registry state is missing; name history cannot be reset") from exc
        state = _decode(raw)
        _validate_state(state, namespace=self.namespace, registry_id=marker["registryId"], max_names=self.max_names)
        return state, identity, marker_identity

    @contextmanager
    def locked(self) -> Iterator[RegistryTransaction]:
        self._check_root()
        if self._transaction_active:
            raise RegistryBusy("registry transaction is already active")
        descriptor: int | None = None
        transaction: RegistryTransaction | None = None
        acquired = False
        active_here = False
        locking_pid = os.getpid()
        try:
            try:
                descriptor = os.open(
                    LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=self._root_fd,
                )
                os.fchmod(descriptor, 0o600)
            except FileExistsError:
                descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self._root_fd)
            self._validate_file(os.fstat(descriptor), maximum=0)
            lock_identity = _identity(os.fstat(descriptor))
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise RegistryBusy("another controller holds the namespace lock") from exc
                raise
            acquired = True
            if _identity(os.stat(LOCK_FILE, dir_fd=self._root_fd, follow_symlinks=False)) != lock_identity:
                raise RegistryError("registry lock identity changed")
            self._transaction_active = True
            active_here = True
            state, state_identity, marker_identity = self._load(initialize=True)
            transaction = RegistryTransaction(self, state, state_identity, marker_identity, lock_identity)
            yield transaction
        except OSError as exc:
            raise RegistryError("cannot access or lock protected registry state") from exc
        finally:
            if transaction is not None:
                transaction._active = False
            if active_here:
                self._transaction_active = False
            if descriptor is not None:
                # flock belongs to the open-file description. A fork child
                # must close its inherited copy without unlocking its parent.
                if acquired and os.getpid() == locking_pid:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)


class RegistryTransaction:
    """One nonblocking exclusive lock; methods persist mutations immediately."""

    def __init__(
        self, registry: SandboxRegistry, state: dict[str, Any], state_identity: tuple[int, ...],
        marker_identity: tuple[int, ...], lock_identity: tuple[int, ...],
    ) -> None:
        self._registry = registry
        self._state = state
        self._state_identity = state_identity
        self._marker_identity = marker_identity
        self._lock_identity = lock_identity
        self._active = True
        self._thread_id = threading.get_ident()

    def _check(self) -> None:
        if (
            not self._active or not self._registry._transaction_active
            or threading.get_ident() != self._thread_id
        ):
            raise RegistryError("transaction is no longer locked")
        self._registry._check_root()
        current, state_identity, marker_identity = self._registry._load()
        named_lock = os.stat(LOCK_FILE, dir_fd=self._registry._root_fd, follow_symlinks=False)
        if (
            state_identity != self._state_identity or marker_identity != self._marker_identity
            or _identity(named_lock) != self._lock_identity or current != self._state
        ):
            raise RegistryError("protected registry state changed outside this transaction")

    @property
    def epoch(self) -> int:
        self._check()
        return self._state["epoch"]

    @property
    def registry_id(self) -> str:
        self._check()
        return self._state["registryId"]

    def records(self) -> tuple[dict[str, Any], ...]:
        self._check()
        return tuple(copy.deepcopy(self._state["records"][name]) for name in sorted(self._state["records"]))

    def _persist(self, candidate: dict[str, Any]) -> None:
        self._check()
        if not _counter(self._state["revision"] + 1):
            raise RegistryError("registry revision exhausted")
        candidate["revision"] = self._state["revision"] + 1
        _validate_state(
            candidate, namespace=self._registry.namespace, registry_id=self._state["registryId"],
            max_names=self._registry.max_names,
        )
        raw = _encode(candidate)
        if len(raw) > self._registry.max_state_bytes:
            raise RegistryQuotaExceeded("registry byte quota exceeded; permanent history is retained")
        temporary = ".registry-" + secrets.token_hex(16) + ".pending"
        temporary_identity: tuple[int, ...] | None = None
        replaced = False
        try:
            temporary_identity = self._registry._write_exclusive(temporary, raw)
            self._check()
            if _identity(os.stat(temporary, dir_fd=self._registry._root_fd, follow_symlinks=False)) != temporary_identity:
                raise RegistryError("pending registry identity changed")
            os.replace(temporary, STATE_FILE, src_dir_fd=self._registry._root_fd, dst_dir_fd=self._registry._root_fd)
            replaced = True
            os.fsync(self._registry._root_fd)
            persisted, state_identity = self._registry._file(STATE_FILE, maximum=self._registry.max_state_bytes)
            if persisted != raw:
                raise RegistryError("persisted registry differs from the committed mutation")
            self._state = candidate
            self._state_identity = state_identity
        except (OSError, RegistryError) as exc:
            self._registry._poisoned = True
            raise RegistryUncertainWrite("registry mutation is uncertain; controller must be fenced") from exc
        finally:
            if temporary_identity is not None and not replaced:
                try:
                    named = os.stat(temporary, dir_fd=self._registry._root_fd, follow_symlinks=False)
                    if _identity(named) == temporary_identity:
                        os.unlink(temporary, dir_fd=self._registry._root_fd)
                except OSError:
                    pass

    def takeover(self) -> int:
        """Durably fence predecessors and acquire a new controller epoch."""
        self._check()
        epoch = self._state["epoch"] + 1
        if not _counter(epoch, positive=True):
            raise RegistryError("controller epoch exhausted")
        candidate = copy.deepcopy(self._state)
        candidate["epoch"] = epoch
        for record in candidate["records"].values():
            if record["state"] != "removed":
                record["epoch"] = epoch
                record["state"] = "fenced"
        self._persist(candidate)
        self._registry._controller_epoch = epoch
        return epoch

    def _require_epoch(self, epoch: int) -> None:
        self._check()
        if (
            not _counter(epoch, positive=True) or epoch != self._state["epoch"]
            or epoch != self._registry._controller_epoch
        ):
            raise RegistryError("stale or unowned controller epoch")

    def reserve(self, scope: dict[str, Any], *, epoch: int) -> dict[str, Any]:
        self._require_epoch(epoch)
        scope = _scope(scope)
        if len(self._state["records"]) >= self._registry.max_names:
            raise RegistryQuotaExceeded("permanent name quota exhausted; names cannot be recycled")
        names = self._state["records"]
        generations = {record["generation"] for record in names.values()}
        for _ in range(8):
            name = "sf-" + secrets.token_hex(16)
            generation = "gen-" + secrets.token_hex(16)
            if name not in names and generation not in generations:
                break
        else:
            raise RegistryError("could not allocate a fresh permanent name and generation")
        record = {
            "name": name, "generation": generation, "epoch": epoch, "state": "allocated",
            "scope": scope, "sandboxId": None, "createdAt": None, "observation": None,
        }
        candidate = copy.deepcopy(self._state)
        candidate["records"][name] = record
        self._persist(candidate)
        return copy.deepcopy(record)

    def _record(self, name: str, generation: str, epoch: int) -> dict[str, Any]:
        self._require_epoch(epoch)
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise RegistryError("invalid reserved sandbox name")
        record = self._state["records"].get(name)
        if record is None or record["generation"] != generation or record["epoch"] != epoch:
            raise RegistryError("sandbox generation or epoch does not match")
        return record

    def bind(
        self, name: str, generation: str, epoch: int, *, sandbox_id: str, created_at: str,
    ) -> dict[str, Any]:
        record = self._record(name, generation, epoch)
        if record["state"] != "allocated":
            raise RegistryError("only an allocated generation can bind an object")
        _binding(sandbox_id, created_at)
        if sandbox_id is None:
            raise RegistryError("binding requires an observed backend identity")
        if record["sandboxId"] is not None:
            if (record["sandboxId"], record["createdAt"]) != (sandbox_id, created_at):
                raise RegistryError("a reserved generation cannot adopt a replacement object")
            return copy.deepcopy(record)
        if any(value["sandboxId"] == sandbox_id for value in self._state["records"].values()):
            raise RegistryError("backend identity was already reserved")
        candidate = copy.deepcopy(self._state)
        candidate["records"][name].update(sandboxId=sandbox_id, createdAt=created_at)
        self._persist(candidate)
        return copy.deepcopy(candidate["records"][name])

    def authorize(
        self, name: str, generation: str, epoch: int, *, allowed_states: set[str] | frozenset[str],
    ) -> dict[str, Any]:
        record = self._record(name, generation, epoch)
        if (
            not isinstance(allowed_states, (set, frozenset)) or not allowed_states
            or not allowed_states <= COMMAND_STATES
        ):
            raise RegistryError("authorization requires explicit unfenced command states")
        if record["state"] not in allowed_states or record["sandboxId"] is None:
            raise RegistryError("generation is fenced, unbound, or outside the permitted command state")
        return copy.deepcopy(record)

    def transition(
        self, name: str, generation: str, epoch: int, *, state: str,
        observation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = self._record(name, generation, epoch)
        if not isinstance(state, str) or state not in _TRANSITIONS[record["state"]]:
            raise RegistryError("sandbox lifecycle transition is not permitted")
        observed = None
        if state in {"stopped", "removed"}:
            observed = _observation(observation, record)
            if state == "removed" and observed["state"] != "absent":
                raise RegistryError("removal requires an observed absent object")
        elif observation is not None:
            raise RegistryError("unexpected backend observation for this transition")
        if state in {"ready", "running", "collecting", "work-complete"} and record["sandboxId"] is None:
            raise RegistryError("active lifecycle state requires a pinned backend identity")
        candidate = copy.deepcopy(self._state)
        changed = candidate["records"][name]
        changed["state"] = state
        if observed is not None:
            changed["observation"] = observed
        self._persist(candidate)
        return copy.deepcopy(changed)

    def fence(self, name: str, generation: str, epoch: int) -> dict[str, Any]:
        record = self._record(name, generation, epoch)
        if record["state"] == "removed":
            raise RegistryError("a removed generation cannot be revived")
        if record["state"] == "fenced":
            return copy.deepcopy(record)
        candidate = copy.deepcopy(self._state)
        candidate["records"][name]["state"] = "fenced"
        self._persist(candidate)
        return copy.deepcopy(candidate["records"][name])
