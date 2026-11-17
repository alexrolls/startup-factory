"""Scoped model-only credential custody, with durable pre-effect cleanup intent.

Only a root-managed OpenAI file is supported by the observed v0.54 protocol.
Source selection is installation data, never a guest/job field. Secret bytes
travel only through the trusted native manager's bounded stdin path; no value,
input hash, environment assignment or command source is journaled here.
"""
from __future__ import annotations

import contextlib
import dataclasses
from functools import wraps
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any

from .execution_backend import BackendIdentity, DockerProfile, LaunchScope, canonical_digest
from .sandbox_controller import GenerationHandle
from .sandbox_deployment import Deployment, canonical_bytes, decode_object, load_deployment
from .sandbox_enrollment import profile_basis_digest
from .sandbox_registry import SandboxRegistry


MAX_SECRET_BYTES = 16384
MAX_LEASES = 1024
MAX_LEDGER_BYTES = 4 * 1024 * 1024
STATE_FILE = "model-credentials.json"
PENDING_FILE = ".model-credentials.pending"
STATES = frozenset({"prepared", "install-uncertain", "installed", "remove-uncertain", "removed"})
TRANSITIONS = {"prepared": {"install-uncertain", "remove-uncertain"},
    "install-uncertain": {"install-uncertain", "installed", "remove-uncertain"},
    "installed": {"remove-uncertain"}, "remove-uncertain": {"remove-uncertain", "removed"}, "removed": {"removed"}}


def _serialized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._mutex:
            try:
                return method(self, *args, **kwargs)
            except ModelCredentialError:
                raise
            except Exception as exc:
                raise ModelCredentialError("scoped model operation failed or has uncertain delivery") from exc
    return call


class ModelCredentialError(RuntimeError):
    """Model provisioning or cleanup is unavailable or uncertain; no fallback."""


@dataclasses.dataclass(frozen=True)
class CredentialLease:
    deployment_digest: str
    profile_basis_digest: str
    handle: GenerationHandle
    identity: BackendIdentity
    scope_digest: str
    provider: str | None

    def __post_init__(self):
        if (type(self.handle) is not GenerationHandle or type(self.identity) is not BackendIdentity
            or self.handle.name != self.identity.name or self.provider not in {None, "openai"}
            or any(type(value) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                   for value in (self.deployment_digest, self.profile_basis_digest, self.scope_digest))):
            raise ModelCredentialError("invalid host credential lease binding")

    def as_dict(self) -> dict:
        return {"deploymentDigest": self.deployment_digest, "profileBasisDigest": self.profile_basis_digest,
            "handle": self.handle.as_dict(), "identity": self.identity.as_dict(), "scopeDigest": self.scope_digest, "provider": self.provider}

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {"deploymentDigest", "profileBasisDigest", "handle", "identity", "scopeDigest", "provider"}:
            raise ModelCredentialError("unknown credential lease schema")
        handle = value["handle"]
        if type(handle) is not dict or set(handle) != {"name", "generation", "epoch"}:
            raise ModelCredentialError("unknown credential generation schema")
        return cls(value["deploymentDigest"], value["profileBasisDigest"], GenerationHandle(handle["name"], handle["generation"], handle["epoch"]),
            BackendIdentity.from_dict(value["identity"]), value["scopeDigest"], value["provider"])


def _key(lease: CredentialLease) -> str:
    return canonical_digest({"name": lease.handle.name, "generation": lease.handle.generation})[7:]


def _source(path: Path, deployment: Deployment) -> bytearray:
    """Root-owned 0640/private-GID single-line file, without computing a hash."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags); descriptor = None; raw = bytearray(); complete = False
    try:
        current = Path("/")
        for index, part in enumerate(path.parts[1:-1]):
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022 or os.access(current, os.W_OK, effective_ids=True):
                raise ModelCredentialError("model source ancestors are not protected")
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory); directory = child; current /= part
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022 or os.access(path.parent, os.W_OK, effective_ids=True):
            raise ModelCredentialError("model source parent is not protected")
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != 0
            or before.st_gid != deployment.controller_gid or stat.S_IMODE(before.st_mode) != 0o640
            or not 1 <= before.st_size <= MAX_SECRET_BYTES or os.access(path, os.W_OK, effective_ids=True)):
            raise ModelCredentialError("model source must be a bounded root-owned 0640 private-group regular file")
        while len(raw) <= MAX_SECRET_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_SECRET_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(raw) != before.st_size or stamp(before) != stamp(os.fstat(descriptor)) or stamp(before) != stamp(os.stat(path.name, dir_fd=directory, follow_symlinks=False)):
            raise ModelCredentialError("model source changed while being read")
        if raw.endswith(b"\n"):
            del raw[-1:]
            if raw.endswith(b"\r"):
                del raw[-1:]
        if not 1 <= len(raw) < MAX_SECRET_BYTES or any(byte < 33 or byte > 126 for byte in raw):
            raise ModelCredentialError("model source must contain one bounded nonempty printable credential line")
        raw.append(10)  # CLI input only, never argv/env/journal.
        complete = True
        return raw
    finally:
        if not complete:
            raw[:] = b"\0" * len(raw)
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


class ScopedModelCredentials:
    def __init__(self, deployment: Deployment, native_manager: Any):
        if type(deployment) is not Deployment or not callable(getattr(native_manager, "run_credential", None)):
            raise ModelCredentialError("trusted deployment and native custody manager are required")
        if os.geteuid() != deployment.controller_uid:
            raise ModelCredentialError("model broker requires its dedicated nonroot account")
        self.deployment = deployment; self.manager = native_manager
        self._pid = os.getpid(); self._mutex = threading.RLock(); self._poisoned = False
        self._storage = SandboxRegistry(Path(deployment.credential_root), deployment.namespace)
        try:
            with self._storage.locked() as transaction:
                try:
                    self._load(transaction)
                except FileNotFoundError:
                    if transaction.epoch != 0:
                        raise ModelCredentialError("credential history is missing; cleanup/requalification required")
                    initial = {"schemaVersion": 1, "deploymentDigest": deployment.digest, "revision": 0, "leases": {}}
                    self._storage._write_exclusive(STATE_FILE, canonical_bytes(initial)); os.fsync(self._storage._root_fd)
                    transaction.takeover()
                else:
                    if transaction.epoch == 0:
                        transaction.takeover()
        except BaseException:
            self._storage.close()
            raise

    def _owner(self, *, cleanup=False):
        if os.getpid() != self._pid or self._poisoned and not cleanup:
            raise ModelCredentialError("credential broker is inherited or durability is uncertain")

    def _load(self, transaction):
        transaction.records()
        try:
            os.stat(PENDING_FILE, dir_fd=self._storage._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ModelCredentialError("credential metadata commit was interrupted; reconcile before dispatch")
        raw, _identity = self._storage._file(STATE_FILE, maximum=MAX_LEDGER_BYTES)
        value = decode_object(raw, maximum=MAX_LEDGER_BYTES)
        if (set(value) != {"schemaVersion", "deploymentDigest", "revision", "leases"}
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["deploymentDigest"] != self.deployment.digest or type(value["revision"]) is not int or value["revision"] < 0
            or type(value["leases"]) is not dict or len(value["leases"]) > MAX_LEASES):
            raise ModelCredentialError("credential ledger policy/schema is invalid")
        for key, record in value["leases"].items():
            if type(record) is not dict or set(record) != {"lease", "state", "receiptDigest"} or type(record["state"]) is not str or record["state"] not in STATES:
                raise ModelCredentialError("credential journal record is invalid")
            lease = CredentialLease.from_dict(record["lease"])
            if _key(lease) != key or lease.deployment_digest != self.deployment.digest:
                raise ModelCredentialError("credential lease identity changed")
            if record["receiptDigest"] is not None and (type(record["receiptDigest"]) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", record["receiptDigest"])):
                raise ModelCredentialError("credential acknowledgment is invalid")
        return value

    def _save(self, transaction, state):
        state["revision"] += 1
        raw = canonical_bytes(state)
        if len(raw) > MAX_LEDGER_BYTES:
            raise ModelCredentialError("permanent credential history byte quota exhausted")
        previous, identity = self._storage._file(STATE_FILE, maximum=MAX_LEDGER_BYTES)
        try:
            self._storage._write_exclusive(PENDING_FILE, raw)
            transaction.records()
            observed, current = self._storage._file(STATE_FILE, maximum=MAX_LEDGER_BYTES)
            if previous != observed or identity != current:
                raise ModelCredentialError("credential history changed before commit")
            os.replace(PENDING_FILE, STATE_FILE, src_dir_fd=self._storage._root_fd, dst_dir_fd=self._storage._root_fd)
            os.fsync(self._storage._root_fd)
            if self._storage._file(STATE_FILE, maximum=MAX_LEDGER_BYTES)[0] != raw:
                raise ModelCredentialError("credential history commit is uncertain")
        except BaseException:
            self._poisoned = True
            raise

    def _binding(self, profile, handle, identity, lease=None, *, cleanup=False):
        self._owner(cleanup=cleanup)
        if (type(profile) is not DockerProfile or type(handle) is not GenerationHandle or type(identity) is not BackendIdentity
            or handle.name != identity.name or profile.controller_uid != self.deployment.controller_uid
            or profile.namespace != self.deployment.namespace or profile_basis_digest(profile) != self.deployment.profile_basis_digest):
            raise ModelCredentialError("credential operation targets another deployment/generation")
        if lease is not None and (type(lease) is not CredentialLease or lease.deployment_digest != self.deployment.digest
            or lease.profile_basis_digest != self.deployment.profile_basis_digest or lease.identity != identity
            or lease.handle.name != handle.name or lease.handle.generation != handle.generation
            or (handle.epoch < lease.handle.epoch if cleanup else handle.epoch != lease.handle.epoch)):
            raise ModelCredentialError("credential lease does not match its immutable generation")
        if not cleanup and load_deployment(self.deployment.source_path).raw != self.deployment.raw:
            raise ModelCredentialError("root model credential configuration changed")

    @_serialized
    def prepare(self, profile, handle, identity, scope, *, require_model=True) -> CredentialLease:
        """Durable metadata only; no source read or native credential effect."""
        self._binding(profile, handle, identity)
        if type(scope) is not LaunchScope or LaunchScope.from_dict(scope.as_dict()) != scope or type(require_model) is not bool:
            raise ModelCredentialError("host-assigned scope and explicit model requirement are required")
        if scope.project_id not in {project["projectId"] for project in self.deployment.projects}:
            raise ModelCredentialError("model scope is outside the project allowlist")
        provider = self.deployment.model_credentials["roles"].get(scope.role) if require_model else None
        if require_model and provider is None:
            raise ModelCredentialError("this real agent role has no root-configured model provider; no credential fallback")
        lease = CredentialLease(self.deployment.digest, self.deployment.profile_basis_digest, handle, identity, canonical_digest(scope.as_dict()), provider)
        with self._mutex, self._storage.locked() as transaction:
            state = self._load(transaction); key = _key(lease); prior = state["leases"].get(key)
            if prior is not None:
                if prior["lease"] != lease.as_dict():
                    raise ModelCredentialError("credential generation cannot be rebound to another scope")
                return lease
            if any(record["state"] != "removed" for record in state["leases"].values()):
                raise ModelCredentialError("prior scoped credential cleanup is unresolved; new model dispatch is blocked")
            if len(state["leases"]) >= MAX_LEASES:
                raise ModelCredentialError("permanent credential lease quota exhausted")
            state["leases"][key] = {"lease": lease.as_dict(), "state": "prepared", "receiptDigest": None}
            self._save(transaction, state)
        return lease

    def _transition(self, lease, state_name, receipt=None):
        self._owner()
        with self._mutex, self._storage.locked() as transaction:
            state = self._load(transaction); record = state["leases"].get(_key(lease))
            if record is None or record["lease"] != lease.as_dict():
                raise ModelCredentialError("unknown or changed credential lease")
            if state_name not in TRANSITIONS[record["state"]]:
                raise ModelCredentialError("retiring credential lease cannot be revived")
            if receipt is not None and (type(receipt) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt)):
                raise ModelCredentialError("native credential acknowledgment is not metadata-only")
            record["state"] = state_name; record["receiptDigest"] = receipt
            self._save(transaction, state)

    def _record(self, lease):
        self._owner()
        with self._storage.locked() as transaction:
            record = self._load(transaction)["leases"].get(_key(lease))
            if record is None or record["lease"] != lease.as_dict():
                raise ModelCredentialError("unknown or changed credential lease")
            return record

    @_serialized
    def install(self, profile, handle, identity, scope, *, lease, permit):
        self._binding(profile, handle, identity, lease)
        if type(scope) is not LaunchScope or canonical_digest(scope.as_dict()) != lease.scope_digest:
            raise ModelCredentialError("credential installation scope differs from its pre-journaled lease")
        record = self._record(lease)
        if record["state"] == "installed":
            return record["receiptDigest"]
        self._transition(lease, "install-uncertain")  # Precedes source read/native set.
        if lease.provider is None:
            receipt = canonical_digest({"kind": "no-model-credential", "lease": lease.as_dict()})
        else:
            source = self.deployment.model_credentials["providers"][lease.provider]["sourceFile"]
            raw = _source(Path(source), self.deployment)
            try:
                receipt = self.manager.run_credential(profile, permit, operation="credential-set", service=lease.provider, secret=raw)
            finally:
                raw[:] = b"\0" * len(raw)  # Best effort transient-buffer overwrite.
        self._transition(lease, "installed", receipt)
        return receipt

    @_serialized
    def remove(self, profile, handle, identity, lease, *, permit):
        """Cleanup still attempts exact scoped removal after ledger-write failure."""
        self._binding(profile, handle, identity, lease, cleanup=True)
        if not self._poisoned:
            try:
                record = self._record(lease)
            except Exception:
                record = None
            if record is not None and record["state"] == "removed":
                return record["receiptDigest"]
        failure = None
        try:
            self._transition(lease, "remove-uncertain")
        except Exception as exc:
            failure = exc
        if lease.provider is None:
            receipt = canonical_digest({"kind": "no-model-credential-removed", "lease": lease.as_dict()})
        else:
            receipt = self.manager.run_credential(profile, permit, operation="credential-remove", service=lease.provider)
        if failure is not None:
            raise ModelCredentialError("scoped removal acknowledged but credential metadata remains uncertain") from failure
        self._transition(lease, "removed", receipt)
        return receipt

    def records(self) -> tuple[dict, ...]:
        self._owner()
        with self._mutex, self._storage.locked() as transaction:
            value = self._load(transaction)
            return tuple(value["leases"][key] for key in sorted(value["leases"]))

    def assert_ready(self) -> None:
        """Call before allocating the next VM; never clear unresolved history."""
        if any(record["state"] != "removed" for record in self.records()):
            raise ModelCredentialError("prior scoped credential cleanup is unresolved")

    def close(self):
        with self._mutex:
            self._storage.close()
