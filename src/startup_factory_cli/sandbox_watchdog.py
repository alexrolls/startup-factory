"""Independent watchdog leases and a read-only fresh-admission verifier.

The separate installed daemon revokes its ledger before attempting the namespace
lock. CLI cleanup is best effort and never a daemon queue/storage barrier. A
restart revokes every surviving lease; no persisted numeric PID is signaled.
"""
from __future__ import annotations

import contextlib
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import sys
import threading
import time
from typing import Any

from .execution_backend import BackendIdentity, DockerProfile, canonical_digest, load_profile
from .native_clients import GateTools, NativeClientJournal, ProgramPin, _identity_helper
from .sandbox_controller import AuthorityProof, CleanupProof, GenerationHandle, watchdog_request_digest
from .sandbox_deployment import Deployment, decode_object, load_deployment
from .sandbox_qualification_evidence import verify_deployment_enrollment
from .sandbox_registry import SandboxRegistry, RegistryBusy
from .sandbox_enrollment import profile_basis_digest

LEDGER_FILE = "watchdog-leases.json"
PENDING_FILE = ".watchdog-leases.pending"
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 1024
MAX_FRAME_BYTES = 16 * 1024
RPC_SECONDS = 5.0
FRESH_NS = 5_000_000_000
CLEANUP_GRACE_NS = 30_000_000_000
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_RECORD_KEYS = {"name", "generation", "epoch", "leaseId", "serviceId", "deadline", "deadlineNs", "emergencyAtNs", "state", "sandboxId", "createdAt"}
_HEADER_KEYS = {"schemaVersion", "journalId", "deploymentDigest", "profileBasisDigest", "ownerPid", "ownerIdentity", "freshUntilNs", "records"}


class WatchdogError(RuntimeError):
    pass


def _encode(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_LEDGER_BYTES:
        raise WatchdogError("watchdog history quota exhausted")
    return raw


def _decode(raw: bytes, deployment: Deployment, profile: DockerProfile, journal_id: str) -> dict:
    value = decode_object(raw, maximum=MAX_LEDGER_BYTES)
    if type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1:
        if set(value) != (_HEADER_KEYS - {"profileBasisDigest"}) | {"profileDigest"} or value["profileDigest"] != profile.digest:
            raise WatchdogError("v1 watchdog history requires its exact old profile for migration")
        value.pop("profileDigest")
        value.update(schemaVersion=2, profileBasisDigest=profile_basis_digest(profile))
    if (set(value) != _HEADER_KEYS or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 2
        or value["journalId"] != journal_id or value["deploymentDigest"] != deployment.digest
        or value["profileBasisDigest"] != profile_basis_digest(profile) or type(value["ownerPid"]) is not int or value["ownerPid"] <= 1
        or type(value["ownerIdentity"]) is not str or not value["ownerIdentity"].startswith(("linux:", "darwin:"))
        or "unknown-boot" in value["ownerIdentity"] or type(value["freshUntilNs"]) is not int
        or type(value["records"]) is not dict or len(value["records"]) > MAX_RECORDS):
        raise WatchdogError("watchdog ledger binding is invalid")
    for name, record in value["records"].items():
        if type(record) is not dict or set(record) != _RECORD_KEYS or record["name"] != name:
            raise WatchdogError("watchdog record schema is invalid")
        GenerationHandle(name, record["generation"], record["epoch"])
        if (type(record["leaseId"]) is not str or not _TOKEN.fullmatch(record["leaseId"])
            or type(record["serviceId"]) is not str or not _TOKEN.fullmatch(record["serviceId"])
            or type(record["deadline"]) is not int or record["deadline"] <= 0
            or type(record["deadlineNs"]) is not int or record["deadlineNs"] <= 0
            or type(record["emergencyAtNs"]) is not int or record["emergencyAtNs"] <= 0
            or record["state"] not in {"armed", "bound", "revoked", "disarmed"}):
            raise WatchdogError("watchdog lease is invalid")
        if record["sandboxId"] is not None:
            BackendIdentity(name, record["sandboxId"], record["createdAt"])
        elif record["createdAt"] is not None or record["state"] == "bound":
            raise WatchdogError("watchdog backend identity is incomplete")
    return value


def _read_existing(storage: SandboxRegistry, deployment: Deployment, profile: DockerProfile) -> dict:
    storage._check_root()
    _state, _state_id, _marker_id = storage._load(initialize=False)
    marker, _ = storage._file("registry.identity", maximum=4096)
    journal_id = decode_object(marker)["registryId"]
    try:
        os.stat(PENDING_FILE, dir_fd=storage._root_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise WatchdogError("interrupted watchdog commit requires manual reconciliation")
    raw, _ = storage._file(LEDGER_FILE, maximum=MAX_LEDGER_BYTES)
    return _decode(raw, deployment, profile, journal_id)


def verify_watchdog_lease(deployment_path: Path, *, name: str, generation: str, epoch: int,
                          lease_id: str, deadline: int) -> bool:
    """Read bounded protected bytes only; never lock/init/fence a namespace.

    A short watchdog freshness lease, daemon generation and both wall/monotonic
    deadlines bind every new admission. Immutable already-admitted retries are
    governed separately by their existing recovery rules.
    """
    storage = None
    try:
        handle = GenerationHandle(name, generation, epoch)
        if type(lease_id) is not str or not _TOKEN.fullmatch(lease_id) or type(deadline) is not int:
            return False
        deployment = load_deployment(Path(deployment_path))
        profile = load_profile(Path(deployment.profile_path))
        if os.geteuid() != deployment.controller_uid or profile.namespace != deployment.namespace:
            return False
        storage = SandboxRegistry(Path(deployment.watchdog_root), deployment.namespace)
        value = _read_existing(storage, deployment, profile)
        now_ns = time.monotonic_ns()
        if not now_ns < value["freshUntilNs"] <= now_ns + FRESH_NS:
            return False
        helper = _identity_helper(ProgramPin(Path(deployment.programs["lifecycleHelper"]["path"]), deployment.programs["lifecycleHelper"]["sha256"]))
        if helper.process_identity(value["ownerPid"]) != value["ownerIdentity"]:
            return False
        record = value["records"].get(handle.name)
        return bool(record and (record["generation"], record["epoch"], record["leaseId"], record["deadline"])
                    == (handle.generation, handle.epoch, lease_id, deadline)
                    and record["state"] == "bound" and int(time.time()) < deadline
                    and now_ns < record["deadlineNs"])
    except Exception:
        return False
    finally:
        if storage is not None:
            storage.close()


class WatchdogLedger:
    """Private finite history; its flock is independent of namespace fencing."""
    def __init__(self, deployment: Deployment, profile: DockerProfile, identity: str) -> None:
        self.deployment, self.profile = deployment, profile
        self._storage = SandboxRegistry(Path(deployment.watchdog_root), profile.namespace)
        self._lock = threading.RLock()
        self._failed = False
        try:
            with self._storage.locked() as tx:
                try:
                    value = _read_existing(self._storage, deployment, profile)
                except FileNotFoundError:
                    if tx.epoch != 0:
                        raise WatchdogError("watchdog history cannot be reset")
                    value = {"schemaVersion": 2, "journalId": tx.registry_id, "deploymentDigest": deployment.digest,
                        "profileBasisDigest": profile_basis_digest(profile), "ownerPid": os.getpid(), "ownerIdentity": identity,
                        "freshUntilNs": time.monotonic_ns() + FRESH_NS, "records": {}}
                    self._storage._write_exclusive(LEDGER_FILE, _encode(value))
                    os.fsync(self._storage._root_fd)
                    tx.takeover()
                for record in value["records"].values():
                    if record["state"] != "disarmed":
                        record["state"] = "revoked"
                        record["emergencyAtNs"] = time.monotonic_ns()
                value.update(ownerPid=os.getpid(), ownerIdentity=identity, freshUntilNs=time.monotonic_ns() + FRESH_NS)
                self._commit(tx, value)
        except BaseException:
            self._storage.close()
            raise

    def _commit(self, tx: Any, value: dict) -> None:
        raw = _encode(value)
        try:
            self._storage._write_exclusive(PENDING_FILE, raw)
            tx.records()
            os.replace(PENDING_FILE, LEDGER_FILE, src_dir_fd=self._storage._root_fd, dst_dir_fd=self._storage._root_fd)
            os.fsync(self._storage._root_fd)
        except BaseException:
            self._failed = True
            raise

    def change(self, action: Any) -> Any:
        with self._lock, self._storage.locked() as tx:
            if self._failed:
                raise WatchdogError("watchdog durability is uncertain")
            value = _read_existing(self._storage, self.deployment, self.profile)
            result = action(value)
            value["freshUntilNs"] = time.monotonic_ns() + FRESH_NS
            self._commit(tx, value)
            return result

    def snapshot(self) -> dict:
        with self._lock:
            return _read_existing(self._storage, self.deployment, self.profile)

    def close(self) -> None:
        self._storage.close()


def _receive(connection: socket.socket, *, timeout: float = RPC_SECONDS) -> dict:
    deadline = time.monotonic() + timeout
    def exact(count: int) -> bytes:
        result = bytearray()
        while len(result) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WatchdogError("watchdog RPC deadline exceeded")
            connection.settimeout(remaining)
            chunk = connection.recv(count - len(result))
            if not chunk:
                raise EOFError
            result.extend(chunk)
        return bytes(result)
    count = struct.unpack("!I", exact(4))[0]
    if not 0 < count <= MAX_FRAME_BYTES:
        raise WatchdogError("watchdog frame exceeds its limit")
    return decode_object(exact(count), maximum=MAX_FRAME_BYTES)


def _send(connection: socket.socket, value: dict) -> None:
    raw = _encode(value)
    if len(raw) > MAX_FRAME_BYTES:
        raise WatchdogError("watchdog response exceeds its limit")
    connection.settimeout(RPC_SECONDS)
    connection.sendall(struct.pack("!I", len(raw)) + raw)


class _DarwinAuditToken(ctypes.Structure):
    # Apple mach/message.h: audit_token_t is a 32-byte struct, not a pointer.
    # libbsm.h accepts this aggregate BY VALUE. Declare that C ABI explicitly;
    # an indirect aggregate ABI on one architecture is not a portable contract.
    _fields_ = [("val", ctypes.c_uint32 * 8)]


def _peer_uid(connection: socket.socket) -> int:
    if sys.platform.startswith("linux"):
        return struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED", 17), struct.calcsize("3i")))[1]
    if sys.platform == "darwin":
        # Same kernel audit-token interface used by publication-supervisor.
        token = connection.getsockopt(0, 0x006, 32)  # SOL_LOCAL / LOCAL_PEERTOKEN
        if len(token) != 32:
            raise WatchdogError("Darwin native peer token is incomplete")
        try:
            bsm = ctypes.CDLL("/usr/lib/libbsm.dylib")
            bsm.audit_token_to_euid.argtypes = [_DarwinAuditToken]
            bsm.audit_token_to_euid.restype = ctypes.c_uint32
            audit_token = _DarwinAuditToken.from_buffer_copy(token)
            return int(bsm.audit_token_to_euid(audit_token))
        except (OSError, AttributeError, ValueError) as exc:
            raise WatchdogError("Darwin peer credential extraction is unavailable") from exc
    if hasattr(connection, "getpeereid"):
        return connection.getpeereid()[0]
    raise WatchdogError("native peer authentication is unavailable")


class IndependentWatchdogClient:
    """One persistent service liveness connection; never inherited by children."""
    def __init__(self, deployment: Deployment) -> None:
        self.deployment = deployment
        self._pid = os.getpid()
        self._lock = threading.RLock()
        self._bindings: dict[str, dict] = {}
        self._stop = threading.Event()
        self._failed = False
        self._connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._connection.settimeout(RPC_SECONDS)
        self._connection.connect(deployment.watchdog_socket_path)
        if _peer_uid(self._connection) != deployment.controller_uid:
            self._connection.close()
            raise WatchdogError("watchdog endpoint has another native owner")
        self._rpc("register", {})
        self._heartbeat = threading.Thread(target=self._beat, daemon=True)
        self._heartbeat.start()

    def _rpc(self, operation: str, payload: dict) -> dict:
        if os.getpid() != self._pid or self._failed:
            raise WatchdogError("watchdog lease is inherited or disconnected")
        with self._lock:
            try:
                _send(self._connection, {"schemaVersion": 1, "operation": operation, "deploymentDigest": self.deployment.digest, "payload": payload})
                response = _receive(self._connection)
                if set(response) != {"ok", "result"} or response["ok"] is not True or type(response["result"]) is not dict:
                    raise WatchdogError("watchdog refused the operation")
                return response["result"]
            except BaseException:
                self._failed = True
                self._connection.close()
                raise

    def _beat(self) -> None:
        while not self._stop.wait(1):
            try:
                self._rpc("heartbeat", {})
            except Exception:
                return

    def validate_backend(self, backend: Any, profile: DockerProfile) -> bool:
        health = self._rpc("health", {})
        if health != {"nativePoolBlocked": False}:
            return False
        return bool(getattr(backend, "custody", None) and backend.custody.is_bound_to(backend, profile))

    def arm(self, profile: DockerProfile, handle: GenerationHandle, deadline: int) -> AuthorityProof:
        result = self._rpc("arm", {"handle": handle.as_dict(), "deadline": deadline})
        self._bindings[handle.name] = {"handle": handle.as_dict(), "deploymentPath": str(self.deployment.source_path), "leaseId": result["leaseId"], "deadline": deadline}
        return AuthorityProof(watchdog_request_digest(profile, handle, deadline), result["evidenceDigest"])

    def binding(self, handle: GenerationHandle) -> dict:
        self._rpc("heartbeat", {})
        if handle.name not in self._bindings or self._bindings[handle.name]["handle"] != handle.as_dict():
            raise WatchdogError("watchdog generation is not armed")
        return {key: value for key, value in self._bindings[handle.name].items() if key != "handle"}

    def bind(self, handle: GenerationHandle, identity: BackendIdentity) -> bool:
        self._rpc("bind", {"handle": handle.as_dict(), "identity": identity.as_dict()})
        return True

    def operation_live(self, handle: GenerationHandle) -> bool:
        self._rpc("check", {"handle": handle.as_dict()})
        return True

    def fence(self, handle: GenerationHandle) -> bool:
        self._rpc("fence", {"handle": handle.as_dict()})
        return True

    def disarm(self, handle: GenerationHandle, proof: CleanupProof) -> bool:
        if type(proof) is not CleanupProof or not all((proof.native_clients_reaped, proof.late_commands_quiescent, proof.storage_cleanup_verified, proof.name_and_id_absent)):
            return False
        self._rpc("disarm", {"handle": handle.as_dict(), "proofDigest": proof.evidence_digest})
        return True

    def close(self) -> None:
        self._stop.set()
        self._connection.close()  # EOF independently revokes every non-disarmed lease


class WatchdogDaemon:
    def __init__(self, deployment: Deployment) -> None:
        self.deployment = deployment
        self.profile = load_profile(Path(deployment.profile_path))
        self.registry = SandboxRegistry(Path(deployment.registry_root), deployment.namespace)
        self.enrollment = verify_deployment_enrollment(deployment, self.profile, Path(deployment.receipt_path), self.registry)
        pin = deployment.programs["lifecycleHelper"]
        self._identity = _identity_helper(ProgramPin(Path(pin["path"]), pin["sha256"]))
        identity = self._identity.process_identity(os.getpid())
        if not identity:
            raise WatchdogError("watchdog lacks stable process identity")
        self.ledger = WatchdogLedger(deployment, self.profile, identity)
        self._stop = threading.Event()
        self._sessions: dict[str, float] = {}
        self._session_lock = threading.RLock()
        self._active_connections = 0
        self._cleanup_started: set[str] = set()
        self._cleanup_lock = threading.RLock()
        self._cleanup_inflight = 0
        from .native_custody import JournalCustody
        from .docker_backend import DockerBackend
        pins = deployment.programs
        tools = GateTools(*(ProgramPin(Path(pins[name]["path"]), pins[name]["sha256"]) for name in ("python", "gate", "lifecycleHelper")))
        # An interrupted main-service journal commit must not prevent the
        # independent owner from journaling best-effort cleanup. This fixed
        # private child remains under the same enrolled aggregate HOME quota.
        self.ledger._storage._check_root()
        try:
            os.mkdir("native-clients", 0o700, dir_fd=self.ledger._storage._root_fd)
        except FileExistsError:
            pass
        native_root = Path(deployment.watchdog_root) / "native-clients"
        self._native = JournalCustody(NativeClientJournal(native_root, Path(deployment.profile_path), tools))
        self._cleanup = threading.local()
        self._cleanup_backend = DockerBackend(Path(deployment.profile_path), permit=self._cleanup_permit,
                                              custody=self._native, native_client_reconciler=self)

    @contextlib.contextmanager
    def _cleanup_permit(self, profile, request):
        from .docker_backend import OperationPermit
        record = getattr(self._cleanup, "record", None)
        if (record is None or profile != self.profile or request.operation not in {"inspect", "stop", "destroy"}
            or request.identity != BackendIdentity(record["name"], record["sandboxId"], record["createdAt"])):
            raise WatchdogError("watchdog only permits exact fenced-object cleanup")
        digest = canonical_digest({"operation": "watchdog-best-effort-cleanup", "deployment": self.deployment.digest, "record": record})
        yield OperationPermit(request.digest, record["name"], record["generation"], record["epoch"], digest)

    def authorize_native(self, profile, permit, intent) -> bool:
        record = getattr(self._cleanup, "record", None)
        return bool(record is not None and profile == self.profile
                    and intent.operation in {"inspect", "list", "stop", "destroy", "credential-remove"}
                    and (intent.name, intent.generation, intent.epoch)
                    == (record["name"], record["generation"], record["epoch"]))

    def _fence_registry(self, record: dict) -> None:
        # Ledger revocation is already durable and independent of this lock.
        # Failure is conservative: the revoked tombstone never becomes clean.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with SandboxRegistry(Path(self.deployment.registry_root), self.deployment.namespace) as registry, registry.locked() as tx:
                    matches = [item for item in tx.records() if item["name"] == record["name"] and item["generation"] == record["generation"]]
                    if not matches or matches[0]["state"] == "removed":
                        return
                    # Only the current epoch owner can write lifecycle state.
                    # Emergency takeover fences the complete pool; revoke all
                    # publication leases before changing the namespace epoch.
                    def revoke_all(value):
                        for lease in value["records"].values():
                            if lease["state"] != "disarmed":
                                lease["state"] = "revoked"
                                lease["emergencyAtNs"] = min(lease["emergencyAtNs"], time.monotonic_ns())
                    self.ledger.change(revoke_all)
                    tx.takeover()
                    current = next(item for item in tx.records() if item["name"] == record["name"])
                    tx.fence(current["name"], current["generation"], current["epoch"])
                    tx.transition(current["name"], current["generation"], current["epoch"], state="cleanup-pending")
                    if current["sandboxId"] is not None:
                        if record["sandboxId"] is not None and (record["sandboxId"], record["createdAt"]) != (current["sandboxId"], current["createdAt"]):
                            return
                        self._cleanup.record = current
                        try:
                            from .docker_backend import OperationPermit
                            credential_request = canonical_digest({"operation": "watchdog-remove-openai", "deployment": self.deployment.digest, "record": current})
                            credential_permit = OperationPermit(credential_request, current["name"], current["generation"], current["epoch"], credential_request)
                            with contextlib.suppress(Exception):
                                self._native.run_credential(self.profile, credential_permit,
                                                            operation="credential-remove", service="openai")
                            identity = BackendIdentity(current["name"], current["sandboxId"], current["createdAt"])
                            self._cleanup_backend.stop(identity)
                            self._cleanup_backend.destroy(identity)
                        finally:
                            self._cleanup.record = None
                    # No queued-command/storage proof or terminal transition.
                    return
            except RegistryBusy:
                time.sleep(.1)
            except Exception:
                return

    def _revocations(self, services: set[str] | None = None) -> None:
        expired = []
        def revoke(value):
            for record in value["records"].values():
                emergency = (int(time.time()) >= record["deadline"] or time.monotonic_ns() >= record["deadlineNs"]
                             or services is not None and record["serviceId"] in services)
                if record["state"] != "disarmed" and emergency:
                    record["state"] = "revoked"
                    record["emergencyAtNs"] = min(record["emergencyAtNs"], time.monotonic_ns())
                if record["state"] == "revoked" and time.monotonic_ns() >= record["emergencyAtNs"]:
                    with self._cleanup_lock:
                        if record["leaseId"] not in self._cleanup_started and self._cleanup_inflight < 4:
                            expired.append(dict(record)); self._cleanup_started.add(record["leaseId"])
                            self._cleanup_inflight += 1
        self.ledger.change(revoke)
        for record in expired:
            def cleanup(selected=record):
                try:
                    self._fence_registry(selected)
                finally:
                    with self._cleanup_lock:
                        self._cleanup_inflight -= 1
            try:
                threading.Thread(target=cleanup, daemon=True).start()
            except Exception:
                with self._cleanup_lock:
                    self._cleanup_inflight -= 1
                    self._cleanup_started.discard(record["leaseId"])
                raise

    def _dispatch(self, service_id: str, operation: str, payload: dict) -> dict:
        if operation == "health":
            if payload:
                raise WatchdogError("unknown health fields")
            native = getattr(self, "_native", None)
            return {"nativePoolBlocked": native is None or native.pool_blocked}
        if operation in {"register", "heartbeat"}:
            if payload:
                raise WatchdogError("unknown heartbeat fields")
            with self._session_lock:
                self._sessions[service_id] = time.monotonic()
            return {}
        if operation not in {"arm", "bind", "fence", "disarm", "check"}:
            raise WatchdogError("unsupported watchdog command")
        fields = {"arm": {"handle", "deadline"}, "bind": {"handle", "identity"}, "fence": {"handle"}, "disarm": {"handle", "proofDigest"}, "check": {"handle"}}
        if set(payload) != fields[operation] or type(payload["handle"]) is not dict or set(payload["handle"]) != {"name", "generation", "epoch"}:
            raise WatchdogError("unknown watchdog operation fields")
        handle = GenerationHandle(**payload["handle"])
        def change(value):
            record = value["records"].get(handle.name)
            if operation == "arm":
                deadline = payload["deadline"]
                native = getattr(self, "_native", None)
                if (native is not None and native.pool_blocked or record is not None or len(value["records"]) >= MAX_RECORDS or type(deadline) is not int
                    or not int(time.time()) < deadline <= min(int(time.time()) + self.profile.limits.wall_seconds, self.enrollment.expires_at)):
                    raise WatchdogError("watchdog name is reused, quota exhausted or deadline invalid")
                record = {**handle.as_dict(), "leaseId": secrets.token_hex(16), "serviceId": service_id,
                    "deadline": deadline, "deadlineNs": time.monotonic_ns() + max(0, deadline - int(time.time())) * 1_000_000_000,
                    "emergencyAtNs": time.monotonic_ns() + max(0, deadline - int(time.time())) * 1_000_000_000,
                    "state": "armed", "sandboxId": None, "createdAt": None}
                value["records"][handle.name] = record
            elif (record is None or (record["generation"], record["epoch"], record["serviceId"]) != (handle.generation, handle.epoch, service_id)):
                raise WatchdogError("watchdog generation/service mismatch")
            elif operation == "bind":
                identity = BackendIdentity.from_dict(payload["identity"])
                if identity.name != handle.name or record["state"] not in {"armed", "bound"} or record["sandboxId"] not in {None, identity.sandbox_id} or record["createdAt"] not in {None, identity.created_at}:
                    raise WatchdogError("watchdog identity replacement refused")
                record.update(sandboxId=identity.sandbox_id, createdAt=identity.created_at, state="bound")
            elif operation == "fence":
                if record["state"] != "disarmed":
                    if record["state"] != "revoked":
                        record["emergencyAtNs"] = min(record["deadlineNs"], time.monotonic_ns() + CLEANUP_GRACE_NS)
                    record["state"] = "revoked"
            elif operation == "check":
                if record["state"] not in {"armed", "bound"} or int(time.time()) >= record["deadline"] or time.monotonic_ns() >= record["deadlineNs"]:
                    raise WatchdogError("watchdog lease no longer permits workload dispatch")
            else:
                if record["state"] not in {"revoked", "disarmed"} or not re.fullmatch(r"sha256:[0-9a-f]{64}", payload["proofDigest"]):
                    raise WatchdogError("clean removal proof is missing")
                record["state"] = "disarmed"
            return {"leaseId": record["leaseId"], "evidenceDigest": canonical_digest(record)}
        return self.ledger.change(change)

    def _connection(self, connection: socket.socket) -> None:
        service_id = secrets.token_hex(16)
        try:
            if _peer_uid(connection) != self.deployment.controller_uid:
                return
            while not self._stop.is_set():
                request = _receive(connection)
                if set(request) != {"schemaVersion", "deploymentDigest", "operation", "payload"} or type(request["schemaVersion"]) is not int or request["schemaVersion"] != 1 or request["deploymentDigest"] != self.deployment.digest or type(request["operation"]) is not str or type(request["payload"]) is not dict:
                    raise WatchdogError("unknown watchdog RPC schema")
                result = self._dispatch(service_id, request["operation"], request["payload"])
                _send(connection, {"ok": True, "result": result})
        except Exception:
            pass
        finally:
            connection.close()
            with self._session_lock:
                self._sessions.pop(service_id, None)
                self._active_connections = max(0, self._active_connections - 1)
            with contextlib.suppress(Exception):
                self._revocations({service_id})

    def serve(self) -> None:
        path = Path(self.deployment.watchdog_socket_path)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise WatchdogError("watchdog socket parent must be private")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(path))  # never unlink/adopt a preexisting endpoint
            os.chmod(path, 0o600)
            server.listen(16)
            server.settimeout(.5)
            while not self._stop.is_set():
                self._revocations()
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                with self._session_lock:
                    if self._active_connections >= 32:
                        connection.close()
                        continue
                    self._active_connections += 1
                threading.Thread(target=self._connection, args=(connection,), daemon=True).start()
        finally:
            server.close()
            self._stop.set()
            with contextlib.suppress(Exception):
                self._revocations(set(self._sessions))
            self.ledger.close()
            self.registry.close()


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("serve",))
    parser.add_argument("--deployment", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        WatchdogDaemon(load_deployment(args.deployment)).serve()
        return 0
    except Exception:
        print("sandbox watchdog refused startup or stopped; publication leases are unavailable", file=__import__("sys").stderr)
        return 1
