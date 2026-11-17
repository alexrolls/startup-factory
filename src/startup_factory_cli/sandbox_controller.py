"""Fail-closed lifecycle orchestration for the enrolled persistent service.

The plain Docker adapter is insufficient: the service must bind its real
pre-exec native journal, finite stream provisioner, independent watchdog, and
current reconciliation authority. No automatic enrollment or permit defaults
are provided. Guest data never creates a permit, proof, registry handle,
command, or enrollment receipt.

Lock order is namespace registry, authority/native-client journal, then task or
capability authority. Native leases must remain independently revocable without
acquiring the namespace lock. No namespace lock spans session pipe I/O.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import os
from pathlib import Path
import re
import time
import threading
from typing import Any, Callable, ContextManager, Iterator, Protocol

from .docker_backend import OperationPermit, OperationRequest
from .execution_backend import (
    ArtifactReference, Backend, BackendIdentity, BackendObservation,
    BackendSession, DockerProfile, GuestCommand, LaunchScope, LaunchSpec,
    _digest, canonical_digest, load_profile,
)
from .sandbox_enrollment import EnrollmentReceipt, load_enrollment
from .sandbox_registry import RegistryTransaction, SandboxRegistry


class ControllerError(RuntimeError):
    """Work is refused or requires independent reconciliation."""


@dataclasses.dataclass(frozen=True)
class GenerationHandle:
    name: str
    generation: str
    epoch: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not re.fullmatch(r"sf-[0-9a-f]{32}", self.name) or not isinstance(self.generation, str) or not re.fullmatch(r"gen-[0-9a-f]{32}", self.generation) or type(self.epoch) is not int or not 1 <= self.epoch <= 2**63 - 1:
            raise ControllerError("invalid host generation handle")

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "generation": self.generation, "epoch": self.epoch}


@dataclasses.dataclass(frozen=True)
class ReconciliationProof:
    request_digest: str
    evidence_digest: str
    absent_names: tuple[str, ...]
    native_clients_reaped: bool
    late_commands_quiescent: bool
    namespace_exclusive: bool
    storage_cleanup_verified: bool


@dataclasses.dataclass(frozen=True)
class NativeOperationLease:
    request_digest: str
    reconciliation_digest: str
    journaled_before_exec: bool
    independently_revocable: bool


@dataclasses.dataclass(frozen=True)
class AuthorityProof:
    """A trusted implementation's evidence, not a guest-serializable authority."""
    request_digest: str
    evidence_digest: str


@dataclasses.dataclass(frozen=True)
class CleanupProof:
    request_digest: str
    evidence_digest: str
    native_clients_reaped: bool
    late_commands_quiescent: bool
    storage_cleanup_verified: bool
    name_and_id_absent: bool


def reconciliation_request_digest(profile: DockerProfile, registry_id: str, epoch: int, records: tuple[dict[str, Any], ...]) -> str:
    return canonical_digest({"operation": "reconcile-namespace", "profileDigest": profile.digest,
                             "registryId": registry_id, "epoch": epoch, "records": list(records)})


def native_lease_request_digest(request: OperationRequest, record: dict[str, Any], epoch: int) -> str:
    """Bind a native journal lease to one permanent generation, including create.

    A create OperationRequest has no BackendIdentity, so identical launch specs
    alone cannot distinguish two reserved names or generations.
    """
    return canonical_digest({"request": request.as_dict(), "epoch": epoch,
                             "name": record["name"], "generation": record["generation"],
                             "recordEpoch": record["epoch"], "sandboxId": record["sandboxId"],
                             "createdAt": record["createdAt"], "scope": record["scope"]})


def provisioning_request_digest(profile: DockerProfile, handle: GenerationHandle, identity: BackendIdentity, scope: LaunchScope, manifest: ArtifactReference) -> str:
    return canonical_digest({"operation": "provision", "profileDigest": profile.digest,
                             "generation": handle.as_dict(), "identity": identity.as_dict(),
                             "scope": scope.as_dict(), "manifestDigest": manifest.digest})


def watchdog_request_digest(profile: DockerProfile, handle: GenerationHandle, deadline: int) -> str:
    return canonical_digest({"operation": "arm-watchdog", "profileDigest": profile.digest,
                             "generation": handle.as_dict(), "deadline": deadline})


def quiescence_request_digest(profile: DockerProfile, record: dict[str, Any]) -> str:
    return canonical_digest({"operation": "quiesce-native-clients", "profileDigest": profile.digest, "record": record})


def cleanup_request_digest(profile: DockerProfile, record: dict[str, Any], removal: ArtifactReference | None) -> str:
    return canonical_digest({"operation": "confirm-absence", "profileDigest": profile.digest,
                             "record": record, "removalDigest": None if removal is None else removal.digest})


class NativeClientReconciler(Protocol):
    """Must own an actually gated durable pre-spawn/pre-exec native journal.

    ``validate_backend`` must reject an ungated Docker adapter. A
    permit or a Popen PID registered after exec cannot establish this contract.
    Reconciliation includes late queued daemon commands and all namespace
    endpoints; killing the known CLI PID is insufficient.
    """
    def validate_backend(self, backend: Backend, profile: DockerProfile) -> bool: ...
    def reconcile(self, profile: DockerProfile, registry_id: str, epoch: int, records: tuple[dict[str, Any], ...]) -> ReconciliationProof: ...
    def lease(self, profile: DockerProfile, request: OperationRequest, record: dict[str, Any], epoch: int) -> ContextManager[NativeOperationLease]: ...
    def quiesce(self, profile: DockerProfile, record: dict[str, Any]) -> AuthorityProof: ...
    def confirm_absence(self, profile: DockerProfile, record: dict[str, Any], removal: ArtifactReference | None) -> CleanupProof: ...


class InputProvisioner(Protocol):
    """Supply bounded digest-approved bytes, never arbitrary host paths.

    Provisioning verifies the approved input manifest, fixed guest bridge and
    model scope. The concrete job runner uses separately permitted binary
    provision sessions; arbitrary host-path copying remains unsupported.
    """
    def validate_backend(self, backend: Backend, profile: DockerProfile) -> bool: ...
    def provision(self, profile: DockerProfile, backend: Backend, handle: GenerationHandle, identity: BackendIdentity, scope: LaunchScope, manifest: ArtifactReference) -> AuthorityProof: ...


class IndependentWatchdog(Protocol):
    """Persist before create; survive controller death and fence publication.

    arm() must cover the unbound name and late native commands. bind() pins the
    observed identity. fence() must revoke publication independently before
    runtime cleanup. A controller thread/timer is not this watchdog.
    """
    def validate_backend(self, backend: Backend, profile: DockerProfile) -> bool: ...
    def arm(self, profile: DockerProfile, handle: GenerationHandle, deadline: int) -> AuthorityProof: ...
    def bind(self, handle: GenerationHandle, identity: BackendIdentity) -> bool: ...
    def fence(self, handle: GenerationHandle) -> bool: ...
    def disarm(self, handle: GenerationHandle, proof: CleanupProof) -> bool: ...


PolicyCheck = Callable[[str, DockerProfile, LaunchScope | None], bool]


@dataclasses.dataclass(frozen=True)
class _Operation:
    kind: str
    record: dict[str, Any]
    launch_spec: LaunchSpec | None = None
    command: GuestCommand | None = None


def _serialized(method):
    @functools.wraps(method)
    def guarded(self, *args, **kwargs):
        with self._control_lock:
            return method(self, *args, **kwargs)
    return guarded


class SandboxController:
    """One epoch on one existing registry; no guest-selected control surface."""

    def __init__(self, profile_path: Path, receipt_path: Path, registry: SandboxRegistry, backend: Backend, *, policy: PolicyCheck, reconciler: NativeClientReconciler, provisioner: InputProvisioner, watchdog: IndependentWatchdog):
        if type(registry) is not SandboxRegistry or not callable(policy) or any(component is None for component in (backend, reconciler, provisioner, watchdog)):
            raise ControllerError("controller requires all independent trusted authority implementations")
        self.profile_path = Path(profile_path)
        self.receipt_path = Path(receipt_path)
        self.registry = registry
        self.backend = backend
        self.policy = policy
        self.reconciler = reconciler
        self.provisioner = provisioner
        self.watchdog = watchdog
        self.profile: DockerProfile | None = None
        self.enrollment: EnrollmentReceipt | None = None
        self.epoch: int | None = None
        self._proof: ReconciliationProof | None = None
        self._operation: _Operation | None = None
        self._transaction: RegistryTransaction | None = None
        self._launches: dict[str, LaunchSpec] = {}
        self._network_ready: set[tuple[str, str, int]] = set()
        self._failed = False
        self._pid = os.getpid()
        self._control_lock = threading.RLock()

    def _owner(self, *, cleanup: bool = False) -> None:
        if os.getpid() != self._pid or self.epoch is None or self.profile is None or (self._failed and not cleanup):
            raise ControllerError("controller is unstarted, inherited, or fenced")

    def _authority(self, transaction: RegistryTransaction) -> DockerProfile:
        profile = load_profile(self.profile_path)
        receipt = load_enrollment(profile, self.receipt_path, self.registry, transaction=transaction)
        if self.profile is not None and profile != self.profile:
            raise ControllerError("protected profile changed; a new controller is required")
        if self.enrollment is not None and receipt != self.enrollment:
            raise ControllerError("protected enrollment changed; a new controller is required")
        return profile

    @staticmethod
    def _proof_matches(proof: Any, expected_type: type, request_digest: str) -> None:
        if type(proof) is not expected_type or proof.request_digest != request_digest:
            raise ControllerError("trusted evidence is missing or bound to another operation")
        _digest(proof.evidence_digest, "trusted evidence digest")

    def _policy(self, action: str, profile: DockerProfile, scope: LaunchScope | None) -> None:
        if self.policy(action, profile, scope) is not True:
            raise ControllerError("current host policy refused sandbox work")

    @_serialized
    def start(self) -> int:
        if self.epoch is not None or self._failed or os.getpid() != self._pid:
            raise ControllerError("controller cannot restart or inherit an epoch")
        try:
            # Refuse missing/unsafe enrollment before the registry's lock can
            # initialize an empty root. Recheck again under the namespace lock.
            preliminary = load_profile(self.profile_path)
            load_enrollment(preliminary, self.receipt_path, self.registry)
            with self.registry.locked() as transaction:
                profile = self._authority(transaction)
                if getattr(self.backend, "native_client_reconciler", None) is not self.reconciler:
                    raise ControllerError("backend has no bound pre-exec native-client journal")
                for component in (self.reconciler, self.provisioner, self.watchdog):
                    if component.validate_backend(self.backend, profile) is not True:
                        raise ControllerError("required independent backend authority is unavailable")
                self._policy("start", profile, None)
                self.profile = profile
                self.enrollment = load_enrollment(profile, self.receipt_path, self.registry, transaction=transaction)
                self.epoch = transaction.takeover()  # durable fence precedes recovery
                records = tuple(record for record in transaction.records() if record["state"] != "removed")
                proof = self.reconciler.reconcile(profile, transaction.registry_id, self.epoch, records)
                if type(proof) is not ReconciliationProof or proof.request_digest != reconciliation_request_digest(profile, transaction.registry_id, self.epoch, records) or proof.native_clients_reaped is not True or proof.late_commands_quiescent is not True or proof.namespace_exclusive is not True or proof.storage_cleanup_verified is not True or type(proof.absent_names) is not tuple or len(proof.absent_names) != len(set(proof.absent_names)) or set(proof.absent_names) != {record["name"] for record in records}:
                    raise ControllerError("namespace and native children are not independently reconciled")
                _digest(proof.evidence_digest, "reconciliation evidence digest")
                for record in records:
                    self._mark_absent(transaction, record)
                self._proof = proof
                return self.epoch
        except Exception as exc:
            self._failed = True
            raise ControllerError("controller startup refused; independent reconciliation is required") from exc

    def _record(self, transaction: RegistryTransaction, handle: GenerationHandle, *, states: set[str] | None = None) -> dict[str, Any]:
        self._owner(cleanup=states is None)
        if type(handle) is not GenerationHandle or handle.epoch != self.epoch or transaction.epoch != self.epoch:
            raise ControllerError("stale generation or controller epoch")
        records = [record for record in transaction.records() if record["name"] == handle.name]
        if len(records) != 1 or records[0]["generation"] != handle.generation or records[0]["epoch"] != handle.epoch:
            raise ControllerError("generation does not match the permanent registry")
        record = records[0]
        if states is not None and record["state"] not in states:
            raise ControllerError("generation is outside the required lifecycle state")
        return record

    @staticmethod
    def _identity(record: dict[str, Any]) -> BackendIdentity:
        return BackendIdentity(record["name"], record["sandboxId"], record["createdAt"])

    def _invoke(self, transaction: RegistryTransaction, kind: str, record: dict[str, Any], action: Callable[[], Any], *, launch_spec: LaunchSpec | None = None, command: GuestCommand | None = None) -> Any:
        if self._transaction is not None or self._operation is not None:
            raise ControllerError("nested controller runtime operation")
        self._transaction = transaction
        self._operation = _Operation(kind, record, launch_spec, command)
        try:
            return action()
        finally:
            self._operation = None
            self._transaction = None

    @contextlib.contextmanager
    def operation_permit(self, profile: DockerProfile, request: OperationRequest) -> Iterator[OperationPermit]:
        """Adapter callback; no caller outside an in-progress method gets a lease."""
        operation, transaction = self._operation, self._transaction
        cleanup = operation is not None and operation.kind in {"stop", "destroy", "credential-remove"}
        self._owner(cleanup=cleanup)
        if operation is None or transaction is None or self._proof is None or type(request) is not OperationRequest or type(request.controller_pid) is not int or request.controller_pid != self._pid or type(profile) is not DockerProfile or profile != self.profile:
            raise ControllerError("no current controller operation permits this runtime request")
        record = self._record(transaction, GenerationHandle(operation.record["name"], operation.record["generation"], operation.record["epoch"]))
        expected = OperationRequest(operation=operation.kind, profile_digest=profile.digest,
                                    namespace=profile.namespace, controller_pid=self._pid,
                                    identity=None if operation.kind == "create" else self._identity(record),
                                    launch_spec=operation.launch_spec, guest_command=operation.command)
        if request != expected:
            raise ControllerError("runtime request differs from the host-assigned operation")
        if not cleanup:
            self._authority(transaction)
            self._policy(operation.kind, profile, LaunchScope.from_dict(record["scope"]))
        with self.reconciler.lease(profile, request, record, record["epoch"]) as lease:
            if type(lease) is not NativeOperationLease or lease.request_digest != native_lease_request_digest(request, record, record["epoch"]) or lease.reconciliation_digest != self._proof.evidence_digest or lease.journaled_before_exec is not True or lease.independently_revocable is not True:
                raise ControllerError("native runtime operation lacks a gated, revocable journal lease")
            yield OperationPermit(request.digest, record["name"], record["generation"], record["epoch"], lease.reconciliation_digest)

    def _failed_generation(self, transaction: RegistryTransaction, handle: GenerationHandle) -> None:
        self._failed = True
        failure: Exception | None = None
        try:
            record = self._record(transaction, handle)
            if record["state"] != "removed":
                transaction.fence(handle.name, handle.generation, handle.epoch)
                transaction.transition(handle.name, handle.generation, handle.epoch, state="cleanup-pending")
        except Exception as exc:
            failure = exc
        # Attempt revocation even after an uncertain registry write. The
        # watchdog must not require this namespace lock to revoke work.
        try:
            if self.watchdog.fence(handle) is not True:
                raise ControllerError("independent publication revocation is unconfirmed")
        except Exception as exc:
            failure = exc
        if failure is not None:
            raise ControllerError("sandbox cleanup required; durable fencing or publication revocation is unconfirmed") from failure

    @_serialized
    def allocate(self, launch_spec: LaunchSpec) -> GenerationHandle:
        self._owner()
        if type(launch_spec) is not LaunchSpec or launch_spec.profile_digest != self.profile.digest:
            raise ControllerError("launch specification differs from the protected profile")
        with self.registry.locked() as transaction:
            profile = self._authority(transaction)
            self._policy("allocate", profile, launch_spec.scope)
            if transaction.epoch != self.epoch:
                raise ControllerError("controller epoch is stale")
            record = transaction.reserve(launch_spec.scope.as_dict(), epoch=self.epoch)
            handle = GenerationHandle(record["name"], record["generation"], record["epoch"])
            self._launches[handle.name] = launch_spec
            try:
                deadline = min(int(time.time()) + profile.limits.wall_seconds, self.enrollment.expires_at)
                proof = self.watchdog.arm(profile, handle, deadline)
                self._proof_matches(proof, AuthorityProof, watchdog_request_digest(profile, handle, deadline))
                identity = self._invoke(transaction, "create", record, lambda: self.backend.create(launch_spec), launch_spec=launch_spec)
                if type(identity) is not BackendIdentity or identity.name != handle.name:
                    raise ControllerError("created object differs from the reserved name")
                transaction.bind(handle.name, handle.generation, handle.epoch, sandbox_id=identity.sandbox_id, created_at=identity.created_at)
                if self.watchdog.bind(handle, identity) is not True:
                    raise ControllerError("independent watchdog did not bind the exact object")
                return handle
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("sandbox creation is fenced and requires reconciliation") from exc

    @_serialized
    def configure_network(self, handle: GenerationHandle, policy) -> ArtifactReference:
        """Remove the create deny lock only through the pinned typed policy."""
        from .sandbox_network_policy import ModelNetworkPolicy
        self._owner()
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"allocated"})
            profile = self._authority(transaction)
            if type(policy) is not ModelNetworkPolicy or policy.namespace != profile.namespace or policy.digest != profile.policy_digest:
                raise ControllerError("network policy differs from protected enrollment")
            self._policy("policy-activate", profile, LaunchScope.from_dict(record["scope"]))
            try:
                receipt = self._invoke(transaction, "policy-activate", record,
                    lambda: self.backend.configure_network(self._identity(record), policy))
                if type(receipt) is not ArtifactReference:
                    raise ControllerError("network activation has no verified native receipt")
                self._network_ready.add((handle.name, handle.generation, handle.epoch))
                return receipt
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("network activation was fenced") from exc

    def _require_network(self, handle: GenerationHandle) -> None:
        if (handle.name, handle.generation, handle.epoch) not in self._network_ready:
            raise ControllerError("pinned network activation must precede credentials and source")

    @_serialized
    def provision(self, handle: GenerationHandle, manifest: ArtifactReference) -> AuthorityProof:
        self._owner()
        self._require_network(handle)
        if type(manifest) is not ArtifactReference:
            raise ControllerError("provisioning requires a host-approved content digest")
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"allocated"})
            try:
                profile = self._authority(transaction)
                scope = LaunchScope.from_dict(record["scope"])
                self._policy("provision", profile, scope)
                identity = self._identity(record)
                proof = self.provisioner.provision(profile, self.backend, handle, identity, scope, manifest)
                self._proof_matches(proof, AuthorityProof, provisioning_request_digest(profile, handle, identity, scope, manifest))
                transaction.transition(handle.name, handle.generation, handle.epoch, state="ready")
                return proof
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("sandbox provisioning is fenced and incomplete") from exc

    @_serialized
    def open_provision_session(self, handle: GenerationHandle, command: GuestCommand) -> BackendSession:
        """Open only; source transfer occurs after all control locks are released."""
        self._owner()
        self._require_network(handle)
        if type(command) is not GuestCommand:
            raise ControllerError("provisioning requires a fixed trusted guest command")
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"allocated"})
            try:
                self._policy("provision", self._authority(transaction), LaunchScope.from_dict(record["scope"]))
                return self._invoke(transaction, "provision", record,
                    lambda: self.backend.open_session(self._identity(record), command, operation="provision",
                        max_input_bytes=44 * 1024 * 1024), command=command)
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("provisioning session was fenced") from exc

    @_serialized
    def install_credentials(self, handle: GenerationHandle, broker, lease):
        self._owner()
        self._require_network(handle)
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"allocated"})
            profile = self._authority(transaction)
            scope = LaunchScope.from_dict(record["scope"])
            self._policy("credential-set", profile, scope)
            identity = self._identity(record)
            def install():
                request = OperationRequest(operation="credential-set", profile_digest=profile.digest,
                    namespace=profile.namespace, controller_pid=self._pid, identity=identity)
                with self.operation_permit(profile, request) as permit:
                    return broker.install(profile, handle, identity, scope, lease=lease, permit=permit)
            try:
                return self._invoke(transaction, "credential-set", record, install)
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("scoped model credential installation was fenced") from exc

    @_serialized
    def remove_credentials(self, handle: GenerationHandle, broker, lease):
        self._owner(cleanup=True)
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle)
            identity = self._identity(record)
            def remove():
                request = OperationRequest(operation="credential-remove", profile_digest=self.profile.digest,
                    namespace=self.profile.namespace, controller_pid=self._pid, identity=identity)
                with self.operation_permit(self.profile, request) as permit:
                    return broker.remove(self.profile, handle, identity, lease, permit=permit)
            try:
                return self._invoke(transaction, "credential-remove", record, remove)
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("scoped model credential cleanup is unconfirmed") from exc

    @_serialized
    def complete_provision(self, handle: GenerationHandle, manifest: ArtifactReference, proof: AuthorityProof) -> None:
        self._owner()
        self._require_network(handle)
        if type(manifest) is not ArtifactReference:
            raise ControllerError("approved provisioning digest is required")
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"allocated"})
            try:
                profile = self._authority(transaction)
                scope = LaunchScope.from_dict(record["scope"])
                self._policy("provision", profile, scope)
                self._proof_matches(proof, AuthorityProof, provisioning_request_digest(profile, handle, self._identity(record), scope, manifest))
                transaction.transition(handle.name, handle.generation, handle.epoch, state="ready")
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("provisioning completion is fenced") from exc

    @_serialized
    def activate(self, handle: GenerationHandle) -> None:
        self._owner()
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"ready"})
            try:
                self._policy("activate", self._authority(transaction), LaunchScope.from_dict(record["scope"]))
                if handle.name not in self._launches:
                    raise ControllerError("a previous controller's work cannot be resumed")
                transaction.transition(handle.name, handle.generation, handle.epoch, state="running")
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("sandbox activation was fenced") from exc

    @_serialized
    def open_session(self, handle: GenerationHandle) -> BackendSession:
        self._owner()
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"running"})
            try:
                self._policy("open-session", self._authority(transaction), LaunchScope.from_dict(record["scope"]))
                command = self._launches[handle.name].command
                return self._invoke(transaction, "open-session", record, lambda: self.backend.open_session(self._identity(record), command), command=command)
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("sandbox session was fenced") from exc

    @_serialized
    def begin_collection(self, handle: GenerationHandle) -> None:
        self._owner()
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"running"})
            try:
                self._policy("collect", self._authority(transaction), LaunchScope.from_dict(record["scope"]))
                transaction.transition(handle.name, handle.generation, handle.epoch, state="collecting")
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("sandbox collection was fenced") from exc

    @_serialized
    def open_collection_session(self, handle: GenerationHandle, command: GuestCommand) -> BackendSession:
        self._owner()
        if type(command) is not GuestCommand:
            raise ControllerError("collection requires a fixed trusted guest command")
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle, states={"collecting"})
            try:
                self._policy("collect", self._authority(transaction), LaunchScope.from_dict(record["scope"]))
                return self._invoke(transaction, "collect", record,
                    lambda: self.backend.open_session(self._identity(record), command, operation="collect",
                        max_output_bytes=44 * 1024 * 1024), command=command)
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("collection session was fenced") from exc

    def collect_output(self, handle: GenerationHandle, request: ArtifactReference) -> ArtifactReference:
        # No arbitrary guest path, tar extraction, host Git, or implicit import.
        # An opaque digest alone cannot select guest files. Concrete collection
        # uses open_collection_session plus the job runner's closed manifest
        # decoder/quarantine pipeline, under the same enrolled controller.
        raise ControllerError("opaque collection is not integrated; use the bounded job runner")

    def _mark_absent(self, transaction: RegistryTransaction, record: dict[str, Any]) -> None:
        args = (record["name"], record["generation"], record["epoch"])
        observed = {"sandboxId": record["sandboxId"], "createdAt": record["createdAt"], "state": "absent"}
        transaction.transition(*args, state="stopping")
        transaction.transition(*args, state="stopped", observation=observed)
        transaction.transition(*args, state="removing")
        transaction.transition(*args, state="removed", observation=observed)

    @_serialized
    def cancel(self, handle: GenerationHandle) -> CleanupProof:
        """Fence first. Expired enrollment or a denied work policy cannot block it."""
        self._owner(cleanup=True)
        with self.registry.locked() as transaction:
            record = self._record(transaction, handle)
            if record["state"] == "removed":
                raise ControllerError("generation is already removed")
            try:
                record = transaction.fence(handle.name, handle.generation, handle.epoch)
                if self.watchdog.fence(handle) is not True:
                    raise ControllerError("publication watchdog did not fence the generation")
                quiescence = self.reconciler.quiesce(self.profile, record)
                self._proof_matches(quiescence, AuthorityProof, quiescence_request_digest(self.profile, record))
                removal: ArtifactReference | None = None
                if record["sandboxId"] is not None:
                    record = transaction.transition(handle.name, handle.generation, handle.epoch, state="stopping")
                    observed = self._invoke(transaction, "stop", record, lambda: self.backend.stop(self._identity(record)))
                    if type(observed) is not BackendObservation or observed.identity != self._identity(record) or observed.state != "stopped":
                        raise ControllerError("exact object is not confirmed stopped")
                    observation = {"sandboxId": record["sandboxId"], "createdAt": record["createdAt"], "state": "stopped"}
                    record = transaction.transition(handle.name, handle.generation, handle.epoch, state="stopped", observation=observation)
                    record = transaction.transition(handle.name, handle.generation, handle.epoch, state="removing")
                    removal = self._invoke(transaction, "destroy", record, lambda: self.backend.destroy(self._identity(record)))
                    if type(removal) is not ArtifactReference:
                        raise ControllerError("removal did not return a bounded observation reference")
                proof = self.reconciler.confirm_absence(self.profile, record, removal)
                self._proof_matches(proof, CleanupProof, cleanup_request_digest(self.profile, record, removal))
                if proof.native_clients_reaped is not True or proof.late_commands_quiescent is not True or proof.storage_cleanup_verified is not True or proof.name_and_id_absent is not True:
                    raise ControllerError("native clients, exact object, and storage absence are not confirmed")
                # Keep the record nonterminal until every required cleanup
                # authority has acknowledged. A failed disarm must remain in
                # the next controller's reconciliation set.
                if self.watchdog.disarm(handle, proof) is not True:
                    raise ControllerError("independent watchdog could not disarm the removed generation")
                if record["sandboxId"] is None:
                    self._mark_absent(transaction, record)
                else:
                    transaction.transition(handle.name, handle.generation, handle.epoch, state="removed", observation={"sandboxId": record["sandboxId"], "createdAt": record["createdAt"], "state": "absent"})
                return proof
            except Exception as exc:
                self._failed_generation(transaction, handle)
                raise ControllerError("cleanup remains fenced and unconfirmed") from exc
