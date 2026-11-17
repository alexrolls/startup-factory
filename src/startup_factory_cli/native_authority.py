"""Normal-operation authority for a qualified persistent custody deployment.

Only clean, acknowledged history can use the enrolled synchronous-command and
cleanup semantics. No crash/ambiguous delivery is upgraded by this module into
a queue barrier. Unfinished startup records require manual reconciliation and a
new root-reviewed enrollment; there is no automatic adoption or journal reset.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import secrets
import time
import threading
from typing import Any

from .docker_backend import DockerBackend, OperationPermit, OperationRequest
from .execution_backend import ArtifactReference, DockerProfile, canonical_digest, load_profile
from .native_custody import JournalCustody
from .sandbox_controller import (AuthorityProof, CleanupProof, GenerationHandle, NativeOperationLease,
    ReconciliationProof, cleanup_request_digest, native_lease_request_digest,
    quiescence_request_digest, reconciliation_request_digest)
from .sandbox_deployment import Deployment, read_root_protected, verify_deployment
from .sandbox_qualification_evidence import MAX_EVIDENCE_BYTES, verify_deployment_enrollment, verify_live_evidence
from .sandbox_registry import SandboxRegistry
from .sandbox_watchdog import IndependentWatchdogClient


class NativeAuthorityError(RuntimeError):
    pass


class NativeRuntimeAuthority:
    def __init__(self, deployment: Deployment, registry: SandboxRegistry, custody: JournalCustody,
                 watchdog: IndependentWatchdogClient) -> None:
        if type(deployment) is not Deployment or type(registry) is not SandboxRegistry or type(custody) is not JournalCustody or type(watchdog) is not IndependentWatchdogClient:
            raise NativeAuthorityError("qualified deployment and independent authority objects are required")
        self.deployment, self.registry, self.custody, self.watchdog = deployment, registry, custody, watchdog
        self.profile = load_profile(Path(deployment.profile_path))
        # Must happen before the controller takes its namespace transaction.
        self.enrollment = verify_deployment_enrollment(deployment, self.profile, Path(deployment.receipt_path), registry)
        self._pid = os.getpid()
        self._backend: DockerBackend | None = None
        self._reconciliation: str | None = None
        self._operation = threading.local()
        custody.bind_reconciler(self)

    def _verify(self, profile: DockerProfile, *, cleanup: bool = False) -> None:
        if os.getpid() != self._pid or profile != self.profile:
            raise NativeAuthorityError("native authority is inherited or targets another profile")
        verify_deployment(self.deployment, profile)
        raw, digest = read_root_protected(Path(self.deployment.receipt_path), maximum=64 * 1024)
        if raw is None or "sha256:" + digest != profile.qualification_digest:
            raise NativeAuthorityError("protected enrollment changed")
        now = int(time.time())
        if not cleanup and not self.enrollment.issued_at <= now < self.enrollment.expires_at:
            raise NativeAuthorityError("native enrollment expired")
        if not cleanup:
            for gate, digest in self.enrollment.checks:
                raw, observed = read_root_protected(Path(self.deployment.evidence_root) / (digest[7:] + ".json"), maximum=MAX_EVIDENCE_BYTES)
                if raw is None or "sha256:" + observed != digest:
                    raise NativeAuthorityError("qualified live evidence changed")
                verify_live_evidence(raw, gate, self.deployment, profile, self.enrollment.as_dict()["registry"], now=now)
        space = os.statvfs(self.deployment.storage["mountPoint"])
        if not cleanup and space.f_bavail * space.f_frsize < self.deployment.storage["minimumFreeBytes"]:
            raise NativeAuthorityError("qualified host storage headroom is unavailable")

    def validate_backend(self, backend: Any, profile: DockerProfile) -> bool:
        self._verify(profile)
        if type(backend) is not DockerBackend or not self.custody.is_bound_to(backend, profile):
            return False
        if self._backend is not None and self._backend is not backend:
            return False
        self._backend = backend
        return self.watchdog.validate_backend(backend, profile)

    def _inventory(self, profile: DockerProfile, digest: str, epoch: int, *, name: str | None = None,
                   generation: str | None = None) -> list[dict]:
        if self._backend is None:
            raise NativeAuthorityError("native backend is unbound")
        permit = OperationPermit(digest, name, generation or "gen-" + secrets.token_hex(16), epoch,
                                 self._reconciliation or digest)
        previous = getattr(self._operation, "inventory_digest", None)
        self._operation.inventory_digest = digest
        try:
            return self._backend._rows(profile, permit)
        finally:
            self._operation.inventory_digest = previous

    def reconcile(self, profile: DockerProfile, registry_id: str, epoch: int, records: tuple[dict, ...]) -> ReconciliationProof:
        self._verify(profile)
        digest = reconciliation_request_digest(profile, registry_id, epoch, records)
        if (registry_id != self.enrollment.registry_id or any(record["state"] != "removed" for record in records)
            or self.custody.pool_blocked or self.custody.diagnostics()["activeClients"]):
            raise NativeAuthorityError("unfinished registry/native history requires manual requalification")
        if self._inventory(profile, digest, epoch):
            raise NativeAuthorityError("dedicated namespace is not positively empty")
        if self.custody.pool_blocked:
            raise NativeAuthorityError("native history changed during reconciliation")
        # True only under the root-enrolled normal acknowledgment, exclusive
        # endpoint, storage and cleanup semantics, with no unfinished command.
        evidence = canonical_digest({"request": digest, "deployment": self.deployment.digest,
            "qualification": profile.qualification_digest, "acknowledgedHistory": list(self.custody.journal.records()),
            "positiveEmptyInventory": True})
        self._reconciliation = evidence
        return ReconciliationProof(digest, evidence, tuple(record["name"] for record in records), True, True, True, True)

    @contextlib.contextmanager
    def lease(self, profile: DockerProfile, request: OperationRequest, record: dict, epoch: int):
        cleanup = request.operation in {"stop", "destroy", "credential-remove"}
        self._verify(profile, cleanup=cleanup)
        if self._reconciliation is None or not cleanup and self.custody.pool_blocked:
            raise NativeAuthorityError("native pool is unreconciled or delivery is uncertain")
        handle = GenerationHandle(record["name"], record["generation"], epoch)
        self.watchdog.binding(handle)  # independent service liveness; no namespace lock there
        if not cleanup and self.watchdog.operation_live(handle) is not True:
            raise NativeAuthorityError("watchdog revoked or expired this workload")
        previous = getattr(self._operation, "binding", None)
        self._operation.binding = (request.digest, handle, cleanup, request.operation)
        try:
            yield NativeOperationLease(native_lease_request_digest(request, record, epoch), self._reconciliation, True, True)
        finally:
            self._operation.binding = previous

    def authorize_native(self, profile: DockerProfile, permit: OperationPermit, intent: Any) -> bool:
        binding = getattr(self._operation, "binding", None)
        if profile != self.profile:
            return False
        if intent.operation == "list" and permit.request_digest == getattr(self._operation, "inventory_digest", None):
            return True
        if binding is None:
            return False
        request_digest, handle, cleanup, operation = binding
        if (permit.request_digest != request_digest or (intent.name, intent.generation, intent.epoch)
            != (handle.name, handle.generation, handle.epoch)):
            return False
        allowed = {"create": {"create", "inspect", "list"}, "inspect": {"inspect"},
            "open-session": {"inspect", "open-session"}, "provision": {"inspect", "provision"},
            "collect": {"inspect", "collect"}, "stop": {"inspect", "stop"}, "destroy": {"inspect", "destroy", "list"},
            "credential-set": {"credential-set"}, "credential-remove": {"credential-remove"},
            "policy-activate": {"inspect", "policy-inspect", "policy-allow", "policy-remove-lock"}}
        if intent.operation not in allowed.get(operation, set()):
            return False
        return cleanup or self.watchdog.operation_live(handle) is True

    def quiesce(self, profile: DockerProfile, record: dict) -> AuthorityProof:
        self._verify(profile, cleanup=True)
        self.custody.cancel_generation(record["name"], record["generation"], record["epoch"])
        # Cancellation may leave delivery uncertainty. This proof is only a
        # bounded owned-client observation; confirm_absence refuses that case.
        digest = quiescence_request_digest(profile, record)
        return AuthorityProof(digest, canonical_digest({"request": digest, "native": self.custody.diagnostics()}))

    def confirm_absence(self, profile: DockerProfile, record: dict,
                        removal: ArtifactReference | None) -> CleanupProof:
        self._verify(profile)
        digest = cleanup_request_digest(profile, record, removal)
        if self.custody.pool_blocked or self.custody.diagnostics()["activeClients"]:
            raise NativeAuthorityError("native delivery uncertainty is not a server queue barrier")
        rows = self._inventory(profile, digest, record["epoch"], name=record["name"], generation=record["generation"])
        if self.custody.pool_blocked:
            raise NativeAuthorityError("native history changed during cleanup verification")
        if any(row["name"] == record["name"] or row["id"] == record["sandboxId"] for row in rows):
            raise NativeAuthorityError("exact sandbox name or ID remains present")
        if record["sandboxId"] is not None:
            if type(removal) is not ArtifactReference or self._backend is None:
                raise NativeAuthorityError("identity-bound native removal observation is required")
            import json
            observation = json.loads(self._backend.read_receipt(removal))
            if (observation["identity"] != {"name": record["name"], "sandboxId": record["sandboxId"], "createdAt": record["createdAt"]}
                or observation["generation"] != record["generation"] or observation["epoch"] != record["epoch"]
                or observation["nameAndIdAbsent"] is not True):
                raise NativeAuthorityError("removal observation targets another generation")
        evidence = canonical_digest({"request": digest, "deployment": self.deployment.digest,
            "qualification": profile.qualification_digest, "positiveAbsence": True,
            "nativeAcknowledgments": list(self.custody.journal.records()), "removal": None if removal is None else removal.digest})
        return CleanupProof(digest, evidence, True, True, True, True)
