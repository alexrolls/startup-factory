"""Protected completion gates for verdicts admitted before a review VM exits.

Admission is only a durable message receipt. A Docker review approval may leave
the host broker only after the same capability's fresh VM completed normally,
the host verified unchanged tracked source, and exact-generation cleanup ended.
These receipts grant no marker/status/hold authority; existing broker checks do.
"""
from __future__ import annotations
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from startup_factory_cli.execution_backend import LaunchScope, load_profile
from startup_factory_cli.sandbox_deployment import canonical_bytes, decode_object, load_deployment
from startup_factory_cli.sandbox_qualification_evidence import verify_deployment_enrollment
from startup_factory_cli.sandbox_registry import SandboxRegistry
from startup_factory_cli.sandbox_enrollment import profile_basis_digest
from execution_descriptor import validate_sandbox_binding
from host_git import HostGit, open_directory, read_regular
from sandbox_acceptance import project_id

CAPABILITY = re.compile(r"cap-[0-9a-f]{32}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
JOB = re.compile(r"job-[0-9a-f]{32}\Z")
BOUND_FIELDS = {"schemaVersion", "kind", "registryId", "deploymentDigest", "profileBasisDigest", "jobId", "requestDigest", "capabilityId", "scope", "sandbox", "reviewBinding"}
DONE_FIELDS = {"schemaVersion", "kind", "boundDigest", "status", "readonlyVerified", "evidenceDigest"}
MAX_FILES = 4096
MAX_BYTES = 64 * 1024


class CompletionError(RuntimeError):
    pass


class CompletionPending(CompletionError):
    pass


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _record(directory, name):
    try:
        return read_regular(directory, name, MAX_BYTES, private=True)
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise CompletionError("protected gate record is unsafe or changed") from exc


def _review(value):
    if value is None:
        return None
    if type(value) is not dict or not {"requestDigest", "head", "package"} <= set(value) or set(value) - {"requestDigest", "head", "package", "base", "reviewGates"}:
        raise CompletionError("invalid protected review binding")
    if any(type(value[key]) is not str or not DIGEST.fullmatch(value[key]) for key in ("requestDigest", "package")) or not isinstance(value["head"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["head"]):
        raise CompletionError("invalid protected review digest/head")
    if "base" in value and (not isinstance(value["base"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["base"])):
        raise CompletionError("invalid protected review base")
    if "reviewGates" in value and (type(value["reviewGates"]) is not list or len(value["reviewGates"]) > 32 or any(type(gate) is not str or not re.fullmatch(r"[a-z0-9-]{1,80}", gate) for gate in value["reviewGates"])):
        raise CompletionError("invalid protected review gates")
    return json.loads(canonical_bytes(value))


def _bound(value):
    if type(value) is not dict or set(value) != BOUND_FIELDS or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or value["kind"] != "sandbox-gate-binding":
        raise CompletionError("unsupported protected gate binding")
    if type(value["capabilityId"]) is not str or not CAPABILITY.fullmatch(value["capabilityId"]) or type(value["jobId"]) is not str or not JOB.fullmatch(value["jobId"]) or type(value["requestDigest"]) is not str or not DIGEST.fullmatch(value["requestDigest"]) or not isinstance(value["registryId"], str) or not re.fullmatch(r"reg-[0-9a-f]{32}", value["registryId"]):
        raise CompletionError("invalid protected gate identity")
    if any(type(value[key]) is not str or not DIGEST.fullmatch(value[key]) for key in ("deploymentDigest", "profileBasisDigest")):
        raise CompletionError("gate binding requires protected stable deployment/profile anchors")
    scope = LaunchScope.from_dict(value["scope"])
    binding = validate_sandbox_binding(value["sandbox"])
    if scope.task_id == "-" or scope.attempt < 1 or binding["state"] != "ready" or any(binding[key] is not None for key in ("acceptedCommit", "acceptedTree", "acceptedExportDigest")):
        raise CompletionError("gate binding requires an exact ready task assignment")
    review = _review(value["reviewBinding"])
    if review is not None and review["head"] != binding["baseCommit"]:
        raise CompletionError("review VM source differs from its approved review head")
    return json.loads(canonical_bytes(value))


def _done(value):
    if type(value) is not dict or set(value) != DONE_FIELDS or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or value["kind"] != "sandbox-gate-completion" or value["status"] not in {"succeeded", "failed"} or type(value["readonlyVerified"]) is not bool or any(type(value[key]) is not str or not DIGEST.fullmatch(value[key]) for key in ("boundDigest", "evidenceDigest")):
        raise CompletionError("unsupported protected gate completion")
    if value["status"] == "succeeded" and value["readonlyVerified"] is not True:
        raise CompletionError("successful gate lacks a read-only verification")
    return value


class GateCompletionStore:
    def __init__(self, registry: SandboxRegistry, *, authorize: Callable[[], bool] | None = None,
                 deployment_digest: str | None = None, profile_basis_digest: str | None = None):
        self.registry, self.authorize = registry, authorize
        self.deployment_digest, self.profile_basis_digest = deployment_digest, profile_basis_digest

    def _transaction(self, transaction):
        if transaction is not None and getattr(transaction, "_registry", None) is not self.registry:
            raise CompletionError("gate transaction belongs to another registry")
        return self.registry.locked() if transaction is None else contextlib.nullcontext(transaction)

    def _directory(self, *, create):
        if create:
            try:
                os.mkdir("gate-completions", 0o700, dir_fd=self.registry._root_fd)
                os.fsync(self.registry._root_fd)
            except FileExistsError:
                pass
        fd = os.open("gate-completions", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.registry._root_fd)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise CompletionError("unsafe protected gate directory")
        return fd

    @staticmethod
    def _name(capability_id, suffix):
        if type(capability_id) is not str or not CAPABILITY.fullmatch(capability_id):
            raise CompletionError("invalid gate capability locator")
        return capability_id + suffix + ".json"

    def _write(self, directory, name, raw, *, before_publish=None):
        if len(raw) > MAX_BYTES:
            raise CompletionError("protected gate record exceeds its bound")
        try:
            existing = _record(directory, name)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != raw:
                raise CompletionError("immutable gate record cannot be rebound")
            return
        if len(os.listdir(directory)) >= MAX_FILES:
            raise CompletionError("permanent gate completion quota exhausted")
        pending = "." + name + ".pending"
        try:
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        except FileExistsError:
            if _record(directory, pending) != raw:
                raise CompletionError("interrupted gate record requires reconciliation")
        else:
            try:
                view = memoryview(raw)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise CompletionError("gate record write made no progress")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
        if before_publish is not None and before_publish() is not True:
            raise CompletionError("gate authority changed before durable publication")
        os.link(pending, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(pending, dir_fd=directory)
        os.fsync(directory)

    @staticmethod
    def _row(transaction, bound):
        binding = bound["sandbox"]
        rows = [row for row in transaction.records() if row["generation"] == binding["generation"]]
        if len(rows) != 1:
            raise CompletionError("gate generation is absent")
        row = rows[0]
        expected = {"name": binding["name"], "epoch": binding["epoch"], "sandboxId": binding["sandboxId"],
            "createdAt": binding["createdAt"], "scope": bound["scope"]}
        if transaction.registry_id != bound["registryId"] or binding["namespace"] != transaction._registry.namespace or any(row[key] != value for key, value in expected.items()):
            raise CompletionError("gate generation differs from protected ownership")
        return row

    def bind(self, *, capability_id, job_id, request_digest, scope, binding, review_binding=None, transaction=None):
        with self._transaction(transaction) as transaction:
            value = _bound({"schemaVersion": 1, "kind": "sandbox-gate-binding", "registryId": transaction.registry_id,
                "deploymentDigest": self.deployment_digest, "profileBasisDigest": self.profile_basis_digest,
                "jobId": job_id, "requestDigest": request_digest, "capabilityId": capability_id,
                "scope": scope.as_dict(), "sandbox": binding, "reviewBinding": _review(review_binding)})
            if self._row(transaction, value)["state"] != "ready" or self.authorize is None or self.authorize() is not True:
                raise CompletionError("fresh gate binding is not currently authorized")
            directory = self._directory(create=True)
            try:
                self._write(directory, self._name(capability_id, ".bound"), canonical_bytes(value), before_publish=self.authorize)
            finally:
                os.close(directory)
        return json.loads(canonical_bytes(value))

    def finish(self, capability_id, job_id, request_digest, *, success, readonly_verified, evidence_digest, transaction=None):
        if type(success) is not bool or type(readonly_verified) is not bool:
            raise CompletionError("gate completion requires trusted boolean outcomes")
        with self._transaction(transaction) as transaction:
            directory = self._directory(create=False)
            try:
                raw = _record(directory, self._name(capability_id, ".bound"))
                bound = _bound(decode_object(raw, maximum=MAX_BYTES))
                if bound["jobId"] != job_id or bound["requestDigest"] != request_digest:
                    raise CompletionError("completion belongs to another gate request")
                if bound["deploymentDigest"] != self.deployment_digest or bound["profileBasisDigest"] != self.profile_basis_digest:
                    raise CompletionError("completion deployment/profile authority changed")
                row = self._row(transaction, bound)
                if success and (row["state"] != "removed" or self.authorize is None or self.authorize() is not True):
                    raise CompletionError("successful gate cleanup/current authority is unconfirmed")
                value = _done({"schemaVersion": 1, "kind": "sandbox-gate-completion", "boundDigest": _digest(raw),
                    "status": "succeeded" if success else "failed", "readonlyVerified": readonly_verified,
                    "evidenceDigest": evidence_digest})
                self._write(directory, self._name(capability_id, ".completed"), canonical_bytes(value), before_publish=self.authorize if success else None)
            finally:
                os.close(directory)
        return json.loads(canonical_bytes(value))

    def verify(self, capability_id):
        with self.registry.locked() as transaction:
            try:
                directory = self._directory(create=False)
            except FileNotFoundError as exc:
                raise CompletionPending("gate has no protected start/completion") from exc
            try:
                try:
                    raw = _record(directory, self._name(capability_id, ".bound"))
                    bound = _bound(decode_object(raw, maximum=MAX_BYTES))
                    done = _done(decode_object(_record(directory, self._name(capability_id, ".completed")), maximum=MAX_BYTES))
                except FileNotFoundError as exc:
                    raise CompletionPending("gate completion is pending") from exc
            finally:
                os.close(directory)
            row = self._row(transaction, bound)
            if bound["capabilityId"] != capability_id or bound["deploymentDigest"] != self.deployment_digest or bound["profileBasisDigest"] != self.profile_basis_digest:
                raise CompletionError("completion authority/locator differs from the protected binding")
            if done["boundDigest"] != _digest(raw) or done["status"] != "succeeded" or done["readonlyVerified"] is not True or row["state"] != "removed":
                raise CompletionError("gate did not complete read-only work and cleanup")
        return {"binding": bound, "completion": done}


def verify_gate_completion(deployment_path: Path, repository: Path, workspace: Path,
                           team: str, feature: str, task: str, entry: dict, *, require_review_binding: bool = True) -> dict:
    if type(require_review_binding) is not bool:
        raise CompletionError("review binding policy must be host assigned")
    capability = entry.get("producerCapability")
    if type(capability) is not dict:
        raise CompletionError("Docker code approval requires its native producer capability")
    capability_id = capability.get("id")
    GateCompletionStore._name(capability_id, ".bound")
    deployment = load_deployment(deployment_path)
    profile = load_profile(Path(deployment.profile_path))
    project = project_id(repository)
    projects = [p for p in deployment.projects if p["projectId"] == project and p["repository"] == str(repository)]
    if len(projects) != 1 or Path(projects[0]["workspaceRoot"]) / team != workspace:
        raise CompletionError("gate does not belong to the enrolled project/workspace")
    with SandboxRegistry(Path(deployment.registry_root), profile.namespace) as registry:
        verify_deployment_enrollment(deployment, profile, Path(deployment.receipt_path), registry)
        receipt = GateCompletionStore(registry, deployment_digest=deployment.digest,
            profile_basis_digest=profile_basis_digest(profile)).verify(capability_id)
    bound, binding = receipt["binding"], receipt["binding"]["sandbox"]
    scope = LaunchScope.from_dict(bound["scope"])
    expected = {"projectId": project, "team": team, "featureId": feature, "taskId": task,
        "role": entry.get("actor"), "attempt": entry.get("attempt")}
    if scope.as_dict() != expected or entry.get("team") != team or entry.get("featureId") != feature or entry.get("taskId") != task or bound["capabilityId"] != capability_id:
        raise CompletionError("producer differs from its completed gate assignment")
    if any(binding[key] != getattr(profile, attribute) for key, attribute in (("namespace", "namespace"), ("policyDigest", "policy_digest"), ("image", "image"))):
        raise CompletionError("completed gate differs from the enrolled runtime")
    review = bound["reviewBinding"]
    if require_review_binding and review is None:
        raise CompletionError("code approval has no protected review request")
    # Paths are derived from native broker identity; guest-selected paths are
    # assertions only. The final broker independently re-verifies the signature.
    delivery = entry.get("deliveryId")
    if delivery is None:
        identifier = entry.get("id")
        if type(identifier) is not str or not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", identifier):
            raise CompletionError("invalid producer body identity")
        parent, leaf = workspace / "outbox/bodies", identifier + ".md"
        if entry.get("bodyPath") != str(parent / leaf):
            raise CompletionError("producer body path differs from its assigned identity")
    else:
        if type(delivery) is not str or not re.fullmatch(r"delivery-[0-9a-f]{32}", delivery):
            raise CompletionError("invalid broker delivery identity")
        git = HostGit(repository)
        scope_digest = hashlib.sha256(canonical_bytes({"repository": str(repository), "workspace": str(workspace), "team": team, "featureId": feature})).hexdigest()
        parent = git.git_dir / "startup-factory-broker/outbox-deliveries" / scope_digest
        leaf = delivery + ".source.md"
        if entry.get("stagedBodyPath") != str(parent / leaf):
            raise CompletionError("staged body path differs from its broker identity")
    directory = open_directory(parent)
    try:
        raw = read_regular(directory, leaf, 65536, private=False)
    finally:
        os.close(directory)
    if capability.get("bodySha256") != _digest(raw):
        raise CompletionError("completed gate body differs from its native signature")
    if not raw.startswith(("[" + str(entry.get("marker")) + "]").encode()):
        raise CompletionError("completed gate body differs from its marker")
    if not require_review_binding:
        return receipt
    from review_evidence import fields
    values = fields(raw.decode("utf-8", errors="strict"), ("Review-Request-SHA256", "Task-Branch-Head", "Review-Package-SHA256"))
    expected_fields = {"Review-Request-SHA256": review["requestDigest"], "Task-Branch-Head": review["head"], "Review-Package-SHA256": review["package"]}
    if values != expected_fields:
        raise CompletionError("approval differs from the completed review request/head/package")
    return receipt
