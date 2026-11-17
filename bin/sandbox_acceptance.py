"""Protected receipts for structural import to a task ref, never review approval.

The immutable receipt lives outside the repository. Execution JSON merely points
to it by a bounded generation identifier. No guest-supplied path is opened.
"""
from __future__ import annotations

import hashlib
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from startup_factory_cli.execution_backend import LaunchScope, load_profile
from startup_factory_cli.sandbox_deployment import (
    canonical_bytes, decode_object, load_deployment,
)
from startup_factory_cli.sandbox_qualification_evidence import verify_deployment_enrollment
from startup_factory_cli.sandbox_enrollment import profile_basis_digest
from startup_factory_cli.sandbox_registry import SandboxRegistry
from execution_descriptor import require_accepted_sandbox, validate_sandbox_binding


MAX_RECEIPT_BYTES = 64 * 1024
MAX_RECEIPTS = 1024
RECEIPT_FIELDS = {"schemaVersion", "kind", "scope", "sandbox", "promotion", "evidenceDigest"}
RENEWABLE_FIELDS = RECEIPT_FIELDS | {"deploymentDigest", "profileBasisDigest"}
PROMOTION_FIELDS = {"schemaVersion", "kind", "exportId", "assignmentDigest", "manifestDigest",
                    "baseCommit", "tree", "commit", "targetRef", "previousHead"}


class AcceptanceError(RuntimeError):
    pass


class ImportPending(AcceptanceError):
    """An admitted immutable intent must wait for its host source import."""


def project_id(repository: Path) -> str:
    return "sha256:" + hashlib.sha256(str(repository.resolve(strict=True)).encode()).hexdigest()


def task_key(task: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", task).strip("-").lower()[:32] or "task"
    return slug + "-" + hashlib.sha256(task.encode()).hexdigest()[:10]


def _file(fd: int, name: str) -> bytes:
    try:
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise AcceptanceError("protected import receipt is unavailable or unsafe") from exc
    try:
        before = os.fstat(handle)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= MAX_RECEIPT_BYTES:
            raise AcceptanceError("unsafe protected import receipt")
        result = bytearray()
        while len(result) <= MAX_RECEIPT_BYTES:
            chunk = os.read(handle, min(65536, MAX_RECEIPT_BYTES + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(result) != before.st_size or stamp(before) != stamp(os.fstat(handle)) or stamp(before) != stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)):
            raise AcceptanceError("protected import receipt changed during observation")
        return bytes(result)
    except OSError as exc:
        raise AcceptanceError("protected import receipt observation failed") from exc
    finally:
        os.close(handle)


def _validate(value: dict) -> dict:
    if type(value) is not dict or type(value.get("schemaVersion")) is not int or value["schemaVersion"] not in {1, 2} or set(value) != (RECEIPT_FIELDS if value["schemaVersion"] == 1 else RENEWABLE_FIELDS) or value["kind"] != "sandbox-task-import":
        raise AcceptanceError("unsupported protected import receipt")
    if value["schemaVersion"] == 2 and any(type(value[key]) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) for key in ("deploymentDigest", "profileBasisDigest")):
        raise AcceptanceError("invalid stable protected enrollment anchors")
    binding = validate_sandbox_binding(value["sandbox"])
    require_accepted_sandbox({"schemaVersion": 2, "sandbox": binding,
                             "claimLineage": {}, "lineageDigest": "sha256:" + "0" * 64})
    scope = LaunchScope.from_dict(value["scope"])
    if scope.task_id == "-" or scope.attempt < 1:
        raise AcceptanceError("task import requires a concrete task attempt")
    promotion = value["promotion"]
    if type(promotion) is not dict or set(promotion) != PROMOTION_FIELDS or type(promotion["schemaVersion"]) is not int or promotion["schemaVersion"] != 1 or promotion["kind"] != "sandbox-promotion":
        raise AcceptanceError("import receipt lacks a host promotion")
    if promotion["targetRef"] != f"refs/heads/agent-task/{scope.team}/{task_key(scope.task_id)}":
        raise AcceptanceError("promotion does not name the assigned task ref")
    expected = {"baseCommit": binding["baseCommit"], "previousHead": binding["baseCommit"],
                "commit": binding["acceptedCommit"], "tree": binding["acceptedTree"],
                "manifestDigest": binding["acceptedExportDigest"]}
    if any(promotion[name] != expected[name] for name in expected):
        raise AcceptanceError("host import and sandbox generation bindings differ")
    for key in ("assignmentDigest",):
        if not isinstance(promotion[key], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", promotion[key]):
            raise AcceptanceError("invalid protected assignment digest")
    if not isinstance(promotion["exportId"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", promotion["exportId"]):
        raise AcceptanceError("invalid protected export identity")
    if not isinstance(value["evidenceDigest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["evidenceDigest"]):
        raise AcceptanceError("invalid import evidence digest")
    return value


class AcceptanceStore:
    def __init__(self, registry: SandboxRegistry, *, authorize: Callable[[], bool] | None = None,
                 deployment_digest: str | None = None, profile_basis_digest: str | None = None):
        self.registry = registry
        self.authorize = authorize
        if (deployment_digest is None) != (profile_basis_digest is None):
            raise AcceptanceError("both stable enrollment anchors are required")
        self.anchors = {} if deployment_digest is None else {"deploymentDigest": deployment_digest, "profileBasisDigest": profile_basis_digest}

    def _directory(self, *, create: bool) -> int:
        if create:
            try:
                os.mkdir("acceptances", 0o700, dir_fd=self.registry._root_fd)
                os.fsync(self.registry._root_fd)
            except FileExistsError:
                pass
        try:
            fd = os.open("acceptances", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.registry._root_fd)
        except OSError as exc:
            raise AcceptanceError("protected import receipt directory is unavailable") from exc
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise AcceptanceError("unsafe protected import receipt directory")
        return fd

    def record(self, scope: LaunchScope, binding: dict, promotion: dict, *, evidence_digest: str, transaction=None) -> dict:
        """Hold registry→task authority, then reauthorize durable acceptance.

        A caller holding the namespace lock passes its live transaction, avoiding
        inverse lock acquisition or a second non-reentrant registry lock.
        """
        value = _validate({"schemaVersion": 2 if self.anchors else 1, "kind": "sandbox-task-import", "scope": scope.as_dict(),
                           "sandbox": binding, "promotion": promotion, "evidenceDigest": evidence_digest, **self.anchors})
        if binding["namespace"] != self.registry.namespace:
            raise AcceptanceError("task import names another ownership namespace")
        raw = canonical_bytes(value)
        if len(raw) > MAX_RECEIPT_BYTES or self.authorize is None:
            raise AcceptanceError("current task import authority is required")
        if transaction is not None and getattr(transaction, "_registry", None) is not self.registry:
            raise AcceptanceError("acceptance transaction belongs to another registry")
        with self.registry.locked() if transaction is None else contextlib.nullcontext(transaction) as transaction:
            if self.authorize() is not True:
                raise AcceptanceError("current task import authority is required")
            rows = [r for r in transaction.records() if r["generation"] == binding["generation"]]
            if len(rows) != 1:
                raise AcceptanceError("import generation is absent from protected ownership history")
            row = rows[0]
            expected = {"name": binding["name"], "generation": binding["generation"], "epoch": binding["epoch"],
                        "sandboxId": binding["sandboxId"], "createdAt": binding["createdAt"], "scope": scope.as_dict()}
            if any(row[key] != expected[key] for key in expected) or row["state"] not in {"work-complete", "stopped", "removed"}:
                raise AcceptanceError("import generation has not completed normal work")
            fd = self._directory(create=True)
            try:
                name = binding["generation"] + ".json"
                try:
                    existing = _file(fd, name)
                except FileNotFoundError:
                    existing = None
                if existing is not None:
                    if existing != raw:
                        raise AcceptanceError("immutable import receipt cannot be replaced")
                    return json.loads(existing)
                if len(os.listdir(fd)) >= MAX_RECEIPTS:
                    raise AcceptanceError("permanent import receipt quota exhausted")
                pending = "." + name + ".pending"
                try:
                    handle = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
                except FileExistsError:
                    if _file(fd, pending) != raw:
                        raise AcceptanceError("uncertain import receipt requires reconciliation")
                else:
                    try:
                        view = memoryview(raw)
                        while view:
                            count = os.write(handle, view)
                            if count <= 0:
                                raise AcceptanceError("import receipt write made no progress")
                            view = view[count:]
                        os.fsync(handle)
                    finally:
                        os.close(handle)
                if self.authorize() is not True:
                    raise AcceptanceError("task import authority was revoked")
                os.link(pending, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                os.unlink(pending, dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)
        return json.loads(raw)

    def verify(self, scope: LaunchScope, binding: dict, *, transaction=None) -> dict:
        binding = validate_sandbox_binding(binding)
        if binding["namespace"] != self.registry.namespace:
            raise AcceptanceError("task import names another ownership namespace")
        if transaction is not None and getattr(transaction, "_registry", None) is not self.registry:
            raise AcceptanceError("acceptance transaction belongs to another registry")
        with self.registry.locked() if transaction is None else contextlib.nullcontext(transaction) as transaction:
            rows = [r for r in transaction.records() if r["generation"] == binding["generation"]]
            if len(rows) != 1:
                raise AcceptanceError("protected import generation is absent")
            row = rows[0]
            expected = {"name": binding["name"], "epoch": binding["epoch"], "sandboxId": binding["sandboxId"],
                        "createdAt": binding["createdAt"], "scope": scope.as_dict()}
            if any(row[key] != expected[key] for key in expected) or row["state"] not in {"work-complete", "stopped", "removed"}:
                raise AcceptanceError("protected import generation identity mismatch")
            fd = self._directory(create=False)
            try:
                try:
                    value = _validate(decode_object(_file(fd, binding["generation"] + ".json"), maximum=MAX_RECEIPT_BYTES))
                except FileNotFoundError as exc:
                    raise AcceptanceError("protected import receipt is absent") from exc
            finally:
                os.close(fd)
        if value["scope"] != scope.as_dict() or value["sandbox"] != binding:
            raise AcceptanceError("execution projection differs from its protected import receipt")
        return value


def verify_execution_acceptance(deployment_path: Path, repository: Path, workspace: Path,
                                team: str, feature: str, task: str, record: dict) -> dict | None:
    binding = require_accepted_sandbox(record)
    if binding is None:
        return None
    deployment = load_deployment(deployment_path)
    profile = load_profile(Path(deployment.profile_path))
    repository = repository.resolve(strict=True)
    expected_project = project_id(repository)
    projects = [p for p in deployment.projects if p["projectId"] == expected_project and Path(p["repository"]) == repository]
    if len(projects) != 1 or Path(projects[0]["workspaceRoot"]) / team != workspace:
        raise AcceptanceError("task import does not belong to the enrolled project/workspace")
    if binding["policyDigest"] != profile.policy_digest or binding["image"] != profile.image or binding["namespace"] != profile.namespace:
        raise AcceptanceError("task import differs from the current enrolled profile")
    scope = LaunchScope(expected_project, team, feature, record["role"], task, record["attempt"])
    with SandboxRegistry(Path(deployment.registry_root), profile.namespace) as registry:
        verify_deployment_enrollment(deployment, profile, Path(deployment.receipt_path), registry)
        receipt = AcceptanceStore(registry).verify(scope, binding)
    verify_profile_provenance(receipt, deployment, profile)
    from host_git import HostGit
    git = HostGit(repository)
    git.assert_no_checkout_programs()
    if git.read_ref(receipt["promotion"]["targetRef"]) != binding["acceptedCommit"] or git.commit_tree(binding["acceptedCommit"]) != binding["acceptedTree"]:
        raise AcceptanceError("the assigned task ref no longer names the accepted sandbox bytes")
    return receipt


def verify_profile_provenance(receipt: dict, deployment, profile) -> None:
    """A historical full digest is usable only with protected stable anchors."""
    value = _validate(receipt)
    if any(value["sandbox"][key] != expected for key, expected in (
            ("policyDigest", profile.policy_digest), ("image", profile.image), ("namespace", profile.namespace))):
        raise AcceptanceError("historical import runtime/policy differs from current enrollment")
    if value["schemaVersion"] == 1:
        if value["sandbox"]["profileDigest"] != profile.digest:
            raise AcceptanceError("legacy import requires its original enrolled profile")
    elif value["deploymentDigest"] != deployment.digest or value["profileBasisDigest"] != profile_basis_digest(profile):
        raise AcceptanceError("import differs from the current stable enrollment")


def verify_configured_execution(record: dict, repository: Path, workspace: Path,
                                team: str, feature: str, task: str, runtime_root: Path,
                                *, allow_pending: bool = False) -> dict | None:
    """A Docker record cannot silently enter a legacy/native integration path."""
    from startup_factory_cli.config_values import read_config_file, value_for
    from execution_descriptor import execution_version
    config = read_config_file(runtime_root / "config/team.config.md", label="team config")
    backend = value_for(config, "AGENT_EXECUTION_BACKEND") or "protected-runner"
    version = execution_version(record)
    if backend not in {"protected-runner", "docker-sandboxes"}:
        raise AcceptanceError("unsupported configured execution backend")
    if version == 1:
        if backend != "docker-sandboxes":
            return None
        if allow_pending:
            raise ImportPending("sandbox assignment or source import is pending")
        raise AcceptanceError("Docker execution cannot use a legacy unbound task record")
    if backend != "docker-sandboxes":
        raise AcceptanceError("sandbox execution cannot fall back to a native integration path")
    binding = validate_sandbox_binding(record["sandbox"])
    if binding["acceptedCommit"] is None:
        if allow_pending:
            raise ImportPending("sandbox source has not yet been imported by the host")
        raise AcceptanceError("sandbox source has not yet been imported by the host")
    path = value_for(config, "AGENT_SANDBOX_DEPLOYMENT")
    if not path or value_for(config, "AGENT_SANDBOX_ENFORCED") != "true":
        raise AcceptanceError("Docker task has no enforced protected deployment")
    return verify_execution_acceptance(Path(path), repository, workspace, team, feature, task, record)
