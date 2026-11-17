"""Shared execution-record versions and sandbox projection bindings.

These records are projections, never enrollment or import authority. A sandbox
acceptance must also be verified against protected controller state before an
integration mutation. Legacy records retain their existing checks at callers;
adding a sandbox field to a legacy record is always an invalid downgrade.
"""
from __future__ import annotations

import copy
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from startup_factory_cli.execution_backend import (  # noqa: E402
    BackendContractError, BackendIdentity, _digest, _image,
)


class ExecutionDescriptorError(ValueError):
    pass


SANDBOX_FIELDS = frozenset({
    "schemaVersion", "backend", "namespace", "name", "sandboxId", "createdAt",
    "generation", "epoch", "profileDigest", "policyDigest", "image",
    "inputDigest", "baseCommit", "state", "acceptedCommit", "acceptedTree",
    "acceptedExportDigest",
})
SANDBOX_STATES = frozenset({
    "ready", "running", "collecting", "candidate", "accepted", "fenced",
    "work-complete", "failed", "cleanup-pending", "stopped", "removed",
})
ACCEPTED_FIELDS = ("acceptedCommit", "acceptedTree", "acceptedExportDigest")
_OID = re.compile(r"[0-9a-f]{40}\Z")
_ROLE = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")


def validate_sandbox_binding(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != SANDBOX_FIELDS:
        raise ExecutionDescriptorError("sandbox binding requires exactly its supported fields")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or value["backend"] != "docker-sandboxes":
        raise ExecutionDescriptorError("unsupported sandbox binding version or backend")
    namespace = value["namespace"]
    if not isinstance(namespace, str) or not re.fullmatch(r"sf-[a-z0-9]+(?:-[a-z0-9]+)*", namespace) or len(namespace) > 20 or namespace == "sf-qualification":
        raise ExecutionDescriptorError("sandbox binding has no dedicated production namespace")
    if not isinstance(value["name"], str) or not re.fullmatch(r"sf-[0-9a-f]{32}", value["name"]):
        raise ExecutionDescriptorError("sandbox name is not a permanently reserved random locator")
    if not isinstance(value["generation"], str) or not re.fullmatch(r"gen-[0-9a-f]{32}", value["generation"]):
        raise ExecutionDescriptorError("invalid sandbox generation")
    if type(value["epoch"]) is not int or not 1 <= value["epoch"] <= 2**63 - 1:
        raise ExecutionDescriptorError("invalid sandbox controller epoch")
    try:
        BackendIdentity(value["name"], value["sandboxId"], value["createdAt"])
        for field in ("profileDigest", "policyDigest", "inputDigest"):
            _digest(value[field], field)
        _image(value["image"])
    except BackendContractError as exc:
        raise ExecutionDescriptorError(str(exc)) from exc
    if not isinstance(value["baseCommit"], str) or not _OID.fullmatch(value["baseCommit"]):
        raise ExecutionDescriptorError("sandbox binding has an invalid approved base commit")
    if not isinstance(value["state"], str) or value["state"] not in SANDBOX_STATES:
        raise ExecutionDescriptorError("unsupported sandbox execution state")
    present = [value[field] is not None for field in ACCEPTED_FIELDS]
    if any(present) and not all(present):
        raise ExecutionDescriptorError("sandbox acceptance must have all three immutable bindings")
    if all(present):
        if value["state"] not in {"accepted", "removed"}:
            raise ExecutionDescriptorError("sandbox acceptance is inconsistent with its execution state")
        for field in ("acceptedCommit", "acceptedTree"):
            if not isinstance(value[field], str) or not _OID.fullmatch(value[field]):
                raise ExecutionDescriptorError("invalid host-accepted Git identity")
        try:
            _digest(value["acceptedExportDigest"], "accepted export digest")
        except BackendContractError as exc:
            raise ExecutionDescriptorError(str(exc)) from exc
    elif value["state"] == "accepted":
        raise ExecutionDescriptorError("accepted sandbox execution lacks host acceptance bindings")
    return copy.deepcopy(value)


def execution_version(record: object) -> int:
    if type(record) is not dict or type(record.get("schemaVersion")) is not int:
        raise ExecutionDescriptorError("execution record must have a literal supported version")
    version = record["schemaVersion"]
    if version == 1:
        if "sandbox" in record:
            raise ExecutionDescriptorError("sandbox execution cannot be downgraded to the legacy schema")
    elif version == 2:
        validate_sandbox_binding(record.get("sandbox"))
        if type(record.get("claimLineage")) is not dict:
            raise ExecutionDescriptorError("sandbox execution requires immutable claim lineage")
        try:
            _digest(record.get("lineageDigest"), "claim lineage digest")
        except BackendContractError as exc:
            raise ExecutionDescriptorError(str(exc)) from exc
    else:
        raise ExecutionDescriptorError("unsupported execution record version")
    return version


def execution_extensions(record: dict) -> frozenset[str]:
    return frozenset({"sandbox"}) if execution_version(record) == 2 else frozenset()


def require_accepted_sandbox(record: dict) -> dict[str, Any] | None:
    """Check projection structure only; callers must verify protected acceptance."""
    if execution_version(record) == 1:
        return None
    binding = validate_sandbox_binding(record["sandbox"])
    if binding["state"] not in {"accepted", "removed"} or binding["acceptedCommit"] is None:
        raise ExecutionDescriptorError("sandbox output has not been independently accepted by the host")
    return binding


def expected_execution_identity(
    record: dict, *, workspace: Path, team: str, feature: str, task: str,
    key: str, role: str | None = None, attempt: int | None = None,
    include_sandbox: bool = True,
) -> dict[str, Any]:
    version = execution_version(record)
    role = record.get("role") if role is None else role
    attempt = record.get("attempt") if attempt is None else attempt
    if not isinstance(role, str) or not _ROLE.fullmatch(role) or type(attempt) is not int or attempt < 1:
        raise ExecutionDescriptorError("execution has an invalid concrete role or attempt")
    artifact = workspace / "artifacts" / key / f"attempt-{attempt}"
    result = {
        "schemaVersion": version, "featureId": feature, "taskId": task,
        "taskKey": key, "attempt": attempt, "role": role,
        "branch": f"agent-task/{team}/{key}",
        "worktree": str(workspace / "worktrees" / f"{role}#{attempt}-{key}"),
        "packetPath": str(artifact / "task-packet.md"),
        "packetJsonPath": str(artifact / "task-packet.json"),
        "reportPath": str(artifact / "task-report.md"),
    }
    if version == 2 and include_sandbox:
        result["sandbox"] = validate_sandbox_binding(record["sandbox"])
    return result
