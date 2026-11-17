"""Semantic verification of independently root-reviewed live observations.

This is an evidence verifier and privileged issuer, not a test-result converter.
The administrator must run and review each named live method on the dedicated
deployment. Fixture/unit reports, arbitrary `passed` booleans and personal
qualification namespaces cannot be enrolled. Root ownership is an explicit
administrator trust decision; JSON cannot prove an observation was performed.
"""
from __future__ import annotations

import contextlib
import dataclasses
import errno
import fcntl
import os
from pathlib import Path
import platform
import re
import stat
import time
from typing import Any

from .execution_backend import DockerProfile, parse_profile
from .sandbox_deployment import (
    Deployment, DeploymentError, _closed, _within, canonical_bytes, decode_object,
    digest_bytes, private_directory, read_root_protected, verify_deployment,
)
from .sandbox_enrollment import EnrollmentError, EnrollmentReceipt, load_enrollment
from .sandbox_qualification import REQUIRED_CHECK_IDS
from .sandbox_registry import SandboxRegistry, _validate_state as validate_registry_state
from .secret_safety import contains_secret_like


MAX_EVIDENCE_BYTES = 128 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_ARTIFACTS = 16
MAX_OBSERVATION_AGE = 24 * 3600
EVIDENCE_FIELDS = frozenset({"schemaVersion", "kind", "gateId", "method", "deploymentDigest",
    "profileBasisDigest", "controllerUid", "namespace", "registry", "observedAt", "validUntil",
    "review", "artifacts", "observations"})
METHODS = {key: "dedicated-host-" + key + "-v1" for key in REQUIRED_CHECK_IDS}
POLICY_CASES = frozenset({"public-ipv4", "public-ipv6", "dns", "private-ipv4", "private-ipv6",
    "link-local-metadata", "loopback-host", "unapproved-model", "approved-dummy-model"})
TRANSPORT_CASES = frozenset({"binary-echo", "stderr-separation", "guest-exit", "backpressure",
    "oversize-frame", "truncated-frame", "slow-input", "reader-disconnect", "cancel"})
IDENTITY_CASES = frozenset({"replacement-denied", "stale-epoch-denied", "stale-generation-denied",
    "second-controller-denied", "external-operator-denied", "daemon-restart-fenced"})
LIFECYCLE_CASES = frozenset({"controller-sigkill", "relay-failure", "guest-timeout", "daemon-restart",
    "queued-exec-race", "watchdog-failure"})


class QualificationEvidenceError(EnrollmentError):
    """Live deployment qualification is missing, inconsistent or unproven."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationEvidenceError(message)


def _number(value: Any, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    _require(type(value) is int and minimum <= value <= maximum, "invalid bounded observation integer")
    return value


def _case_set(value: Any, required: frozenset[str], fields: set[str]) -> list[dict]:
    _require(type(value) is list and len(value) == len(required), "required live cases are incomplete")
    result = []
    names = set()
    for case in value:
        _closed(case, fields, "live case")
        _require(type(case["case"]) is str and case["case"] in required and case["case"] not in names, "unknown or repeated live case")
        names.add(case["case"]); result.append(case)
    _require(names == required, "required live cases are incomplete")
    return result


def _semantics(gate: str, value: Any, deployment: Deployment, profile: DockerProfile) -> None:
    """Check named raw-result semantics; there is no generic 'passed' field."""
    if gate == "version-platform":
        _closed(value, {"system", "architecture", "osVersion", "kernelRelease", "pythonVersion", "cliVersion", "daemonVersion", "runtimeSha256", "signatureTeamId", "notarized"}, "platform observations")
        _require(value["system"] == "Darwin" and value["architecture"] == "arm64"
            and value["system"] == platform.system() and value["architecture"] == platform.machine()
            and value["osVersion"] == platform.mac_ver()[0] and value["kernelRelease"] == platform.release()
            and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", value["osVersion"]) is not None
            and int(value["osVersion"].split(".")[0]) >= 14
            and type(value["pythonVersion"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["pythonVersion"]) is not None
            and tuple(map(int, value["pythonVersion"].split("."))) >= (3, 10, 0)
            and value["cliVersion"] == value["daemonVersion"] == "v0.54.0"
            and value["runtimeSha256"] == profile.sbx_sha256
            and value["signatureTeamId"] == "9BNSXJN65R" and value["notarized"] is True,
            "exact signed/notarized macOS runtime/platform was not established")
    elif gate == "mountless-startup":
        _closed(value, {"image", "hostMounts", "runtimeMounts", "mcpServers", "skillsEnabled", "settings", "guestRootCanaryHostReads"}, "mountless observations")
        settings = _closed(value["settings"], {"ssh.agentForwardingEnabled", "browser.enabled", "clipboard.imagePaste", "sandbox.fuse", "model.server.enabled"}, "effective integration settings")
        _require(value["image"] == profile.image and value["hostMounts"] == value["runtimeMounts"] == value["mcpServers"] == []
            and value["skillsEnabled"] is False and all(setting is False for setting in settings.values())
            and value["guestRootCanaryHostReads"] == [], "host integrations, mounts or host-file canaries are not isolated")
    elif gate == "policy-before-execution":
        _closed(value, {"policyDigest", "policyInstalledSequence", "firstGuestSequence", "probes"}, "policy observations")
        _require(value["policyDigest"] == profile.policy_digest and _number(value["policyInstalledSequence"], minimum=1) < _number(value["firstGuestSequence"], minimum=1), "policy did not precede every guest phase")
        for case in _case_set(value["probes"], POLICY_CASES, {"case", "positiveControlReached", "guestReached", "policyDecision"}):
            allowed = case["case"] == "approved-dummy-model"
            _require(case["positiveControlReached"] is True and case["guestReached"] is allowed
                and case["policyDecision"] == ("allow" if allowed else "deny"), "network case lacks a positive control or expected policy decision")
    elif gate == "object-identity":
        _closed(value, {"strategy", "endpoints", "ordinaryUidProbes", "guestControlAccess", "faultCases"}, "identity observations")
        _require(value["strategy"] == "dedicated-account-exclusive-controller" and value["guestControlAccess"] is False, "exclusive controller strategy was not established")
        _require(type(value["endpoints"]) is list and 1 <= len(value["endpoints"]) <= 16, "control endpoint inventory is missing")
        endpoints = set()
        for endpoint in value["endpoints"]:
            _closed(endpoint, {"path", "device", "inode", "uid", "mode"}, "daemon endpoint")
            _require(type(endpoint["path"]) is str and _within(endpoint["path"], deployment.account_home)
                and endpoint["path"] not in endpoints and type(endpoint["uid"]) is int and endpoint["uid"] == deployment.controller_uid
                and type(endpoint["mode"]) is int and endpoint["mode"] in {0o600, 0o700}, "invalid private daemon endpoint")
            _number(endpoint["device"]); _number(endpoint["inode"], minimum=1); endpoints.add(endpoint["path"])
        _require(type(value["ordinaryUidProbes"]) is list and 1 <= len(value["ordinaryUidProbes"]) <= 64, "ordinary-user access probes are missing")
        denied = set()
        for probe in value["ordinaryUidProbes"]:
            _closed(probe, {"uid", "path", "connectErrno"}, "ordinary-user endpoint probe")
            _number(probe["uid"], minimum=1, maximum=2**31 - 1)
            _require(probe["uid"] != deployment.controller_uid and probe["path"] in endpoints
                and type(probe["connectErrno"]) is int and probe["connectErrno"] in {errno.EACCES, errno.EPERM}, "ordinary user reached a daemon endpoint or endpoint absence was mistaken for denial")
            denied.add(probe["path"])
        _require(denied == endpoints, "every control endpoint needs an ordinary-user denial probe")
        for case in _case_set(value["faultCases"], IDENTITY_CASES, {"case", "unexpectedNativeDispatches"}):
            _require(type(case["unexpectedNativeDispatches"]) is int and case["unexpectedNativeDispatches"] == 0, "identity fault dispatched an unauthorized command")
    elif gate == "exec-protocol":
        _closed(value, {"nonTty", "maxFrameBytes", "cases"}, "transport observations")
        _require(value["nonTty"] is True and _number(value["maxFrameBytes"], minimum=1) <= 65536, "bounded non-TTY transport is unproven")
        for case in _case_set(value["cases"], TRANSPORT_CASES, {"case", "expectedDigest", "observedDigest", "elapsedMillis", "nativeChildrenRemaining"}):
            _require(type(case["expectedDigest"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", case["expectedDigest"]) is not None
                and case["observedDigest"] == case["expectedDigest"]
                and _number(case["elapsedMillis"]) <= profile.limits.wall_seconds * 1000
                and type(case["nativeChildrenRemaining"]) is int and case["nativeChildrenRemaining"] == 0,
                "transport output, cancellation or deadline differs from its approved fixture")
    elif gate == "resource-limits":
        _closed(value, {"cpus", "memoryMiB", "rootDiskMiB", "dockerDiskMiB", "outputBytes", "volumeUuid", "quotaBytes", "coveredWritableRoots", "guestRootPressureErrno", "hostPressureBytes", "hostMinimumFreeBytes", "retainedBytesAfterCleanup", "maxConcurrentJobs", "hostPhysicalMemoryMiB", "hostReservedMemoryMiB", "hostLogicalCpus"}, "resource observations")
        limits = profile.limits
        _require(_number(value["cpus"], minimum=1) == limits.cpus and _number(value["memoryMiB"], minimum=1) == limits.memory_mib
            and _number(value["rootDiskMiB"], minimum=1) == limits.root_disk_mib and _number(value["dockerDiskMiB"], minimum=1) == limits.docker_disk_mib
            and _number(value["outputBytes"]) <= limits.max_output_bytes,
            "CPU/memory/disk/output bounds differ from the profile")
        _require(_number(value["maxConcurrentJobs"], minimum=1) == deployment.max_active_jobs
            and _number(value["hostPhysicalMemoryMiB"], minimum=1) >= limits.memory_mib * deployment.max_active_jobs + _number(value["hostReservedMemoryMiB"], minimum=1024)
            and _number(value["hostLogicalCpus"], minimum=2) > limits.cpus * deployment.max_active_jobs,
            "configured concurrent jobs leave insufficient finite host CPU/memory headroom")
        _require(value["volumeUuid"].lower() == deployment.storage["volumeUuid"].lower()
            and value["quotaBytes"] == deployment.storage["quotaBytes"]
            and value["coveredWritableRoots"] == [deployment.account_home]
            and type(value["guestRootPressureErrno"]) is int and value["guestRootPressureErrno"] == errno.ENOSPC
            and 0 < _number(value["hostPressureBytes"]) <= deployment.storage["quotaBytes"]
            and _number(value["hostMinimumFreeBytes"]) >= deployment.storage["minimumFreeBytes"]
            and _number(value["retainedBytesAfterCleanup"]) < deployment.storage["quotaBytes"], "hard aggregate storage/pressure/headroom proof is incomplete")
    elif gate == "cancellation-cleanup":
        _closed(value, {"independentWatchdog", "serverReconciliation", "cases"}, "cleanup observations")
        _require(value["independentWatchdog"] == "external-process" and value["serverReconciliation"] == "daemon-barrier-and-positive-empty-inventory", "independent watchdog/server reconciliation is unproven")
        for case in _case_set(value["cases"], LIFECYCLE_CASES, {"case", "publicationFencedBeforeStop", "queuedCommandsAfterBarrier", "remainingOwnedSandboxes", "remainingOwnedPorts", "storageReconciled"}):
            _require(case["publicationFencedBeforeStop"] is True and type(case["queuedCommandsAfterBarrier"]) is int
                and case["queuedCommandsAfterBarrier"] == 0 and case["remainingOwnedSandboxes"] == []
                and case["remainingOwnedPorts"] == [] and case["storageReconciled"] is True,
                "crash/timeout/restart failed to fence, drain or clean exact owned resources")
    elif gate == "credentials":
        _closed(value, {"principalKind", "agentUid", "modelCliSha256", "modelCliRequestSucceeded", "tlsProxySentinelObserved", "caTrusted", "dummyModelResponseDigest", "globalProviderSecrets", "guestPlaintextCredentialReads", "privilegedServiceAccess", "scopedDummyRequestReceived", "afterScopedRemovalStatus", "quotaDeniedAt", "quotaLimit", "externalMacBrokerFixture"}, "credential observations")
        _require(value["principalKind"] == "dummy-only" and value["globalProviderSecrets"] == []
            and type(value["agentUid"]) is int and value["agentUid"] == 2000
            and value["modelCliRequestSucceeded"] is True and value["tlsProxySentinelObserved"] is True and value["caTrusted"] is True
            and type(value["modelCliSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["modelCliSha256"])
            and type(value["dummyModelResponseDigest"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value["dummyModelResponseDigest"])
            and value["guestPlaintextCredentialReads"] == [] and value["privilegedServiceAccess"] == []
            and value["scopedDummyRequestReceived"] is True and value["afterScopedRemovalStatus"] in {401, 403}
            and _number(value["quotaLimit"], minimum=1, maximum=100) == _number(value["quotaDeniedAt"], minimum=1, maximum=100)
            and value["externalMacBrokerFixture"] == "authenticated-native-peer-only",
            "dummy scoped credentials, no global fallback, quotas or external host broker boundary are unproven")
    else:
        raise QualificationEvidenceError("unknown mandatory gate")


def verify_live_evidence(raw: bytes, gate: str, deployment: Deployment, profile: DockerProfile,
                         registry_binding: dict, *, now: int, check_current_endpoints: bool = True) -> dict:
    try:
        value = _closed(decode_object(raw, maximum=MAX_EVIDENCE_BYTES), EVIDENCE_FIELDS, "live qualification evidence")
        _require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["kind"] == "root-reviewed-live-qualification" and value["gateId"] == gate
            and gate in METHODS and value["method"] == METHODS[gate], "wrong live qualification evidence kind/method")
        _require(value["deploymentDigest"] == deployment.digest and value["profileBasisDigest"] == deployment.profile_basis_digest
            and value["controllerUid"] == deployment.controller_uid and value["namespace"] == deployment.namespace
            and value["registry"] == registry_binding, "live evidence targets another deployment/profile/registry")
        _number(value["observedAt"], minimum=1); _number(value["validUntil"], minimum=1)
        _require(value["observedAt"] <= now < value["validUntil"] <= value["observedAt"] + MAX_OBSERVATION_AGE, "live observations are expired or have an excessive lifetime")
        review = _closed(value["review"], {"reviewerUid", "scope"}, "independent root review")
        _require(type(review["reviewerUid"]) is int and review["reviewerUid"] == 0
            and review["scope"] == "actual-dedicated-macos-host", "unit/container/personal-account observations cannot enroll this deployment")
        artifacts = value["artifacts"]
        _require(type(artifacts) is list and 1 <= len(artifacts) <= MAX_ARTIFACTS, "raw live evidence artifacts are missing")
        seen = set()
        for artifact in artifacts:
            _closed(artifact, {"path", "sha256"}, "live evidence artifact")
            path = artifact["path"]
            _require(type(path) is str and _within(path, deployment.evidence_root) and path not in seen, "artifact escapes protected evidence root or repeats")
            body, observed = read_root_protected(Path(path), maximum=MAX_ARTIFACT_BYTES)
            _require(body is not None and artifact["sha256"] == "sha256:" + observed, "raw live evidence bytes changed")
            _require(not contains_secret_like(body.decode("utf-8", errors="ignore")), "live proof contains apparent credential material; retain only redacted observations")
            seen.add(path)
        _semantics(gate, value["observations"], deployment, profile)
        if gate == "object-identity" and check_current_endpoints:
            for endpoint in value["observations"]["endpoints"]:
                selected = Path(endpoint["path"])
                private_directory(selected.parent, deployment.controller_uid)
                info = os.stat(selected, follow_symlinks=False)
                _require(stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
                    == (endpoint["device"], endpoint["inode"], endpoint["uid"], endpoint["mode"]), "daemon endpoint was replaced or permissions changed; requalification required")
        return value
    except QualificationEvidenceError:
        raise
    except (DeploymentError, OSError, TypeError, KeyError, ValueError, AttributeError) as exc:
        raise QualificationEvidenceError("live qualification evidence is invalid or unavailable") from exc


def verify_deployment_enrollment(deployment: Deployment, profile: DockerProfile, receipt_path: Path,
                                 registry: SandboxRegistry, *, transaction: Any = None, now: int | None = None) -> EnrollmentReceipt:
    """Production service gate: authenticated receipt plus live deployment anchors."""
    current = int(time.time()) if now is None else now
    _number(current, minimum=1)
    _require(str(receipt_path) == deployment.receipt_path and str(registry.root) == deployment.registry_root,
        "service chose an unenrolled receipt or registry path")
    verify_deployment(deployment, profile)
    receipt = load_enrollment(profile, receipt_path, registry, transaction=transaction, now=current)
    binding = receipt.as_dict()["registry"]
    for gate, digest in receipt.checks:
        path = Path(deployment.evidence_root) / (digest[7:] + ".json")
        raw, observed = read_root_protected(path, maximum=MAX_EVIDENCE_BYTES)
        _require(raw is not None and "sha256:" + observed == digest, "enrolled live evidence bytes changed")
        verify_live_evidence(raw, gate, deployment, profile, binding, now=current)
    return receipt


def qualification_inventory(deployment: Deployment) -> dict:
    """Prepare exact named methods; never creates positive evidence or a receipt."""
    return {"schemaVersion": 1, "scope": "dedicated-live-qualification-preparation", "deploymentDigest": deployment.digest,
        "profileBasisDigest": deployment.profile_basis_digest, "qualified": False, "autonomousReady": False,
        "productionBackendAllowed": False, "checks": [{"id": gate, "method": METHODS[gate],
        "evidencePath": str(Path(deployment.evidence_root) / (gate + ".json")), "status": "needs-validation",
        "incompleteTemplate": {"schemaVersion": 1, "kind": "root-reviewed-live-qualification", "gateId": gate,
            "method": METHODS[gate], "deploymentDigest": deployment.digest, "profileBasisDigest": deployment.profile_basis_digest,
            "controllerUid": deployment.controller_uid, "namespace": deployment.namespace, "registry": None,
            "observedAt": 0, "validUntil": 0, "review": {"reviewerUid": 0, "scope": "needs-independent-review"},
            "artifacts": [], "observations": {}}} for gate in REQUIRED_CHECK_IDS],
        "instruction": "Run and independently root-review the named live methods on this dedicated macOS deployment. No unit test or personal-account report is accepted."}


def _controller_file(directory: int, name: str, uid: int, maximum: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_nlink == 1 and 0 < before.st_size <= maximum, "private controller evidence file is unsafe")
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        _require(len(result) == before.st_size and stamp(before) == stamp(os.fstat(descriptor))
            and stamp(before) == stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)), "private evidence changed during observation")
        return bytes(result)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def _quiescent_registry(deployment: Deployment):
    """Root observer holds existing registry lock; never initializes or adopts."""
    device, inode = private_directory(Path(deployment.registry_root), deployment.controller_uid)
    descriptor = os.open(deployment.registry_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lock = None
    try:
        opened_root = os.fstat(descriptor)
        _require((opened_root.st_dev, opened_root.st_ino) == (device, inode), "registry root changed before root observation")
        lock = os.open("registry.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=descriptor)
        info = os.fstat(lock)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == deployment.controller_uid
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0, "unsafe existing registry lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        named = os.stat("registry.lock", dir_fd=descriptor, follow_symlinks=False)
        _require((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino), "registry lock changed")
        marker = decode_object(_controller_file(descriptor, "registry.identity", deployment.controller_uid, 4096))
        state = decode_object(_controller_file(descriptor, "registry.json", deployment.controller_uid, 16 * 1024 * 1024), maximum=16 * 1024 * 1024)
        _closed(marker, {"schemaVersion", "registryId", "namespace"}, "registry marker")
        _closed(state, {"schemaVersion", "registryId", "namespace", "epoch", "revision", "records"}, "registry state")
        _require(type(marker["schemaVersion"]) is int and marker["schemaVersion"] == 1
            and marker["namespace"] == state["namespace"] == deployment.namespace
            and marker["registryId"] == state["registryId"]
            and type(marker["registryId"]) is str and re.fullmatch(r"reg-[0-9a-f]{32}", marker["registryId"]) is not None
            and type(state["records"]) is dict, "existing registry identity is inconsistent")
        validate_registry_state(state, namespace=deployment.namespace, registry_id=marker["registryId"], max_names=1024)
        _require(all(type(record) is dict and record.get("state") == "removed" for record in state["records"].values()),
            "enrollment requires no live/uncertain reservations; reconcile exact resources first")
        yield {"root": deployment.registry_root, "device": device, "inode": inode, "registryId": marker["registryId"]}
    finally:
        if lock is not None:
            os.close(lock)
        os.close(descriptor)


def _root_write(path: Path, raw: bytes, *, expected_digest: str | None = None) -> None:
    """Root-only fixed pending file, fsync and exact CAS replacement."""
    _require(os.geteuid() == 0, "only an administrator may install enrollment authority")
    # The read helper validates every parent. A fresh file uses its real parent
    # and checks all ancestors explicitly before creating the fixed pending name.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open("/", flags)
    try:
        for part in path.parts[1:-1]:
            info = os.fstat(parent)
            _require(info.st_uid == 0 and not info.st_mode & 0o022, "root authority parent is writable")
            opened = os.open(part, flags, dir_fd=parent)
            os.close(parent); parent = opened
        info = os.fstat(parent)
        _require(info.st_uid == 0 and not info.st_mode & 0o022, "root authority parent is writable")
        def existing():
            try:
                body, _sha = read_root_protected(path, maximum=max(MAX_EVIDENCE_BYTES, len(raw)))
            except FileNotFoundError:
                return None
            return body
        current = existing()
        if current == raw:
            return
        _require((current is None and expected_digest is None)
            or current is not None and expected_digest == digest_bytes(current), "root authority bytes changed; overwrite refused")
        pending = "." + path.name + ".pending"
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(descriptor, raw[offset:offset + 65536])
                _require(count > 0, "incomplete authority write")
                offset += count
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _require(existing() == current, "root authority changed before commit")
        os.replace(pending, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        committed, _sha = read_root_protected(path, maximum=max(MAX_EVIDENCE_BYTES, len(raw)))
        _require(committed == raw, "root authority write is uncertain")
    finally:
        os.close(parent)


def verify_quiescent_histories(deployment: Deployment) -> None:
    """Root enrollment must not erase unresolved main/watchdog/model history."""
    roots = [(Path(deployment.native_journal_root), "native-clients.json", ".native-clients.pending", "native"),
        (Path(deployment.watchdog_root) / "native-clients", "native-clients.json", ".native-clients.pending", "native"),
        (Path(deployment.credential_root), "model-credentials.json", ".model-credentials.pending", "credentials")]
    tools = {key: deployment.programs[key] for key in ("python", "gate", "lifecycleHelper")}
    from .execution_backend import canonical_digest
    for root, filename, pending, kind in roots:
        try:
            os.stat(root, follow_symlinks=False)
        except FileNotFoundError:
            _require(root == Path(deployment.watchdog_root) / "native-clients", "main private history root is missing")
            continue
        identity = private_directory(root, deployment.controller_uid)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        lock = None
        try:
            opened = os.fstat(directory)
            _require((opened.st_dev, opened.st_ino) == identity, "private history root changed before observation")
            names = set(os.listdir(directory))
            if not names:
                continue  # A genuinely never-initialized private directory.
            _require(pending not in names and filename in names, "private history is missing or has an interrupted commit")
            lock = os.open("registry.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            info = os.fstat(lock)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == deployment.controller_uid and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and info.st_size == 0, "private history lock is unsafe")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            named = os.stat("registry.lock", dir_fd=directory, follow_symlinks=False)
            _require((named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_nlink, named.st_size)
                == (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size), "private history lock changed")
            marker = decode_object(_controller_file(directory, "registry.identity", deployment.controller_uid, 4096))
            registry_state = decode_object(_controller_file(directory, "registry.json", deployment.controller_uid, 16 * 1024 * 1024), maximum=16 * 1024 * 1024)
            state = decode_object(_controller_file(directory, filename, deployment.controller_uid, 4 * 1024 * 1024), maximum=4 * 1024 * 1024)
            _closed(marker, {"schemaVersion", "registryId", "namespace"}, "history registry identity")
            _require(type(marker["schemaVersion"]) is int and marker["schemaVersion"] == 1 and marker["namespace"] == deployment.namespace
                and type(marker["registryId"]) is str and re.fullmatch(r"reg-[0-9a-f]{32}", marker["registryId"]), "private history namespace/identity differs")
            validate_registry_state(registry_state, namespace=deployment.namespace, registry_id=marker["registryId"], max_names=1024)
            _require(all(record["state"] == "removed" for record in registry_state["records"].values()), "private history registry has unresolved reservations")
            if kind == "native":
                from .native_clients import validate_native_history
                state = validate_native_history(state, profile_basis_digest=deployment.profile_basis_digest,
                    tools_digest=canonical_digest(tools), journal_id=marker["registryId"], namespace=deployment.namespace)
                for record in state["records"].values():
                    _require(type(record) is dict and record.get("state") in {"completed-acknowledged", "aborted-before-release"},
                        "native history contains unacknowledged or uncertain delivery")
            else:
                _closed(state, {"schemaVersion", "deploymentDigest", "revision", "leases"}, "credential history")
                _require(type(state["schemaVersion"]) is int and state["schemaVersion"] == 1
                    and state["deploymentDigest"] == deployment.digest and type(state["revision"]) is int and 0 <= state["revision"] <= 2**63 - 1
                    and type(state["leases"]) is dict and len(state["leases"]) <= 1024,
                    "credential history binding is invalid")
                from .model_credentials import CredentialLease, _key
                for key, record in state["leases"].items():
                    _closed(record, {"lease", "state", "receiptDigest"}, "credential history record")
                    lease = CredentialLease.from_dict(record["lease"])
                    _require(key == _key(lease) and lease.deployment_digest == deployment.digest
                        and lease.profile_basis_digest == deployment.profile_basis_digest and record["state"] == "removed"
                        and (record["receiptDigest"] is None or type(record["receiptDigest"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", record["receiptDigest"])),
                        "scoped model credential cleanup or binding is unresolved")
            current = os.stat(root, follow_symlinks=False)
            _require((current.st_dev, current.st_ino) == identity, "private history root changed during observation")
        finally:
            if lock is not None:
                os.close(lock)
            os.close(directory)


def issue_enrollment(deployment: Deployment, *, now: int | None = None, validity_seconds: int = 3600,
                     install: bool = False) -> dict:
    """Review all real proofs; optionally install exact receipt then profile pin.

    Called only by the administrator after independently reviewed live methods.
    It never invokes Docker, invents evidence, changes a failed result, creates an
    account/registry, or turns a diagnostic smoke report into authority.
    """
    _require(os.geteuid() == 0, "root review/issuance is required; no qualification receipt was created")
    current = int(time.time()) if now is None else now
    _number(current, minimum=1); _number(validity_seconds, minimum=1, maximum=24 * 3600)
    raw_profile, _sha = read_root_protected(Path(deployment.profile_path), maximum=64 * 1024)
    _require(raw_profile is not None, "protected profile is missing")
    profile = parse_profile(raw_profile)
    verify_deployment(deployment, profile)
    with _quiescent_registry(deployment) as binding:
        verify_quiescent_histories(deployment)
        verified = []
        observations = {}
        expires = current + validity_seconds
        for gate in REQUIRED_CHECK_IDS:
            raw, _sha = read_root_protected(Path(deployment.evidence_root) / (gate + ".json"), maximum=MAX_EVIDENCE_BYTES)
            _require(raw is not None, "root-reviewed live gate is missing")
            value = verify_live_evidence(raw, gate, deployment, profile, binding, now=current)
            observations[gate] = value
            expires = min(expires, value["validUntil"])
            verified.append((gate, digest_bytes(raw), raw))
        # These are actual fixed read-only commands as the dedicated account,
        # not values supplied by the dossier. They may not be used as enforcement
        # or pressure-test substitutes. Endpoint identity is checked again so a
        # CLI that started/replaced a daemon cannot enroll the prior generation.
        from .sandbox_qualification_observer import current_settings_policy, current_storage, current_endpoint_denials, current_protected_denials, current_account_status, current_host_resources, current_interpreter
        current_account_status(deployment)
        _require(current_interpreter(deployment) == observations["version-platform"]["observations"]["pythonVersion"], "current protected Python differs from reviewed runtime version")
        current_protected_denials(deployment, profile)
        live = current_settings_policy(deployment, profile)
        _require(live["settings"] == observations["mountless-startup"]["observations"]["settings"], "current effective host settings differ from reviewed proof")
        current_storage(deployment)
        resources = current_host_resources()
        reviewed_resources = observations["resource-limits"]["observations"]
        _require(resources["physicalMemoryMiB"] == reviewed_resources["hostPhysicalMemoryMiB"]
            and resources["logicalCpus"] == reviewed_resources["hostLogicalCpus"], "current host CPU/memory inventory differs from reviewed resource budget")
        current_endpoint_denials(deployment, observations["object-identity"]["observations"]["endpoints"])
        identity_raw = next(raw for gate, _digest, raw in verified if gate == "object-identity")
        verify_live_evidence(identity_raw, "object-identity", deployment, profile, binding, now=current)
        verify_deployment(deployment, profile)
        receipt = EnrollmentReceipt.from_dict({"schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
            "profileBasisDigest": deployment.profile_basis_digest, "controllerUid": deployment.controller_uid,
            "namespace": deployment.namespace, "dedicatedAccount": True, "exclusiveNamespace": True, "registry": binding,
            "issuedAt": current, "expiresAt": expires,
            "checks": {gate: {"passed": True, "evidenceDigest": digest} for gate, digest, _raw in verified}})
        raw_receipt = canonical_bytes(receipt.as_dict())
        revised_profile = dataclasses.replace(profile, qualification_digest=digest_bytes(raw_receipt))
        if install:
            for _gate, digest, raw in verified:
                _root_write(Path(deployment.evidence_root) / (digest[7:] + ".json"), raw)
            try:
                old_receipt, _sha = read_root_protected(Path(deployment.receipt_path), maximum=64 * 1024)
            except FileNotFoundError:
                old_receipt = None
            _root_write(Path(deployment.receipt_path), raw_receipt,
                expected_digest=digest_bytes(old_receipt) if old_receipt is not None else None)
            # Last authority pointer: a crash before this exact replacement
            # leaves a mismatched receipt pin and therefore denies dispatch.
            _root_write(Path(deployment.profile_path), canonical_bytes(revised_profile.as_dict()), expected_digest=digest_bytes(raw_profile))
        return {"schemaVersion": 1, "scope": "root-reviewed-live-enrollment", "installed": install,
            "deploymentDigest": deployment.digest, "receiptDigest": digest_bytes(raw_receipt),
            "profileBasisDigest": deployment.profile_basis_digest, "expiresAt": expires,
            "checks": list(REQUIRED_CHECK_IDS), "serviceStarted": False}
