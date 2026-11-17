"""Protected dedicated-account deployment data, preparation and current anchors.

A deployment describes trusted host installation paths. It is not enrollment.
Queue files are controller-owned data; neither their content nor this manifest
can substitute for task authority, a live qualification receipt or a watchdog.
No account, daemon, launchd job, volume, policy or credential is changed here.
"""
from __future__ import annotations

import copy
import dataclasses
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
from typing import Any

from .execution_backend import (
    BackendContractError, DockerProfile, _absolute_path, _digest, _integer,
    _read_protected, canonical_digest, parse_profile,
)
from .sandbox_enrollment import profile_basis_digest


MAX_DEPLOYMENT_BYTES = 256 * 1024
MAX_BUNDLE_FILES = 20_000
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
PROGRAM_KEYS = frozenset({"python", "gate", "lifecycleHelper", "runner", "watchdog"})
DEPLOYMENT_FIELDS = frozenset({
    "schemaVersion", "backend", "namespace", "profilePath", "profileBasisDigest",
    "receiptPath", "registryRoot", "nativeJournalRoot", "socketPath", "jobRoot",
    "evidenceRoot", "controllerUid", "controllerGid", "accountName", "accountHome",
    "bundleRoot", "bundleDigest", "programs", "projects", "maxActiveJobs",
    "maxQueuedJobs", "jobRequestMaxBytes", "storage", "watchdogSocketPath", "watchdogRoot", "runtimeRoot", "runtimeDigest", "modelCredentials", "credentialRoot", "networkPolicyPath", "lifecycleRoot",
})
_NAME = re.compile(r"_sf_[a-z][a-z0-9_]{0,23}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PRIVATE_ROOTS = ("registryRoot", "nativeJournalRoot", "jobRoot", "watchdogRoot", "credentialRoot", "lifecycleRoot")


class DeploymentError(ValueError):
    """A dedicated deployment is malformed, unsafe or not the current install."""


def _closed(value: Any, fields: set[str] | frozenset[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise DeploymentError(f"{label} has unknown or missing fields")
    return value


def decode_object(raw: bytes, *, maximum: int = MAX_DEPLOYMENT_BYTES, depth_limit: int = 12) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise DeploymentError("protected JSON exceeds its byte limit")
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
            if depth > depth_limit:
                raise DeploymentError("protected JSON nesting exceeds its bound")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise DeploymentError("invalid protected JSON")
    def pairs(items):
        value = {}
        for name, child in items:
            if name in value:
                raise DeploymentError("duplicate protected JSON key")
            value[name] = child
        return value
    def constant(_value):
        raise DeploymentError("nonfinite protected JSON number")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DeploymentError("invalid protected JSON") from exc
    pending = [value]
    while pending:
        child = pending.pop()
        if type(child) is dict:
            pending.extend(child.keys()); pending.extend(child.values())
        elif type(child) is list:
            pending.extend(child)
        elif type(child) is str and any(0xD800 <= ord(char) <= 0xDFFF for char in child):
            raise DeploymentError("protected JSON contains an invalid Unicode scalar")
        elif type(child) is float:
            raise DeploymentError("floating point values are unsupported in protected JSON")
    if type(value) is not dict:
        raise DeploymentError("protected JSON must be an object")
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise DeploymentError("data cannot be canonically encoded") from exc


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def read_root_protected(path: Path, *, maximum: int, executable: bool = False, capture: bool = True, allow_empty: bool = False) -> tuple[bytes | None, str]:
    """Root installer/observer equivalent of the nonroot protected reader.

    Nonroot consumers retain effective-access/ACL checks. Root cannot infer
    ordinary-user denial from its own access; live endpoint/path probes remain
    mandatory qualification evidence.
    """
    if os.geteuid() != 0 and not allow_empty:
        result = _read_protected(path, maximum=maximum, capture=capture, executable=executable)
        if os.stat(path, follow_symlinks=False).st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise DeploymentError("setuid/setgid authority/runtime inputs are unsupported")
        return result
    _absolute_path(str(path), "protected input")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    leaf = None
    def protected(info, *, folder):
        if info.st_uid != 0 or info.st_mode & 0o022 or (folder and not stat.S_ISDIR(info.st_mode)):
            raise DeploymentError("root authority/runtime path is unprotected")
        if not folder and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise DeploymentError("root authority input must be a single-link regular file")
        if not folder and info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise DeploymentError("setuid/setgid authority/runtime inputs are unsupported")
    try:
        protected(os.fstat(directory), folder=True)
        current = Path("/")
        if os.geteuid() != 0 and os.access(current, os.W_OK, effective_ids=True):
            raise DeploymentError("controller can write a protected ancestor")
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory); directory = child
            current /= part
            protected(os.fstat(directory), folder=True)
            if os.geteuid() != 0 and os.access(current, os.W_OK, effective_ids=True):
                raise DeploymentError("controller can write a protected ancestor")
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(leaf)
        protected(before, folder=False)
        if not (0 if allow_empty else 1) <= before.st_size <= maximum or executable and not before.st_mode & 0o111:
            raise DeploymentError("protected input is empty, oversized or not executable")
        if os.geteuid() != 0 and os.access(path, os.W_OK, effective_ids=True):
            raise DeploymentError("controller can write protected bytes")
        chunks = []; digest = hashlib.sha256(); total = 0
        while total <= maximum:
            chunk = os.read(leaf, min(65536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk); digest.update(chunk)
            if capture:
                chunks.append(chunk)
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if total != before.st_size or stamp(before) != stamp(os.fstat(leaf)) or stamp(before) != stamp(os.stat(path.name, dir_fd=directory, follow_symlinks=False)):
            raise DeploymentError("protected input changed during observation")
        return b"".join(chunks) if capture else None, digest.hexdigest()
    finally:
        if leaf is not None:
            os.close(leaf)
        os.close(directory)


def _within(path: str, root: str, *, equal: bool = False) -> bool:
    return (equal and path == root) or path.startswith(root + "/")


def _validate(value: dict) -> None:
    try:
        _closed(value, DEPLOYMENT_FIELDS, "deployment")
        if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or value["backend"] != "docker-sandboxes":
            raise DeploymentError("unsupported deployment version")
        if (type(value["namespace"]) is not str or len(value["namespace"]) > 20
            or value["namespace"] == "sf-qualification"
            or not re.fullmatch(r"sf-[a-z0-9]+(?:-[a-z0-9]+)*", value["namespace"])):
            raise DeploymentError("a dedicated production namespace is required")
        _integer(value["controllerUid"], "controller UID", 1, 2**31 - 1)
        _integer(value["controllerGid"], "controller GID", 1, 2**31 - 1)
        if type(value["accountName"]) is not str or not _NAME.fullmatch(value["accountName"]):
            raise DeploymentError("a dedicated _sf_ service account is required")
        for key in ("profilePath", "receiptPath", "registryRoot", "nativeJournalRoot", "socketPath", "jobRoot", "evidenceRoot", "accountHome", "bundleRoot", "watchdogSocketPath", "watchdogRoot", "runtimeRoot", "credentialRoot", "networkPolicyPath", "lifecycleRoot"):
            _absolute_path(value[key], key)
        for key in ("profileBasisDigest", "bundleDigest", "runtimeDigest"):
            _digest(value[key], key)
        directories = [value[key] for key in _PRIVATE_ROOTS]
        if len(set(directories)) != len(directories) or any(_within(a, b) or _within(b, a) for index, a in enumerate(directories) for b in directories[index + 1:]):
            raise DeploymentError("registry, native journal and queue roots must be disjoint")
        if any(not _within(value[key], value["accountHome"]) for key in (*_PRIVATE_ROOTS, "socketPath", "watchdogSocketPath")):
            raise DeploymentError("private state and control socket must stay inside dedicated HOME")
        if any(_within(value[key], value["accountHome"], equal=True) for key in ("profilePath", "receiptPath", "evidenceRoot", "bundleRoot", "runtimeRoot", "networkPolicyPath")):
            raise DeploymentError("protected authority/runtime must be outside controller-writable HOME")
        if any(_within(value[key], value["bundleRoot"], equal=True) for key in ("profilePath", "receiptPath", "evidenceRoot", "networkPolicyPath")):
            raise DeploymentError("mutable enrollment authority cannot be inside its pinned installed bundle")
        programs = _closed(value["programs"], PROGRAM_KEYS, "program pins")
        for key, program in programs.items():
            _closed(program, {"path", "sha256"}, "program pin")
            _absolute_path(program["path"], "program path")
            if type(program["sha256"]) is not str or not _SHA.fullmatch(program["sha256"]):
                raise DeploymentError("program pin requires a lowercase SHA-256")
            if _within(program["path"], value["accountHome"], equal=True):
                raise DeploymentError("controller cannot own trusted programs")
            if key in {"gate", "lifecycleHelper", "runner", "watchdog"} and not _within(program["path"], value["bundleRoot"]):
                raise DeploymentError("trusted source programs must be in the protected bundle")
        if not programs["runner"]["path"].endswith("/bin/sandbox-custody.py"):
            raise DeploymentError("the installed fixed custody entry point is required")
        if not programs["watchdog"]["path"].endswith("/bin/sandbox-watchdog.py") or value["socketPath"] == value["watchdogSocketPath"]:
            raise DeploymentError("a distinct independent watchdog entry point/socket is required")
        _integer(value["maxActiveJobs"], "active job limit", 1, 32)
        _integer(value["maxQueuedJobs"], "queued job limit", 1, 1024)
        _integer(value["jobRequestMaxBytes"], "job request byte limit", 1024, 4 * 1024 * 1024)
        if type(value["projects"]) is not list or not 1 <= len(value["projects"]) <= 128:
            raise DeploymentError("a finite project allowlist is required")
        projects = set()
        for project in value["projects"]:
            _closed(project, {"projectId", "repository", "workspaceRoot"}, "project")
            _digest(project["projectId"], "project ID")
            for key in ("repository", "workspaceRoot"):
                _absolute_path(project[key], key)
                if not _within(project[key], value["accountHome"]):
                    raise DeploymentError("canonical projects and temporary work must be on dedicated storage")
                if any(_within(project[key], control, equal=True) or _within(control, project[key]) for control in directories):
                    raise DeploymentError("project storage overlaps controller authority/state")
            if project["projectId"] in projects:
                raise DeploymentError("duplicate project allowlist identity")
            if not _within(project["workspaceRoot"], project["repository"]):
                raise DeploymentError("native broker workspace must remain inside its canonical repository")
            projects.add(project["projectId"])
        storage = _closed(value["storage"], {"mountPoint", "volumeUuid", "quotaBytes", "minimumFreeBytes"}, "storage")
        _absolute_path(storage["mountPoint"], "storage mount point")
        if not _within(value["accountHome"], storage["mountPoint"], equal=True):
            raise DeploymentError("the complete dedicated HOME must be inside bounded storage")
        if type(storage["volumeUuid"]) is not str or not re.fullmatch(r"[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}", storage["volumeUuid"]):
            raise DeploymentError("explicit APFS volume identity is required")
        _integer(storage["quotaBytes"], "aggregate storage quota", 1024**3, 1024**4)
        _integer(storage["minimumFreeBytes"], "host headroom", 1024**3, 1024**4)
        credentials = _closed(value["modelCredentials"], {"providers", "roles"}, "model credential configuration")
        if type(credentials["providers"]) is not dict or type(credentials["roles"]) is not dict or len(credentials["roles"]) > 128:
            raise DeploymentError("finite model provider/role configuration is required")
        if any(provider != "openai" for provider in credentials["providers"]):
            raise DeploymentError("this qualified protocol currently supports only the observed OpenAI credential service")
        for provider in credentials["providers"].values():
            _closed(provider, {"sourceFile"}, "root model credential source")
            _absolute_path(provider["sourceFile"], "model credential source")
            if _within(provider["sourceFile"], value["accountHome"], equal=True) or _within(provider["sourceFile"], value["bundleRoot"], equal=True):
                raise DeploymentError("model credentials must be separately root-managed outside controller HOME/bundle")
        for role, provider in credentials["roles"].items():
            if type(role) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", role) or type(provider) is not str or provider not in credentials["providers"]:
                raise DeploymentError("model role assignment uses an unavailable or unsupported provider")
    except BackendContractError as exc:
        raise DeploymentError(str(exc)) from exc


_ATTRS = {"profile_path": "profilePath", "profile_basis_digest": "profileBasisDigest", "receipt_path": "receiptPath",
    "registry_root": "registryRoot", "native_journal_root": "nativeJournalRoot", "socket_path": "socketPath",
    "job_root": "jobRoot", "evidence_root": "evidenceRoot", "controller_uid": "controllerUid", "controller_gid": "controllerGid",
    "account_name": "accountName", "account_home": "accountHome", "bundle_root": "bundleRoot", "bundle_digest": "bundleDigest",
    "max_active_jobs": "maxActiveJobs", "max_queued_jobs": "maxQueuedJobs", "job_request_max_bytes": "jobRequestMaxBytes",
    "watchdog_socket_path": "watchdogSocketPath", "watchdog_root": "watchdogRoot",
    "runtime_root": "runtimeRoot", "runtime_digest": "runtimeDigest", "model_credentials": "modelCredentials",
    "credential_root": "credentialRoot",
    "network_policy_path": "networkPolicyPath",
    "lifecycle_root": "lifecycleRoot",
    "programs": "programs", "projects": "projects", "storage": "storage", "namespace": "namespace"}


@dataclasses.dataclass(frozen=True)
class Deployment:
    source_path: Path
    raw: bytes

    def __post_init__(self) -> None:
        _absolute_path(str(self.source_path), "deployment path")
        value = decode_object(self.raw)
        _validate(value)
        if _within(str(self.source_path), value["accountHome"], equal=True) or _within(str(self.source_path), value["bundleRoot"], equal=True):
            raise DeploymentError("deployment authority must be outside controller HOME and its pinned bundle")

    @property
    def digest(self) -> str:
        return digest_bytes(self.raw)

    def as_dict(self) -> dict:
        return decode_object(self.raw)

    def __getattr__(self, name: str) -> Any:
        if name in _ATTRS:
            value = self.as_dict()[_ATTRS[name]]
            return tuple(value) if name == "projects" else value
        raise AttributeError(name)


def load_deployment(path: Path) -> Deployment:
    """Require a real root-protected manifest; successful loading is not enrollment."""
    try:
        raw, _sha = read_root_protected(path, maximum=MAX_DEPLOYMENT_BYTES)
        if raw is None:
            raise DeploymentError("deployment bytes are unavailable")
        return Deployment(path, raw)
    except (BackendContractError, OSError) as exc:
        raise DeploymentError("protected deployment is unavailable") from exc


def private_directory(path: Path, owner: int) -> tuple[int, int]:
    """Validate private directory and protected real ancestors; no initialization."""
    _absolute_path(str(path), "private state directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for index, component in enumerate(path.parts):
            if index:
                opened = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = opened
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner} or info.st_mode & 0o022:
                raise DeploymentError("state ancestors are not protected")
            if index == len(path.parts) - 1:
                if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
                    raise DeploymentError("state root must be assigned-account mode 0700")
                named = os.stat(path, follow_symlinks=False)
                if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                    raise DeploymentError("state root changed")
                return info.st_dev, info.st_ino
    finally:
        os.close(descriptor)
    raise DeploymentError("state directory unavailable")


def verify_account(deployment: Deployment) -> None:
    try:
        account = pwd.getpwnam(deployment.account_name)
        group = grp.getgrgid(deployment.controller_gid)
    except KeyError as exc:
        raise DeploymentError("dedicated account/group is absent") from exc
    accounts = pwd.getpwall()
    if (account.pw_uid != deployment.controller_uid or account.pw_gid != deployment.controller_gid
        or account.pw_dir != deployment.account_home or account.pw_shell not in {"/usr/bin/false", "/sbin/nologin"}
        or group.gr_name != deployment.account_name
        or any(member != deployment.account_name for member in group.gr_mem)
        or len([entry for entry in accounts if entry.pw_uid == deployment.controller_uid]) != 1
        or any(entry.pw_uid != deployment.controller_uid and entry.pw_gid == deployment.controller_gid for entry in accounts)):
        raise DeploymentError("dedicated account identity, private group, home or nonlogin shell differs")
    if any(entry.gr_gid != deployment.controller_gid and deployment.account_name in entry.gr_mem for entry in grp.getgrall()):
        raise DeploymentError("dedicated account has supplementary group membership")
    private_directory(Path(deployment.account_home), deployment.controller_uid)


def verify_deployment(deployment: Deployment, profile: DockerProfile) -> None:
    """Current passive bindings only; endpoint denial/limits still need live proof."""
    if type(deployment) is not Deployment or type(profile) is not DockerProfile:
        raise DeploymentError("validated deployment and profile objects are required")
    if os.geteuid() != 0 and (os.getuid() != deployment.controller_uid or os.geteuid() != deployment.controller_uid
        or os.getgid() != deployment.controller_gid or os.getegid() != deployment.controller_gid
        or any(group != deployment.controller_gid for group in os.getgroups())):
        raise DeploymentError("service process identity/groups differ from the dedicated account")
    current = load_deployment(deployment.source_path)
    if current.raw != deployment.raw:
        raise DeploymentError("deployment changed after loading")
    current_profile, _sha = read_root_protected(Path(deployment.profile_path), maximum=64 * 1024)
    if current_profile is None or parse_profile(current_profile) != profile:
        raise DeploymentError("protected profile changed after loading")
    policy, _sha = read_root_protected(Path(deployment.network_policy_path), maximum=256 * 1024)
    if policy is None or digest_bytes(policy) != profile.policy_digest:
        raise DeploymentError("root network policy descriptor differs from its profile pin")
    if (profile.controller_uid != deployment.controller_uid or profile.namespace != deployment.namespace
        or profile_basis_digest(profile) != deployment.profile_basis_digest):
        raise DeploymentError("deployment targets another protected profile")
    verify_account(deployment)
    for key in _PRIVATE_ROOTS:
        private_directory(Path(deployment.as_dict()[key]), deployment.controller_uid)
    verify_storage_paths(deployment)
    for name, pin in deployment.programs.items():
        _raw, observed = read_root_protected(Path(pin["path"]), maximum=256 * 1024 * 1024 if name == "python" else 1024 * 1024,
            capture=False, executable=name == "python")
        if observed != pin["sha256"]:
            raise DeploymentError("trusted deployment program pin changed")
    _raw, observed = read_root_protected(Path(profile.sbx_path), maximum=256 * 1024 * 1024, capture=False, executable=True)
    if observed != profile.sbx_sha256:
        raise DeploymentError("pinned Docker runtime changed")
    if protected_bundle_digest(Path(deployment.bundle_root)) != deployment.bundle_digest:
        raise DeploymentError("protected installed bundle changed")
    if not _within(profile.sbx_path, deployment.runtime_root) or protected_tree_digest(Path(deployment.runtime_root), runtime=True) != deployment.runtime_digest:
        raise DeploymentError("protected vendor runtime tree changed")


def verify_storage_paths(deployment: Deployment) -> None:
    """All mutable authority and project roots remain on the enrolled volume."""
    mount = Path(deployment.storage["mountPoint"])
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    paths = {Path(deployment.account_home), *(Path(deployment.as_dict()[key]) for key in _PRIVATE_ROOTS),
        *(Path(project[key]) for project in deployment.projects for key in ("repository", "workspaceRoot"))}
    device = None
    for selected in [mount, *sorted(paths)]:
        descriptor = os.open("/", flags)
        try:
            current = Path("/")
            for index, component in enumerate(selected.parts):
                if index:
                    opened = os.open(component, flags, dir_fd=descriptor)
                    os.close(descriptor); descriptor = opened
                    current /= component
                info = os.fstat(descriptor)
                if info.st_uid not in {0, deployment.controller_uid} or info.st_mode & 0o022:
                    raise DeploymentError("quota/project ancestors are not protected")
                if current == mount:
                    if device is None:
                        device = info.st_dev
                    elif info.st_dev != device:
                        raise DeploymentError("enrolled storage identity changed")
                if device is not None and _within(str(current), str(mount), equal=True) and info.st_dev != device:
                    raise DeploymentError("mutable state/project escapes the enrolled quota volume")
        finally:
            os.close(descriptor)


def protected_bundle_digest(root: Path) -> str:
    """Finite inventory of protected regular bytes; never imports project code."""
    return protected_tree_digest(root)


def protected_tree_digest(root: Path, *, runtime: bool = False) -> str:
    """Runtime links are relative, internal and pinned; source bundles have none."""
    _absolute_path(str(root), "bundle root")
    records = []; total = entries = 0
    def visit(path, relative=""):
        nonlocal total, entries
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise DeploymentError("bundle directory is unprotected")
            names = os.listdir(descriptor)
            if len(names) + len(records) > MAX_BUNDLE_FILES:
                raise DeploymentError("bundle entry limit exceeded")
            for name in sorted(names):
                entries += 1
                if entries > MAX_BUNDLE_FILES:
                    raise DeploymentError("bundle expanded directory/entry limit exceeded")
                if not name or name in {".", ".."} or "/" in name or any(ord(char) < 32 for char in name):
                    raise DeploymentError("unsupported bundle path")
                candidate = path / name
                selected = (relative + "/" + name).lstrip("/")
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    if len(Path(selected).parts) > 32:
                        raise DeploymentError("bundle directory depth exceeded")
                    visit(candidate, selected)
                elif stat.S_ISREG(metadata.st_mode):
                    _raw, sha = read_root_protected(candidate, maximum=(256 if runtime else 32) * 1024 * 1024, capture=False, allow_empty=True)
                    total += metadata.st_size
                    records.append({"path": selected, "size": metadata.st_size, "mode": stat.S_IMODE(metadata.st_mode), "sha256": sha})
                    if len(records) > MAX_BUNDLE_FILES or total > (1024 * 1024 * 1024 if runtime else MAX_BUNDLE_BYTES):
                        raise DeploymentError("bundle byte/entry limit exceeded")
                elif runtime and stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(name, dir_fd=descriptor)
                    lexical = os.path.normpath(str(candidate.parent / target))
                    if metadata.st_uid != 0 or target.startswith("/") or len(target) > 4096 or not _within(lexical, str(root)):
                        raise DeploymentError("runtime link escapes its pinned root")
                    records.append({"path": selected, "kind": "symlink", "target": target})
                else:
                    raise DeploymentError("bundle symlinks and special files are unsupported")
        finally:
            os.close(descriptor)
    visit(root)
    for record in records:
        if record.get("kind") == "symlink" and not _within(str((root / record["path"]).resolve(strict=True)), str(root)):
            raise DeploymentError("runtime link escapes its pinned root")
    if not records:
        raise DeploymentError("protected bundle is empty")
    records.sort(key=lambda record: record["path"])
    return canonical_digest(records)


def preparation_plan(deployment: Deployment) -> dict:
    """Concrete administrator review, without creating an OS user or service."""
    value = deployment.as_dict()
    user, uid, gid, home = deployment.account_name, deployment.controller_uid, deployment.controller_gid, deployment.account_home
    account_commands = [
        ["/usr/bin/dscl", ".", "-create", "/Groups/" + user],
        ["/usr/bin/dscl", ".", "-create", "/Groups/" + user, "PrimaryGroupID", str(gid)],
        ["/usr/bin/dscl", ".", "-create", "/Users/" + user],
        ["/usr/bin/dscl", ".", "-create", "/Users/" + user, "AuthenticationAuthority", ";DisabledUser;"],
        ["/usr/bin/dscl", ".", "-create", "/Users/" + user, "Password", "*"],
        ["/usr/bin/dscl", ".", "-create", "/Users/" + user, "UserShell", "/usr/bin/false"],
        ["/usr/bin/dscl", ".", "-create", "/Users/" + user, "UniqueID", str(uid)],
        ["/usr/bin/dscl", ".", "-create", "/Users/" + user, "PrimaryGroupID", str(gid)],
        ["/usr/bin/dscl", ".", "-create", "/Users/" + user, "NFSHomeDirectory", home],
        ["/usr/bin/dscl", ".", "-create", "/Users/" + user, "IsHidden", "1"],
    ]
    return {"schemaVersion": 1, "scope": "administrator-deployment-preparation", "deploymentDigest": deployment.digest,
        "qualified": False, "autonomousReady": False, "productionBackendAllowed": False,
        "accountCommands": account_commands,
        "accountPreconditions": ["Verify the account name, UID and GID are unused before every create; never modify an existing account.",
            "Create no password or login shell and grant no admin, wheel, Docker or supplementary groups.",
            "Independently validate disabled-account provisioning and every intermediate state on the exact macOS release; a false shell or hidden UI alone is not authentication disablement.",
            "Provision the complete account HOME on the dedicated APFS volume with the declared quota; verify volume UUID and quota before daemon bootstrap."],
        "privateDirectories": [{"path": value[key], "uid": uid, "gid": gid, "mode": "0700"} for key in ("accountHome", *_PRIVATE_ROOTS)],
        "protectedFiles": [str(deployment.source_path), deployment.profile_path, deployment.receipt_path, deployment.network_policy_path],
        "programArguments": [deployment.programs["python"]["path"], "-I", "-B", deployment.programs["runner"]["path"],
            "serve", "--deployment", str(deployment.source_path)],
        "serviceStartAllowed": False,
        "remaining": ["Install the reviewed pinned bundle/runtime as root under protected real ancestors.",
            "Bootstrap only the dedicated daemon before untrusted source; disable host integrations and bundled model server, then restart and capture actual settings.",
            "Run all mandatory live qualification methods with dummy principals, bounded pressure tests and an independent observer/watchdog.",
            "Issue root enrollment only after the semantic evidence verifier and current-account/endpoint/storage bindings all pass."]}
