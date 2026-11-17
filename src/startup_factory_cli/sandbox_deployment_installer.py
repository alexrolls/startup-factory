"""Install reviewed operational bytes without activating an unqualified service.

The administrator first provisions a dedicated nonlogin account, quota volume
and signed vendor runtime. This installer verifies those prerequisites, copies
only validated regular bundle members and writes unloaded launchd candidates.
It never creates accounts, formats disks, imports credentials, starts a daemon,
loads launchd jobs or writes a positive qualification receipt.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import plistlib
import stat
import tempfile

from .execution_backend import DockerProfile, canonical_digest
from .installer import BUNDLE_MANIFEST, MAX_ARCHIVE_BYTES, validate_bundle
from .sandbox_deployment import (
    Deployment, DeploymentError, canonical_bytes, digest_bytes, private_directory,
    read_root_protected, verify_account,
    protected_tree_digest,
)
from .sandbox_enrollment import profile_basis_digest
from .config_values import parse_config_bytes, value_for
from .secret_safety import contains_secret_like


def _bounded_input(path: Path, maximum: int) -> bytes:
    """One no-follow bounded regular snapshot; caller supplies a reviewed hash."""
    if not path.is_absolute() or ".." in path.parts:
        raise DeploymentError("installer input requires a normalized absolute path")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    try:
        for part in path.parts[1:-1]:
            opened = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory); directory = opened
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise DeploymentError("installer input is not a bounded single-link regular file")
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if len(raw) != before.st_size or stamp(before) != stamp(os.fstat(descriptor)) or stamp(before) != stamp(os.stat(path.name, dir_fd=directory, follow_symlinks=False)):
            raise DeploymentError("installer input changed during its snapshot")
        return bytes(raw)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def _directory(path: Path, *, create: bool, private_owner: tuple[int, int] | None = None) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for index, part in enumerate(path.parts[1:], 1):
            parent = os.fstat(descriptor)
            allowed = {0} if private_owner is None else {0, private_owner[0]}
            if parent.st_uid not in allowed or parent.st_mode & 0o022:
                raise DeploymentError("installation parent is not protected")
            if create:
                try:
                    os.mkdir(part, 0o700 if private_owner else 0o755, dir_fd=descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                    if private_owner:
                        os.fchown(child, *private_owner); os.fchmod(child, 0o700)
                    os.fsync(child); os.fsync(descriptor)
                except FileExistsError:
                    child = os.open(part, flags, dir_fd=descriptor)
            else:
                child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        info = os.fstat(descriptor)
        if private_owner:
            if info.st_uid != private_owner[0] or stat.S_IMODE(info.st_mode) != 0o700:
                raise DeploymentError("existing controller directory differs from its private owner/mode")
        elif info.st_uid != 0 or info.st_mode & 0o022:
            raise DeploymentError("existing installation directory is unprotected")
        result = descriptor; descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_fresh(path: Path, raw: bytes, mode: int = 0o444) -> None:
    parent = _directory(path.parent, create=True)
    descriptor = None
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:offset + 65536])
            if count <= 0:
                raise DeploymentError("incomplete protected installation")
            offset += count
        os.fchmod(descriptor, mode); os.fsync(descriptor); os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def launchd_candidates(deployment: Deployment) -> dict[str, bytes]:
    """Unloaded candidates; resource watchdog/enrollment remain mandatory."""
    result = {}
    for key, label in (("runner", "custody"), ("watchdog", "watchdog")):
        value = {"Label": "local.startup-factory." + deployment.namespace + "." + label,
            "ProgramArguments": [deployment.programs["python"]["path"], "-I", "-B", deployment.programs[key]["path"], "serve", "--deployment", str(deployment.source_path)],
            "UserName": deployment.account_name, "GroupName": deployment.account_name,
            "WorkingDirectory": "/", "Umask": 0o077, "RunAtLoad": False, "KeepAlive": False,
            "EnvironmentVariables": {"PATH": "/usr/bin:/bin", "HOME": deployment.account_home,
                "USER": deployment.account_name, "LOGNAME": deployment.account_name,
                "TMPDIR": deployment.account_home + "/tmp", "LANG": "C", "LC_ALL": "C", "SBX_NO_TELEMETRY": "1",
                "STARTUP_FACTORY_LIFECYCLE_STATE_ROOT": deployment.lifecycle_root},
            "StandardOutPath": deployment.account_home + "/logs/" + label + ".stdout.log",
            "StandardErrorPath": deployment.account_home + "/logs/" + label + ".stderr.log",
            "SoftResourceLimits": {"NumberOfFiles": 256, "NumberOfProcesses": 128, "FileSize": 16 * 1024 * 1024},
            "HardResourceLimits": {"NumberOfFiles": 256, "NumberOfProcesses": 128, "FileSize": 16 * 1024 * 1024}}
        result[value["Label"] + ".plist"] = plistlib.dumps(value, sort_keys=True)
    return result


def validate_release_configuration(payload: dict[str, bytes], deployment: Deployment) -> None:
    """Pin reviewed deployment-specific configuration before bundle hashing."""
    raw = payload.get("config/team.config.md")
    if type(raw) is not bytes or not 0 < len(raw) <= 1024 * 1024:
        raise DeploymentError("reviewed archive lacks bounded team configuration")
    config = parse_config_bytes(raw, "reviewed deployment team configuration")
    expected = {"AGENT_EXECUTION_BACKEND": "docker-sandboxes", "AGENT_SANDBOX_ENFORCED": "true",
        "AGENT_SANDBOX_DEPLOYMENT": str(deployment.source_path), "BROKER_LIFECYCLE_ROOT": deployment.lifecycle_root}
    if any(value_for(config, key) != value for key, value in expected.items()):
        raise DeploymentError("build a reviewed deployment-specific archive with enforced Docker backend, exact deployment path and lifecycle root before prepare-bundle; the default release configuration is not deployable")
    command = value_for(config, "SANDBOX_DEFAULT_CMD")
    if not command or "{prompt_file}" not in command or contains_secret_like(command):
        raise DeploymentError("reviewed archive requires a credential-free Linux SANDBOX_DEFAULT_CMD consuming {prompt_file}")


def prepare_bundle_pins(deployment: Deployment, profile: DockerProfile, archive_path: Path, *, archive_sha256: str) -> dict:
    """Snapshot/review the exact finite release; write no deployment/system path."""
    if deployment.controller_uid != profile.controller_uid or deployment.namespace != profile.namespace:
        raise DeploymentError("prepared profile/deployment account or namespace differs")
    snapshot = _bounded_input(archive_path, MAX_ARCHIVE_BYTES)
    if hashlib.sha256(snapshot).hexdigest() != archive_sha256:
        raise DeploymentError("reviewed operational archive SHA-256 differs")
    with tempfile.TemporaryDirectory(prefix="sf-bundle-review-") as temporary:
        selected = Path(temporary) / "reviewed.tar.gz"
        selected.write_bytes(snapshot)
        bundle = validate_bundle(selected, expected_sha256=archive_sha256)
    payload = dict(bundle.payload); payload[BUNDLE_MANIFEST] = bundle.manifest_bytes
    validate_release_configuration(payload, deployment)
    records = []
    for relative in sorted(payload):
        original = bundle.manifest.file_map.get(relative)
        records.append({"path": relative, "size": len(payload[relative]),
            "mode": 0o555 if original is not None and original.mode & 0o111 else 0o444,
            "sha256": hashlib.sha256(payload[relative]).hexdigest()})
    value = deployment.as_dict()
    value["bundleDigest"] = canonical_digest(records)
    value["profileBasisDigest"] = profile_basis_digest(profile)
    for key, pin in value["programs"].items():
        if key == "python":
            continue
        relative = str(Path(pin["path"]).relative_to(deployment.bundle_root))
        if relative not in payload:
            raise DeploymentError("the reviewed release lacks a required protected service program")
        pin["sha256"] = hashlib.sha256(payload[relative]).hexdigest()
    prepared = Deployment(deployment.source_path, canonical_bytes(value))
    return {"schemaVersion": 1, "scope": "reviewed-deployment-preparation", "qualified": False,
        "productionBackendAllowed": False, "preparedDeployment": value, "deploymentDigest": prepared.digest,
        "archiveSha256": archive_sha256, "installedBundleDigest": value["bundleDigest"], "files": len(records),
        "instruction": "Review and save exactly preparedDeployment; no system/account/service path has been changed."}


def prepare_runtime_pins(deployment: Deployment, profile: DockerProfile) -> dict:
    """Inventory an already administrator-installed runtime; execute no program."""
    if not profile.sbx_path.startswith(deployment.runtime_root + "/"):
        raise DeploymentError("profile runtime is outside the reviewed vendor application")
    _raw, sha = read_root_protected(Path(profile.sbx_path), maximum=256 * 1024 * 1024, executable=True, capture=False)
    if sha != profile.sbx_sha256:
        raise DeploymentError("vendor runtime differs from the independently reviewed release SHA-256")
    value = deployment.as_dict()
    value["runtimeDigest"] = protected_tree_digest(Path(deployment.runtime_root), runtime=True)
    _raw, python_sha = read_root_protected(Path(value["programs"]["python"]["path"]), maximum=256 * 1024 * 1024, executable=True, capture=False)
    value["programs"]["python"]["sha256"] = python_sha
    prepared = Deployment(deployment.source_path, canonical_bytes(value))
    return {"schemaVersion": 1, "scope": "reviewed-runtime-inventory", "qualified": False, "productionBackendAllowed": False,
        "preparedDeployment": value, "deploymentDigest": prepared.digest,
        "instruction": "Review this root-protected complete application inventory. Signature/notarization/platform/live gates remain mandatory."}


def install_prepared_bundle(deployment: Deployment, profile: DockerProfile, archive_path: Path, *, archive_sha256: str) -> dict:
    """Root-only first install into fresh destinations; never starts execution."""
    if os.geteuid() != 0:
        raise DeploymentError("administrator privileges are required to install protected deployment bytes")
    if profile_basis_digest(profile) != deployment.profile_basis_digest or profile.controller_uid != deployment.controller_uid or profile.namespace != deployment.namespace:
        raise DeploymentError("prepared profile differs from the reviewed deployment")
    if profile.qualification_digest != "sha256:" + "0" * 64:
        raise DeploymentError("first installation requires an explicitly unenrolled profile")
    verify_account(deployment)
    policy, _sha = read_root_protected(Path(deployment.network_policy_path), maximum=256 * 1024)
    if policy is None or digest_bytes(policy) != profile.policy_digest:
        raise DeploymentError("administrator-installed network policy descriptor differs from its reviewed pin")
    _raw, observed = read_root_protected(Path(profile.sbx_path), maximum=256 * 1024 * 1024, executable=True, capture=False)
    if observed != profile.sbx_sha256:
        raise DeploymentError("administrator-installed vendor runtime differs from its reviewed pin")
    if not profile.sbx_path.startswith(deployment.runtime_root + "/") or protected_tree_digest(Path(deployment.runtime_root), runtime=True) != deployment.runtime_digest:
        raise DeploymentError("administrator-installed complete runtime differs from its reviewed inventory")
    _raw, observed = read_root_protected(Path(deployment.programs["python"]["path"]), maximum=256 * 1024 * 1024, executable=True, capture=False)
    if observed != deployment.programs["python"]["sha256"]:
        raise DeploymentError("administrator-installed isolated Python differs from its reviewed pin")
    from .sandbox_qualification_observer import current_storage
    current_storage(deployment)  # actual mount UUID/quota, never a pressure-test pass
    snapshot = _bounded_input(archive_path, MAX_ARCHIVE_BYTES)
    if hashlib.sha256(snapshot).hexdigest() != archive_sha256:
        raise DeploymentError("reviewed operational archive SHA-256 differs")
    parent = _directory(Path(deployment.bundle_root).parent, create=False)
    try:
        # No adoption, overwrite, recursive chown or deletion of an old tree.
        os.mkdir(Path(deployment.bundle_root).name, 0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    staging = Path(deployment.bundle_root).parent / (".reviewed-bundle-" + hashlib.sha256(snapshot).hexdigest()[:16])
    _write_fresh(staging, snapshot, 0o400)
    bundle = validate_bundle(staging, expected_sha256=archive_sha256)
    payload = dict(bundle.payload)
    payload[BUNDLE_MANIFEST] = bundle.manifest_bytes
    validate_release_configuration(payload, deployment)
    records = []
    for relative in sorted(payload):
        raw = payload[relative]
        original = bundle.manifest.file_map.get(relative)
        mode = 0o555 if original is not None and original.mode & 0o111 else 0o444
        records.append({"path": relative, "size": len(raw), "mode": mode, "sha256": hashlib.sha256(raw).hexdigest()})
    if canonical_digest(records) != deployment.bundle_digest:
        raise DeploymentError("reviewed installed bundle inventory differs from its deployment pin")
    for key, pin in deployment.programs.items():
        if key == "python":
            continue
        relative = str(Path(pin["path"]).relative_to(deployment.bundle_root))
        if relative not in payload or hashlib.sha256(payload[relative]).hexdigest() != pin["sha256"]:
            raise DeploymentError("reviewed source program differs from its deployment pin")
    modes = {record["path"]: record["mode"] for record in records}
    for relative, raw in payload.items():
        _write_fresh(Path(deployment.bundle_root) / relative, raw, modes[relative])
    descriptor = _directory(Path(deployment.bundle_root), create=False)
    os.fchmod(descriptor, 0o755); os.fsync(descriptor); os.close(descriptor)
    for key in ("registryRoot", "nativeJournalRoot", "jobRoot", "watchdogRoot", "credentialRoot", "lifecycleRoot"):
        descriptor = _directory(Path(deployment.as_dict()[key]), create=True, private_owner=(deployment.controller_uid, deployment.controller_gid))
        os.close(descriptor)
    for relative in ("tmp", "logs"):
        descriptor = _directory(Path(deployment.account_home) / relative, create=True, private_owner=(deployment.controller_uid, deployment.controller_gid))
        os.close(descriptor)
    descriptor = _directory(Path(deployment.evidence_root), create=True)
    os.close(descriptor)
    _write_fresh(Path(deployment.profile_path), canonical_bytes(profile.as_dict()))
    _write_fresh(deployment.source_path, deployment.raw)
    for name, raw in launchd_candidates(deployment).items():
        _write_fresh(deployment.source_path.parent / "launchd" / name, raw, 0o600)
    return {"schemaVersion": 1, "scope": "protected-first-install", "deploymentDigest": deployment.digest,
        "bundleArchiveSha256": archive_sha256, "installedFiles": len(payload), "qualified": False,
        "autonomousReady": False, "productionBackendAllowed": False, "servicesStarted": False,
        "note": "Account, APFS volume and signed vendor runtime were preexisting administrator prerequisites. Launchd candidates remain unloaded; all live gates are still required."}
