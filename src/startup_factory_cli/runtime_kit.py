"""Preview-first provisioning for the protected agent runtime profile."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import inspect
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

from .installer import InstallerError, verify_installation
from .readiness import secure_runtime_checks
from .runtime_proof import normalize_runtime_proofs


SCHEMA_VERSION = 1
PROFILE = "rootless-podman-5"
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONFIG_KEYS = (
    "TASK_WORKTREE_MODE",
    "BROKER_TASK_CLONE_ROOT",
    "BROKER_AGENT_OUTBOX_ROOT",
    "AGENT_SANDBOX_RUNNER",
    "AGENT_SANDBOX_ENFORCED",
    "BROKER_LIFECYCLE_ROOT",
    "AGENT_RUNTIME_MANIFEST",
)
ASSIGNMENT = re.compile(r"(?m)^(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>[^\r\n]*)(?P<newline>\r?\n|\Z)")
MAX_ENGINE_OUTPUT = 256 * 1024


class PathSafetyError(InstallerError):
    """A no-follow path identity check failed; durable evidence must survive."""


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _strict_object(content: bytes, label: str) -> dict[str, Any]:
    def pairs(rows: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise InstallerError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(content, object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as exc:
        raise InstallerError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise InstallerError(f"{label} must be a JSON object")
    return value


@dataclasses.dataclass(frozen=True)
class FileState:
    exists: bool
    device: int | None = None
    inode: int | None = None
    mode: int | None = None
    owner: int | None = None
    links: int | None = None
    size: int | None = None
    digest: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class PlannedFile:
    path: Path
    content: bytes
    mode: int
    state: FileState

    def change(self) -> dict[str, Any] | None:
        if self.state.exists and self.state.digest == _sha256(self.content) and self.state.mode == self.mode:
            return None
        return {
            "path": str(self.path),
            "action": "write",
            "mode": f"0{self.mode:o}",
            "sha256": _sha256(self.content),
            "before": self.state.as_dict(),
        }


@dataclasses.dataclass(frozen=True)
class RuntimePlan:
    target: Path
    project: Path
    runtime_root: Path
    clone_root: Path
    lifecycle_root: Path
    outbox_root: Path
    engine: Path
    image: str
    network: str
    files: tuple[PlannedFile, ...]
    config_path: Path
    config_before: bytes
    config_after: bytes
    config_state: FileState
    plan_digest: str
    installation_digest: str
    engine_proof: Mapping[str, Any]
    image_proof: Mapping[str, Any]
    namespace_pre_states: tuple[Mapping[str, Any], ...]

    @property
    def changes(self) -> list[dict[str, Any]]:
        changes = [change for item in self.files if (change := item.change()) is not None]
        if self.config_before != self.config_after:
            changes.append(
                {
                    "path": str(self.config_path),
                    "action": "byte-preserving-config-update",
                    "mode": f"0{self.config_state.mode or 0:o}",
                    "sha256": _sha256(self.config_after),
                    "before": self.config_state.as_dict(),
                    "keys": list(CONFIG_KEYS),
                }
            )
        for directory in (self.runtime_root, self.clone_root, self.lifecycle_root, self.outbox_root):
            if not _path_lexists_nofollow(directory, "runtime plan directory"):
                changes.insert(0, {"path": str(directory), "action": "mkdir", "mode": "0700"})
        return changes

    def as_dict(self, *, applied: bool) -> dict[str, Any]:
        checks = secure_runtime_checks(configured=True, manifest=str(self.files[-1].path))
        return {
            "ok": True,
            "action": "runtime-kit",
            "schemaVersion": SCHEMA_VERSION,
            "profile": PROFILE,
            "applied": applied,
            "planDigest": self.plan_digest,
            "installationDigest": self.installation_digest,
            "readiness": "configured_unproved",
            "ready": False,
            "runtimeRoot": str(self.runtime_root),
            "cloneRoot": str(self.clone_root),
            "lifecycleRoot": str(self.lifecycle_root),
            "outboxRoot": str(self.outbox_root),
            "changes": [] if applied and not self.changes else self.changes,
            "checks": [check.as_dict() for check in checks],
            "remediation": "Run authenticated launcher doctor and external boundary attestation; fixed probes never promote readiness.",
        }


@dataclasses.dataclass(frozen=True)
class RuntimeRecoveryPlan:
    target: Path
    runtime_root: Path
    lock: Path
    journal: Path
    action: str
    phase: str
    transaction_token: str
    plan_digest: str
    installation_digest: str
    lock_content: bytes
    journal_content: bytes | None
    journal_value: Mapping[str, Any] | None
    recovery_digest: str

    def as_dict(self, *, applied: bool) -> dict[str, Any]:
        return {
            "ok": True,
            "action": "runtime-kit-recovery",
            "schemaVersion": 1,
            "applied": applied,
            "ready": False,
            "readiness": "configured_unproved",
            "runtimeRoot": str(self.runtime_root),
            "transactionPhase": self.phase,
            "recoveryAction": self.action,
            "planDigest": self.plan_digest,
            "installationDigest": self.installation_digest,
            "recoveryDigest": self.recovery_digest,
            "remediation": (
                "Apply only this exact recovery with --recover --apply --plan-digest "
                f"{self.recovery_digest}; foreign or changed evidence remains preserved."
                if not applied
                else "Recovery completed without promoting readiness; rerun runtime-kit preview and doctor."
            ),
        }


def _normalized_absolute(path: Path, label: str) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise InstallerError(f"{label} must be an absolute normalized path")
    return path


def _components(path: Path) -> list[Path]:
    current = Path(path.anchor)
    result = [current]
    for part in path.parts[1:]:
        current /= part
        result.append(current)
    return result


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise PathSafetyError("runtime-kit requires descriptor-relative no-follow directory operations")
    return os.O_RDONLY | nofollow | directory


def _path_safety_error(label: str, path: Path) -> PathSafetyError:
    return PathSafetyError(
        f"{label} has an unsafe or substituted path component: {path}; preserve any runtime-kit "
        "lock, journal, and substituted path, inspect the mismatch, restore the exact caller-owned "
        "non-symlink path, then rerun --recover to obtain a new recovery digest"
    )


def _inspect_existing_components(path: Path, label: str) -> bool:
    path = _normalized_absolute(path, label)
    flags = _directory_open_flags()
    descriptor = os.open(path.anchor, flags)
    current = Path(path.anchor)
    try:
        parts = path.parts[1:]
        if not parts:
            return True
        for index, part in enumerate(parts):
            current /= part
            try:
                info = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise _path_safety_error(label, current) from exc
            if stat.S_ISLNK(info.st_mode):
                raise _path_safety_error(label, current)
            if index == len(parts) - 1:
                return True
            if not stat.S_ISDIR(info.st_mode):
                raise _path_safety_error(label, current)
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise _path_safety_error(label, current) from exc
            child_info = os.fstat(child)
            if (child_info.st_dev, child_info.st_ino) != (info.st_dev, info.st_ino):
                os.close(child)
                raise _path_safety_error(label, current)
            os.close(descriptor)
            descriptor = child
    finally:
        os.close(descriptor)


def _validate_existing_components(path: Path, label: str) -> None:
    _inspect_existing_components(path, label)


def _path_lexists_nofollow(path: Path, label: str) -> bool:
    return _inspect_existing_components(path, label)


def _open_directory_nofollow(path: Path, label: str) -> int:
    path = _normalized_absolute(path, label)
    flags = _directory_open_flags()
    descriptor = os.open(path.anchor, flags)
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise _path_safety_error(label, current) from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _disjoint(first: Path, second: Path, labels: str) -> None:
    if _is_within(first, second) or _is_within(second, first):
        raise InstallerError(f"runtime paths must be disjoint ({labels})")


def _read_regular(path: Path, label: str, maximum: int = 2 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise InstallerError(f"{label} requires secure no-follow opens")
    path = _normalized_absolute(path, label)
    parent = _open_directory_nofollow(path.parent, label)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | nofollow, dir_fd=parent)
    except OSError as exc:
        os.close(parent)
        raise InstallerError(f"cannot open {label}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise InstallerError(f"{label} must be a bounded regular file")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > maximum:
            raise InstallerError(f"{label} is too large")
        return bytes(chunks), info
    finally:
        os.close(descriptor)
        os.close(parent)


def _state(path: Path, *, maximum: int = 2 * 1024 * 1024) -> FileState:
    if not _path_lexists_nofollow(path, str(path)):
        return FileState(False)
    content, info = _read_regular(path, str(path), maximum)
    return FileState(
        True,
        info.st_dev,
        info.st_ino,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_nlink,
        info.st_size,
        _sha256(content),
    )


def _validate_protected_executable(path: Path) -> tuple[Path, bytes]:
    path = _normalized_absolute(path, "Podman executable")
    content, info = _read_regular(path, "Podman executable", 128 * 1024 * 1024)
    if info.st_uid not in {0, os.geteuid()}:
        raise InstallerError("Podman executable must be owned by root or the invoking broker")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise InstallerError("Podman executable must not be group/other writable")
    if not info.st_mode & 0o111:
        raise InstallerError("Podman executable must be executable")
    return path, content


def _engine_json(engine: Path, argv: list[str], label: str) -> dict[str, Any] | list[Any]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "XDG_RUNTIME_DIR": f"/run/user/{os.geteuid()}",
    }
    try:
        result = subprocess.run(
            [str(engine), *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            env=environment,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallerError(f"cannot obtain {label} proof from protected Podman") from exc
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_ENGINE_OUTPUT:
        raise InstallerError(f"protected Podman returned invalid {label} proof")
    try:
        return json.loads(result.stdout, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeError, ValueError) as exc:
        raise InstallerError(f"protected Podman returned malformed {label} JSON") from exc


def _reject_duplicate_pairs(rows: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in rows:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _prove_engine(engine: Path, image: str) -> tuple[dict[str, Any], dict[str, Any]]:
    info = _engine_json(engine, ["info", "--format", "json"], "rootless engine")
    inspected = _engine_json(engine, ["image", "inspect", "--format", "json", image], "local image")
    def fail(message: str):
        raise InstallerError(message)

    return normalize_runtime_proofs(info, inspected, image, fail)


def _assignments(raw: bytes) -> tuple[str, dict[str, re.Match[str]], str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise InstallerError("team configuration is not valid UTF-8") from exc
    found: dict[str, re.Match[str]] = {}
    for match in ASSIGNMENT.finditer(text):
        key = match.group("key")
        if key in found:
            raise InstallerError(f"team configuration contains duplicate exact key: {key}")
        found[key] = match
    newline = "\r\n" if "\r\n" in text else "\n"
    return text, found, newline


def _render_config(raw: bytes, updates: Mapping[str, str]) -> bytes:
    text, found, newline = _assignments(raw)
    tracker = found.get("TRACKER_WRITERS")
    if tracker is None or tracker.group("value").split("#", 1)[0].strip().strip('"') != "broker":
        raise InstallerError("runtime-kit requires TRACKER_WRITERS=broker and never weakens it")
    edits: list[tuple[int, int, str]] = []
    missing: list[str] = []
    for key, value in updates.items():
        match = found.get(key)
        if match is None:
            missing.append(f"{key}={value}{newline}")
        else:
            current = match.group("value")
            suffix = ""
            if " #" in current:
                suffix = current[current.index(" #") :]
            edits.append((match.start("value"), match.end("value"), value + suffix))
    for start, end, value in sorted(edits, reverse=True):
        text = text[:start] + value + text[end:]
    if missing:
        if text and not text.endswith(("\n", "\r")):
            text += newline
        text += "".join(missing)
    return text.encode()


def _render_runner(template: bytes, values: Mapping[bytes, str]) -> bytes:
    placeholder = re.compile(rb"@@[A-Z][A-Z0-9_]*@@")
    found = placeholder.findall(template)
    if set(found) != set(values) or any(found.count(token) != 1 for token in set(found)):
        raise InstallerError("runtime runner template placeholder inventory changed")
    rendered: dict[bytes, bytes] = {}
    for token, value in values.items():
        if any(ord(character) < 32 for character in value):
            raise InstallerError("runtime runner binding contains a control character")
        quoted = "'" + value.replace("'", "'\"'\"'") + "'"
        rendered[token] = quoted.encode()
    return placeholder.sub(lambda match: rendered[match.group(0)], template)


def _render_proof_helper(template: bytes) -> tuple[bytes, bytes]:
    token = b"@@NORMALIZE_RUNTIME_PROOFS_PY@@"
    if template.count(token) != 1:
        raise InstallerError("runtime runner proof-helper placeholder inventory changed")
    source = inspect.getsource(normalize_runtime_proofs).encode("utf-8")
    return template.replace(token, source), source


def _plan_material(plan: dict[str, Any]) -> str:
    return _sha256(_canonical_json(plan))


def plan_runtime_kit(
    *,
    target: Path,
    project: Path,
    runtime_root: Path,
    engine: Path,
    image: str,
    network: str = "none",
    host_platform: str | None = None,
) -> RuntimePlan:
    if (host_platform or sys.platform) != "linux":
        raise InstallerError(
            "native macOS runtime-kit apply/preview is unsupported; rerun inside a protected Linux guest and pass its external paths"
        )
    verify_installation(target)
    project = project.resolve(strict=True)
    target = target.resolve(strict=True)
    runtime_root = _normalized_absolute(runtime_root, "runtime root")
    _validate_existing_components(runtime_root, "runtime root")
    _disjoint(runtime_root, project, "runtime root/project")
    _disjoint(runtime_root, target, "runtime root/installed skill")
    parent = runtime_root.parent
    _validate_existing_components(parent, "runtime root parent")
    parent_info = parent.stat()
    if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o077:
        raise InstallerError("runtime root parent must be caller-owned and mode 0700 or stricter")
    clone_root = runtime_root / "attempt-clones"
    lifecycle_root = runtime_root / "lifecycle"
    outbox_root = runtime_root / "outbox-ingress"
    for directory, label in (
        (runtime_root, "runtime root"),
        (clone_root, "clone root"),
        (lifecycle_root, "lifecycle root"),
        (outbox_root, "outbox root"),
        (runtime_root / "assets", "runtime assets root"),
    ):
        if _path_lexists_nofollow(directory, label):
            _validate_private_directory(directory, label)
    namespace_pre_states = tuple(_runtime_namespace_states(runtime_root))
    if _path_lexists_nofollow(
        runtime_root / ".runtime-kit.lock", "runtime-kit lock"
    ) or _path_lexists_nofollow(
        runtime_root / ".runtime-kit-journal.json", "runtime-kit journal"
    ):
        _validate_recovery_evidence(
            runtime_root / ".runtime-kit.lock", runtime_root / ".runtime-kit-journal.json"
        )
    engine, engine_bytes = _validate_protected_executable(engine)
    if not IMAGE.fullmatch(image):
        raise InstallerError("runtime image must be pinned as repository@sha256:<64 lowercase hex>")
    if network != "none":
        raise InstallerError("networked agents require a named external attested egress policy; this kit supports network=none only")
    engine_proof, image_proof = _prove_engine(engine, image)

    runner_template, _ = _read_regular(target / "runtime/runner-linux-container.sh", "runner template")
    policy, _ = _read_regular(target / "runtime/container-policy.json", "container policy")
    network_policy, _ = _read_regular(target / "runtime/network-policy-none.json", "network policy")
    policy_obj = _strict_object(policy, "container policy")
    if policy_obj.get("profile") != PROFILE or policy_obj.get("schemaVersion") != 1:
        raise InstallerError("installed container policy has an unsupported profile")
    runner_source = runner_template
    runner_template, proof_helper = _render_proof_helper(runner_source)
    source_digest = _sha256(runner_source + policy + network_policy)
    implementation_digest = _sha256(runner_source + proof_helper + policy + network_policy)
    version_name = "v1-" + implementation_digest.split(":", 1)[1][:16]
    asset_root = runtime_root / "assets" / version_name
    manifest_path = asset_root / "runtime-manifest.json"
    policy_path = asset_root / "container-policy.json"
    network_path = asset_root / "network-policy.json"
    runner_path = asset_root / "runner"
    runner = _render_runner(
        runner_template,
        {
            b"@@ENGINE@@": str(engine),
            b"@@IMAGE@@": image,
            b"@@MANIFEST@@": str(manifest_path),
            b"@@NETWORK@@": network,
            b"@@PROFILE@@": PROFILE,
            b"@@CLONE_ROOT@@": str(clone_root),
            b"@@OUTBOX_ROOT@@": str(outbox_root),
            b"@@SKILL_ROOT@@": str(target),
            b"@@POLICY@@": str(policy_path),
            b"@@NETWORK_POLICY@@": str(network_path),
            b"@@ENGINE_SHA256@@": _sha256(engine_bytes).split(":", 1)[1],
            b"@@ENGINE_PROOF_SHA256@@": _sha256(_canonical_json(engine_proof)).split(":", 1)[1],
            b"@@IMAGE_PROOF_SHA256@@": _sha256(_canonical_json(image_proof)).split(":", 1)[1],
            b"@@SOURCE_ASSETS_SHA256@@": source_digest.split(":", 1)[1],
        },
    )
    manifest = {
        "schemaVersion": 2,
        "profile": PROFILE,
        "sourceAssetsSha256": source_digest,
        "engine": {"path": str(engine), "sha256": _sha256(engine_bytes), "proofSha256": _sha256(_canonical_json(engine_proof))},
        "image": {"reference": image, "proofSha256": _sha256(_canonical_json(image_proof)), "pull": "never"},
        "runner": {"path": str(runner_path), "sha256": _sha256(runner)},
        "policy": {"path": str(policy_path), "sha256": _sha256(policy)},
        "network": {"name": "none", "path": str(network_path), "sha256": _sha256(network_policy)},
        "cloneRoot": str(clone_root),
        "lifecycleRoot": str(lifecycle_root),
        "outboxRoot": str(outbox_root),
        "skillRoot": str(target),
        "readiness": "configured_unproved",
        "capabilities": {"autonomousDelivery": False, "productionDelivery": False},
    }
    manifest_bytes = _canonical_json(manifest)
    planned = (
        PlannedFile(policy_path, policy, 0o600, _state(policy_path)),
        PlannedFile(network_path, network_policy, 0o600, _state(network_path)),
        PlannedFile(runner_path, runner, 0o700, _state(runner_path)),
        PlannedFile(manifest_path, manifest_bytes, 0o600, _state(manifest_path)),
    )
    for item in planned:
        if item.state.exists and (item.state.digest != _sha256(item.content) or item.state.mode != item.mode):
            raise InstallerError(f"stale or operator-modified runtime asset refuses overwrite: {item.path}")
    config_path = target / "config/team.config.md"
    config_before, config_info = _read_regular(config_path, "team configuration")
    config_state = FileState(
        True, config_info.st_dev, config_info.st_ino, stat.S_IMODE(config_info.st_mode),
        config_info.st_uid, config_info.st_nlink, config_info.st_size, _sha256(config_before),
    )
    config_after = _render_config(
        config_before,
        {
            "TASK_WORKTREE_MODE": "standalone-clone",
            "BROKER_TASK_CLONE_ROOT": str(clone_root),
            "BROKER_AGENT_OUTBOX_ROOT": str(outbox_root),
            "AGENT_SANDBOX_RUNNER": str(asset_root / "runner"),
            "AGENT_SANDBOX_ENFORCED": "true",
            "BROKER_LIFECYCLE_ROOT": str(lifecycle_root),
            "AGENT_RUNTIME_MANIFEST": str(manifest_path),
        },
    )
    material = {
        "schemaVersion": 1,
        "target": str(target),
        "project": str(project),
        "runtimeRoot": str(runtime_root),
        "cloneRoot": str(clone_root),
        "lifecycleRoot": str(lifecycle_root),
        "outboxRoot": str(outbox_root),
        "engine": str(engine),
        "engineSha256": _sha256(engine_bytes),
        "engineProofSha256": _sha256(_canonical_json(engine_proof)),
        "image": image,
        "imageProofSha256": _sha256(_canonical_json(image_proof)),
        "network": network,
        "namespacePreStates": list(namespace_pre_states),
        "files": [
            {"path": str(item.path), "mode": item.mode, "sha256": _sha256(item.content), "before": item.state.as_dict()}
            for item in planned
        ],
        "config": {"path": str(config_path), "before": config_state.as_dict(), "afterSha256": _sha256(config_after)},
    }
    desired = {
        "schemaVersion": 1,
        "profile": PROFILE,
        "runtimeRoot": str(runtime_root),
        "engineSha256": _sha256(engine_bytes),
        "engineProofSha256": _sha256(_canonical_json(engine_proof)),
        "image": image,
        "imageProofSha256": _sha256(_canonical_json(image_proof)),
        "files": [
            {"path": str(item.path), "mode": item.mode, "sha256": _sha256(item.content)}
            for item in planned
        ],
        "configAfterSha256": _sha256(config_after),
    }
    return RuntimePlan(
        target, project, runtime_root, clone_root, lifecycle_root, outbox_root, engine, image, network,
        planned, config_path, config_before, config_after, config_state, _plan_material(material),
        _plan_material(desired),
        engine_proof, image_proof, namespace_pre_states,
    )


def _fsync_directory(path: Path) -> None:
    descriptor = _open_directory_nofollow(path, "runtime transaction directory")
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir_chain(
    path: Path,
    created: list[Path],
    on_created: Any | None = None,
) -> None:
    path = _normalized_absolute(path, "runtime transaction directory")
    flags = _directory_open_flags()
    descriptor = os.open(path.anchor, flags)
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            created_here = False
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    created_here = True
                    os.fsync(descriptor)
                except FileExistsError:
                    # A concurrent creator or substituted path must still pass
                    # the pinned-parent no-follow open below.
                    pass
                except OSError as exc:
                    raise _path_safety_error("runtime transaction directory", current) from exc
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except OSError as exc:
                    raise _path_safety_error("runtime transaction directory", current) from exc
            except OSError as exc:
                raise _path_safety_error("runtime transaction directory", current) from exc
            child_info = os.fstat(child)
            if not stat.S_ISDIR(child_info.st_mode):
                os.close(child)
                raise _path_safety_error("runtime transaction directory", current)
            os.close(descriptor)
            descriptor = child
            if created_here:
                created.append(current)
                if on_created is not None:
                    on_created()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_private_directory(path: Path, label: str) -> None:
    _validate_existing_components(path, label)
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallerError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_nlink < 1
    ):
        raise PathSafetyError(
            f"{label} must be an exact caller-owned, non-symlink mode-0700 directory; preserve "
            "any durable lock, journal, and unexpected namespace for operator recovery"
        )


def _write_exclusive(path: Path, content: bytes, mode: int) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise InstallerError("runtime transaction requires secure no-follow writes")
    parent = _open_directory_nofollow(path.parent, "runtime transaction file parent")
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                mode,
                dir_fd=parent,
            )
        except OSError as exc:
            raise _path_safety_error("runtime transaction file", path) from exc
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _replace_same_parent(source: Path, destination: Path, label: str) -> None:
    if source.parent != destination.parent:
        raise PathSafetyError(f"{label} replacement paths do not share one pinned parent")
    parent = _open_directory_nofollow(destination.parent, f"{label} parent")
    try:
        try:
            os.replace(
                source.name,
                destination.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
            )
        except OSError as exc:
            raise _path_safety_error(label, destination) from exc
        os.fsync(parent)
    finally:
        os.close(parent)


def _identity_matches(path: Path, state: FileState) -> bool:
    try:
        current = _state(path)
    except InstallerError:
        return False
    return current == state


def _replace_config(plan: RuntimePlan) -> None:
    if plan.config_before == plan.config_after:
        return
    if not _identity_matches(plan.config_path, plan.config_state):
        raise InstallerError("team configuration changed after preview; rerun runtime-kit preview")
    temporary = plan.config_path.with_name(f".{plan.config_path.name}.runtime-kit.{os.getpid()}.{secrets.token_hex(8)}")
    try:
        _write_exclusive(temporary, plan.config_after, plan.config_state.mode or 0o600)
        if not _identity_matches(plan.config_path, plan.config_state):
            raise InstallerError("team configuration changed while runtime-kit was preparing")
        _replace_same_parent(temporary, plan.config_path, "team configuration")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _owned_transaction_content(path: Path, label: str) -> bytes:
    content, info = _read_regular(path, label, 1024 * 1024)
    if (
        info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise InstallerError(f"{label} must be a caller-owned, single-link mode-0600 file")
    return content


def _validate_recovery_evidence(lock: Path, journal: Path) -> None:
    """Fail closed on every incomplete transaction, including no-op retries."""

    present = [
        path
        for path, label in ((lock, "runtime-kit lock"), (journal, "runtime-kit journal"))
        if _path_lexists_nofollow(path, label)
    ]
    if not present:
        return
    details: list[str] = []
    for path, label in ((lock, "runtime-kit lock"), (journal, "runtime-kit journal")):
        if not _path_lexists_nofollow(path, label):
            details.append(f"{label} is missing")
            continue
        try:
            content = _owned_transaction_content(path, label)
            value = _strict_object(content, label)
            token = value.get("transactionToken")
            phase = value.get("phase")
            if (
                value.get("schemaVersion") != 3
                or not isinstance(token, str)
                or not re.fullmatch(r"[0-9a-f]{64}", token)
                or phase not in {"locked", "prepared", "assets-written", "config-replaced", "commit-marked"}
            ):
                raise InstallerError(f"{label} has an unsupported recovery schema")
            details.append(f"{label} records phase {phase}")
        except InstallerError as exc:
            details.append(str(exc))
    raise InstallerError(
        "incomplete runtime-kit recovery state requires the explicit recovery preview "
        "(rerun the same runtime-kit command with --recover); " + "; ".join(details)
    )


def _state_from_record(value: Any, label: str) -> FileState:
    names = {field.name for field in dataclasses.fields(FileState)}
    if not isinstance(value, dict) or set(value) != names or type(value.get("exists")) is not bool:
        raise InstallerError(f"{label} has an invalid file-state record")
    state = FileState(**value)
    if not state.exists:
        if any(getattr(state, name) is not None for name in names - {"exists"}):
            raise InstallerError(f"{label} absent state contains unexpected metadata")
        return state
    if (
        any(type(getattr(state, name)) is not int for name in ("device", "inode", "mode", "owner", "links", "size"))
        or state.links != 1
        or state.owner != os.geteuid()
        or state.size is None
        or state.size < 0
        or not isinstance(state.digest, str)
        or DIGEST.fullmatch(state.digest) is None
    ):
        raise InstallerError(f"{label} existing state is unsafe")
    return state


def _directory_recovery_state(path: Path) -> dict[str, Any]:
    if not _path_lexists_nofollow(path, "runtime recovery directory"):
        return {"exists": False}
    parent = _open_directory_nofollow(path.parent, "runtime recovery directory parent")
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        raise _path_safety_error("runtime recovery directory", path) from exc
    finally:
        os.close(parent)
    if stat.S_ISDIR(info.st_mode):
        kind = "directory"
    elif stat.S_ISREG(info.st_mode):
        kind = "regular"
    elif stat.S_ISFIFO(info.st_mode):
        kind = "fifo"
    elif stat.S_ISSOCK(info.st_mode):
        kind = "socket"
    else:
        kind = "other"
    return {
        "exists": True,
        "type": kind,
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "owner": info.st_uid,
        "links": info.st_nlink,
    }


def _runtime_namespace_states(runtime_root: Path) -> list[dict[str, Any]]:
    return [
        {"path": str(path), "state": _directory_recovery_state(path)}
        for path in (
            runtime_root / "assets",
            runtime_root / "attempt-clones",
            runtime_root / "lifecycle",
            runtime_root / "outbox-ingress",
        )
    ]


def _directory_state_from_record(value: Any, label: str) -> dict[str, Any]:
    if value == {"exists": False}:
        return {"exists": False}
    required = {"exists", "type", "device", "inode", "mode", "owner", "links"}
    if not isinstance(value, dict) or set(value) != required or value.get("exists") is not True:
        raise InstallerError(f"{label} has an invalid directory-state record")
    if (
        value.get("type") != "directory"
        or any(type(value.get(name)) is not int for name in ("device", "inode", "mode", "owner", "links"))
        or value["device"] < 0
        or value["inode"] < 1
        or value["mode"] != 0o700
        or value["owner"] != os.geteuid()
        or value["links"] < 1
    ):
        raise InstallerError(
            f"{label} must bind an exact caller-owned mode-0700 directory identity"
        )
    return dict(value)


def _namespace_record_map(value: Any, runtime_root: Path, label: str) -> dict[Path, dict[str, Any]]:
    expected_paths = (
        runtime_root / "assets",
        runtime_root / "attempt-clones",
        runtime_root / "lifecycle",
        runtime_root / "outbox-ingress",
    )
    if not isinstance(value, list) or len(value) != len(expected_paths):
        raise InstallerError(f"{label} must contain every reserved runtime namespace exactly once")
    result: dict[Path, dict[str, Any]] = {}
    for record in value:
        if not isinstance(record, dict) or set(record) != {"path", "state"}:
            raise InstallerError(f"{label} contains a malformed namespace record")
        path = Path(str(record["path"]))
        if path not in expected_paths or path in result:
            raise InstallerError(f"{label} contains an unknown or duplicate namespace path")
        result[path] = _directory_state_from_record(record["state"], f"{label} {path}")
    if set(result) != set(expected_paths):
        raise InstallerError(f"{label} is incomplete")
    return result


def _created_directory_records(value: Any, runtime_root: Path) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 32:
        raise InstallerError("runtime-kit created-directory recovery record is malformed")
    result: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for record in value:
        if not isinstance(record, dict) or set(record) != {"path", "state"}:
            raise InstallerError("runtime-kit created-directory recovery record is malformed")
        path = Path(str(record["path"]))
        if (
            not path.is_absolute()
            or path in seen
            or (path != runtime_root and not _is_within(path, runtime_root))
        ):
            raise InstallerError("runtime-kit created-directory recovery path escapes runtime root")
        state = _directory_state_from_record(record["state"], f"created runtime directory {path}")
        if not state["exists"]:
            raise InstallerError("created runtime directory cannot bind an absent state")
        result.append({"path": str(path), "state": state})
        seen.add(path)
    return result


def _validate_created_directory_identities(
    value: Any, runtime_root: Path
) -> list[dict[str, Any]]:
    records = _created_directory_records(value, runtime_root)
    for record in records:
        path = Path(record["path"])
        current = _directory_recovery_state(path)
        if current != record["state"]:
            raise InstallerError(
                f"runtime recovery transaction-created directory mismatch at {path}; the lock, "
                "journal, and unexpected namespace were preserved. Restore the exact recorded "
                "caller-owned mode-0700 directory identity, then rerun --recover for a new digest"
            )
    return records


def _namespace_mismatch(path: Path, expected: Mapping[str, Any], observed: Mapping[str, Any]) -> InstallerError:
    return InstallerError(
        "runtime recovery reserved namespace mismatch at "
        f"{path}: expected {dict(expected)}, observed {dict(observed)}; the lock, journal, and "
        "unexpected namespace were preserved. Inspect the mismatch, restore the exact recorded "
        "caller-owned mode-0700 directory identity (or remove an unexpected namespace only after "
        "independent verification), then rerun --recover for a new digest"
    )


def _validate_current_namespaces(expected_value: Any, runtime_root: Path, label: str) -> None:
    expected = _namespace_record_map(expected_value, runtime_root, label)
    observed = {
        Path(record["path"]): record["state"]
        for record in _runtime_namespace_states(runtime_root)
    }
    for path, expected_state in expected.items():
        current = observed[path]
        if current != expected_state:
            raise _namespace_mismatch(path, expected_state, current)


def _authorized_namespace_states(
    pre_value: Any, runtime_root: Path, created_directories: Iterable[Path]
) -> list[dict[str, Any]]:
    pre = _namespace_record_map(pre_value, runtime_root, "runtime plan namespace pre-states")
    current_records = _runtime_namespace_states(runtime_root)
    current = {Path(record["path"]): record["state"] for record in current_records}
    created = set(created_directories)
    identity_fields = ("exists", "type", "device", "inode", "mode", "owner")
    for path, pre_state in pre.items():
        observed = current[path]
        if path in created:
            try:
                _directory_state_from_record(observed, f"transaction-created namespace {path}")
            except InstallerError as exc:
                raise PathSafetyError(str(exc)) from exc
            continue
        if not pre_state["exists"]:
            if observed != pre_state:
                raise PathSafetyError(str(_namespace_mismatch(path, pre_state, observed)))
            continue
        direct_children = sum(1 for value in created if value.parent == path)
        expected_links = pre_state["links"] + direct_children
        if (
            any(observed.get(name) != pre_state.get(name) for name in identity_fields)
            or observed.get("links") != expected_links
        ):
            raise PathSafetyError(str(_namespace_mismatch(path, pre_state, observed)))
    return current_records


def _recovery_material(
    *,
    target: Path,
    runtime_root: Path,
    lock_content: bytes,
    journal_content: bytes | None,
    journal_value: Mapping[str, Any] | None,
    action: str,
    phase: str,
) -> dict[str, Any]:
    current: dict[str, Any] = {
        "lockSha256": _sha256(lock_content),
        "journalSha256": None if journal_content is None else _sha256(journal_content),
        "config": None,
        "files": [],
        "commitMarker": None,
        "directories": [],
        "runtimeNamespaces": _runtime_namespace_states(runtime_root),
    }
    if journal_value is not None:
        config_path = Path(str(journal_value["configPath"]))
        current["config"] = _state(config_path).as_dict()
        for record in journal_value["files"]:
            current["files"].append({"path": record["path"], "state": _state(Path(record["path"])).as_dict()})
        marker = runtime_root / (
            ".runtime-kit-committed-" + str(journal_value["installationDigest"]).split(":", 1)[1]
        )
        current["commitMarker"] = {"path": str(marker), "state": _state(marker).as_dict()}
        current["directories"] = [
            {"path": record["path"], "state": _directory_recovery_state(Path(record["path"]))}
            for record in journal_value["createdDirectories"]
        ]
    return {
        "schemaVersion": 1,
        "target": str(target),
        "runtimeRoot": str(runtime_root),
        "action": action,
        "phase": phase,
        "evidence": current,
    }


def plan_runtime_recovery(*, target: Path, runtime_root: Path) -> RuntimeRecoveryPlan:
    """Build an immutable recovery preview from exact durable transaction evidence."""

    target = target.resolve(strict=True)
    runtime_root = _normalized_absolute(runtime_root, "runtime root")
    _validate_existing_components(runtime_root, "runtime root")
    # Even a lock-only crash reserves these names. A substituted symlink must
    # block preview before the lock can be cleared and become part of the exact
    # recovery digest when safely absent or present.
    _runtime_namespace_states(runtime_root)
    lock = runtime_root / ".runtime-kit.lock"
    journal = runtime_root / ".runtime-kit-journal.json"
    journal_present = _path_lexists_nofollow(journal, "runtime-kit journal")
    if not _path_lexists_nofollow(lock, "runtime-kit lock"):
        if journal_present:
            raise InstallerError("runtime recovery journal has no matching lock and is preserved for operator inspection")
        raise InstallerError("runtime-kit recovery found no unresolved lock/journal")
    lock_content = _owned_transaction_content(lock, "runtime-kit lock")
    try:
        lock_value = _strict_object(lock_content, "runtime-kit lock")
    except InstallerError as exc:
        raise InstallerError("runtime-kit lock is malformed or foreign and was preserved") from exc
    required_lock = {
        "schemaVersion", "phase", "transactionToken", "ownerPid", "planDigest",
        "installationDigest", "namespaceStates",
    }
    if (
        set(lock_value) != required_lock
        or lock_value.get("schemaVersion") != 3
        or lock_value.get("phase") != "locked"
        or re.fullmatch(r"[0-9a-f]{64}", str(lock_value.get("transactionToken") or "")) is None
        or type(lock_value.get("ownerPid")) is not int
        or lock_value["ownerPid"] < 1
        or DIGEST.fullmatch(str(lock_value.get("planDigest") or "")) is None
        or DIGEST.fullmatch(str(lock_value.get("installationDigest") or "")) is None
    ):
        raise InstallerError("runtime-kit lock is malformed or foreign and was preserved")
    if not journal_present:
        _validate_current_namespaces(
            lock_value["namespaceStates"], runtime_root, "runtime-kit lock namespace states"
        )
    try:
        os.kill(lock_value["ownerPid"], 0)
    except ProcessLookupError:
        pass
    except (PermissionError, OSError) as exc:
        raise InstallerError(
            "runtime-kit transaction owner cannot be safely proved dead; lock was preserved"
        ) from exc
    else:
        raise InstallerError("runtime-kit transaction owner is still active; lock was preserved")
    token = str(lock_value["transactionToken"])
    journal_content: bytes | None = None
    journal_value: dict[str, Any] | None = None
    action = "clear-lock"
    phase = "locked"
    if journal_present:
        journal_content = _owned_transaction_content(journal, "runtime-kit journal")
        try:
            journal_value = _strict_object(journal_content, "runtime-kit journal")
        except InstallerError as exc:
            raise InstallerError(
                "runtime-kit journal is malformed or foreign and was preserved"
            ) from exc
        required_journal = {
            "schemaVersion", "phase", "transactionToken", "ownerPid", "planDigest", "installationDigest",
            "configPath", "configBefore", "configBeforeState", "configAfterSha256", "files",
            "createdDirectories", "namespacePreStates", "namespaceStates",
        }
        phase = str(journal_value.get("phase") or "")
        if (
            set(journal_value) != required_journal
            or journal_value.get("schemaVersion") != 3
            or phase not in {"prepared", "assets-written", "config-replaced", "commit-marked"}
            or journal_value.get("transactionToken") != token
            or journal_value.get("ownerPid") != lock_value["ownerPid"]
            or journal_value.get("planDigest") != lock_value["planDigest"]
            or journal_value.get("installationDigest") != lock_value["installationDigest"]
            or journal_value.get("namespacePreStates") != lock_value["namespaceStates"]
            or DIGEST.fullmatch(str(journal_value.get("configAfterSha256") or "")) is None
        ):
            raise InstallerError("runtime-kit journal is malformed, foreign, or does not match its lock; evidence was preserved")
        config_path = Path(str(journal_value["configPath"]))
        expected_config = target / "config/team.config.md"
        if config_path != expected_config or not config_path.is_absolute():
            raise InstallerError("runtime-kit recovery config path is outside the installed target")
        before_state = _state_from_record(journal_value["configBeforeState"], "runtime-kit config pre-state")
        try:
            before_content = base64.b64decode(str(journal_value["configBefore"]), validate=True)
        except (ValueError, TypeError) as exc:
            raise InstallerError("runtime-kit config pre-image is malformed") from exc
        if not before_state.exists or before_state.digest != _sha256(before_content) or before_state.size != len(before_content):
            raise InstallerError("runtime-kit config pre-image does not match its recorded digest")
        files = journal_value.get("files")
        if not isinstance(files, list) or len(files) != 4:
            raise InstallerError("runtime-kit recovery requires exactly four runtime assets")
        seen_paths: set[Path] = set()
        for record in files:
            if not isinstance(record, dict) or set(record) != {"path", "before", "afterMode", "afterSha256"}:
                raise InstallerError("runtime-kit recovery asset record is malformed")
            path = Path(str(record["path"]))
            if (
                not path.is_absolute()
                or path in seen_paths
                or not _is_within(path, runtime_root / "assets")
                or type(record["afterMode"]) is not int
                or record["afterMode"] not in {0o600, 0o700}
                or DIGEST.fullmatch(str(record["afterSha256"])) is None
            ):
                raise InstallerError("runtime-kit recovery asset identity is unsafe")
            _state_from_record(record["before"], f"runtime-kit asset pre-state {path}")
            seen_paths.add(path)
        _namespace_record_map(
            journal_value["namespacePreStates"], runtime_root, "runtime-kit namespace pre-states"
        )
        _validate_current_namespaces(
            journal_value["namespaceStates"], runtime_root, "runtime-kit journal namespace states"
        )
        _validate_created_directory_identities(
            journal_value.get("createdDirectories"), runtime_root
        )
        action = "finalize-commit" if phase == "commit-marked" else "rollback"
        current_config = _state(config_path)
        if current_config.digest not in {before_state.digest, journal_value["configAfterSha256"]}:
            raise InstallerError("runtime recovery config matches neither recorded pre-image nor post-image; evidence was preserved")
        all_after = current_config.digest == journal_value["configAfterSha256"]
        for record in files:
            path = Path(record["path"])
            before = _state_from_record(record["before"], f"runtime-kit asset pre-state {path}")
            current_state = _state(path)
            matches_before = current_state == before
            matches_after = bool(
                current_state.exists
                and current_state.digest == record["afterSha256"]
                and current_state.mode == record["afterMode"]
                and current_state.owner == os.geteuid()
                and current_state.links == 1
            )
            if not matches_before and not matches_after:
                raise InstallerError("runtime recovery asset matches neither recorded pre-state nor post-image; evidence was preserved")
            all_after = all_after and matches_after
        marker = runtime_root / (
            ".runtime-kit-committed-" + str(journal_value["installationDigest"]).split(":", 1)[1]
        )
        marker_exact = False
        if _path_lexists_nofollow(marker, "runtime-kit commit marker"):
            marker_content = _owned_transaction_content(marker, "runtime-kit commit marker")
            marker_value = _strict_object(marker_content, "runtime-kit commit marker")
            marker_exact = marker_value == {
                "schemaVersion": 1,
                "installationDigest": journal_value["installationDigest"],
                "appliedPlanDigest": journal_value["planDigest"],
            }
            if not marker_exact:
                raise InstallerError("runtime recovery commit marker is not exact; evidence was preserved")
        if action == "finalize-commit" and (not all_after or not marker_exact):
            raise InstallerError("commit-marked recovery is incomplete or changed; evidence was preserved")
    material = _recovery_material(
        target=target,
        runtime_root=runtime_root,
        lock_content=lock_content,
        journal_content=journal_content,
        journal_value=journal_value,
        action=action,
        phase=phase,
    )
    recovery_digest = _sha256(_canonical_json(material))
    return RuntimeRecoveryPlan(
        target,
        runtime_root,
        lock,
        journal,
        action,
        phase,
        token,
        str(lock_value["planDigest"]),
        str(lock_value["installationDigest"]),
        lock_content,
        journal_content,
        journal_value,
        recovery_digest,
    )


def _unlink_exact(path: Path, expected: bytes, label: str) -> None:
    if _owned_transaction_content(path, label) != expected:
        raise InstallerError(f"{label} changed after recovery preview and was preserved")
    path.unlink()
    _fsync_directory(path.parent)


def _rmdir_created_exact(record: Mapping[str, Any], runtime_root: Path) -> None:
    path = Path(str(record["path"]))
    expected = _directory_state_from_record(
        record["state"], f"transaction-created runtime directory {path}"
    )
    current = _directory_recovery_state(path)
    identity_fields = ("exists", "type", "device", "inode", "mode", "owner")
    if any(current.get(name) != expected.get(name) for name in identity_fields):
        raise InstallerError(
            f"transaction-created runtime directory identity changed before cleanup at {path}; "
            "the lock and journal were preserved. Restore the exact recorded identity and rerun "
            "--recover for a new digest"
        )
    if type(current.get("links")) is not int or not (1 <= current["links"] <= expected["links"]):
        raise InstallerError(
            f"transaction-created runtime directory link state changed before cleanup at {path}; "
            "the lock and journal were preserved. Inspect the directory and rerun --recover only "
            "after restoring the recorded namespace"
        )
    parent = _open_directory_nofollow(path.parent, "runtime recovery directory parent")
    try:
        try:
            os.rmdir(path.name, dir_fd=parent)
        except OSError as exc:
            raise InstallerError(
                f"transaction-created runtime directory is not empty or removable at {path}; "
                "the lock and journal were preserved for operator inspection"
            ) from exc
        os.fsync(parent)
    finally:
        os.close(parent)


def recover_runtime_kit(plan: RuntimeRecoveryPlan, *, expected_recovery_digest: str) -> None:
    if expected_recovery_digest != plan.recovery_digest or DIGEST.fullmatch(expected_recovery_digest) is None:
        raise InstallerError("--plan-digest must exactly match the current immutable recovery preview")
    current = plan_runtime_recovery(target=plan.target, runtime_root=plan.runtime_root)
    if current.recovery_digest != plan.recovery_digest:
        raise InstallerError("runtime recovery evidence or affected state changed after preview")
    if plan.action == "clear-lock":
        _unlink_exact(plan.lock, plan.lock_content, "runtime-kit lock")
        try:
            plan.runtime_root.rmdir()
        except OSError:
            pass
        return
    assert plan.journal_content is not None and plan.journal_value is not None
    journal = dict(plan.journal_value)
    marker = plan.runtime_root / f".runtime-kit-committed-{plan.installation_digest.split(':', 1)[1]}"
    if plan.action == "finalize-commit":
        config = _state(Path(str(journal["configPath"])))
        if config.digest != journal["configAfterSha256"]:
            raise InstallerError("committed runtime recovery config post-image changed; evidence was preserved")
        for record in journal["files"]:
            state = _state(Path(record["path"]))
            if (
                state.digest != record["afterSha256"]
                or state.mode != record["afterMode"]
                or state.owner != os.geteuid()
                or state.links != 1
            ):
                raise InstallerError("committed runtime recovery asset changed; evidence was preserved")
        marker_content = _owned_transaction_content(marker, "runtime-kit commit marker")
        marker_value = _strict_object(marker_content, "runtime-kit commit marker")
        if marker_value != {
            "schemaVersion": 1,
            "installationDigest": plan.installation_digest,
            "appliedPlanDigest": plan.plan_digest,
        }:
            raise InstallerError("committed runtime recovery marker is not exact; evidence was preserved")
        _unlink_exact(plan.journal, plan.journal_content, "runtime-kit journal")
        _unlink_exact(plan.lock, plan.lock_content, "runtime-kit lock")
        return
    config_path = Path(str(journal["configPath"]))
    config_before = base64.b64decode(str(journal["configBefore"]), validate=True)
    config_before_state = _state_from_record(journal["configBeforeState"], "runtime-kit config pre-state")
    current_config = _state(config_path)
    if current_config.digest == journal["configAfterSha256"]:
        temporary = config_path.with_name(f".{config_path.name}.recovery.{os.getpid()}.{secrets.token_hex(8)}")
        _write_exclusive(temporary, config_before, config_before_state.mode or 0o600)
        _replace_same_parent(temporary, config_path, "runtime recovery configuration")
    elif current_config.digest != config_before_state.digest:
        raise InstallerError("runtime recovery config matches neither exact pre-image nor post-image; evidence was preserved")
    for record in reversed(journal["files"]):
        path = Path(record["path"])
        before = _state_from_record(record["before"], f"runtime-kit asset pre-state {path}")
        current_state = _state(path)
        if before.exists:
            if current_state != before:
                raise InstallerError("pre-existing runtime asset changed during recovery; evidence was preserved")
            continue
        if current_state.exists:
            if (
                current_state.digest != record["afterSha256"]
                or current_state.mode != record["afterMode"]
                or current_state.owner != os.geteuid()
                or current_state.links != 1
            ):
                raise InstallerError("created runtime asset changed during recovery; evidence was preserved")
            path.unlink()
            _fsync_directory(path.parent)
    if _path_lexists_nofollow(marker, "runtime-kit commit marker"):
        marker_content = _owned_transaction_content(marker, "runtime-kit commit marker")
        marker_value = _strict_object(marker_content, "runtime-kit commit marker")
        if marker_value != {
            "schemaVersion": 1,
            "installationDigest": plan.installation_digest,
            "appliedPlanDigest": plan.plan_digest,
        }:
            raise InstallerError("runtime recovery commit marker changed; evidence was preserved")
        marker.unlink()
        _fsync_directory(marker.parent)
    created_records = _created_directory_records(journal["createdDirectories"], plan.runtime_root)
    runtime_root_record: Mapping[str, Any] | None = None
    for record in reversed(created_records):
        if Path(record["path"]) == plan.runtime_root:
            runtime_root_record = record
            continue
        _rmdir_created_exact(record, plan.runtime_root)
    _unlink_exact(plan.journal, plan.journal_content, "runtime-kit journal")
    _unlink_exact(plan.lock, plan.lock_content, "runtime-kit lock")
    if runtime_root_record is not None:
        _rmdir_created_exact(runtime_root_record, plan.runtime_root)


def _replace_owned_transaction_file(path: Path, before: bytes, after: bytes) -> None:
    if _owned_transaction_content(path, "runtime-kit journal") != before:
        raise InstallerError("runtime-kit journal changed during the transaction")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}")
    try:
        _write_exclusive(temporary, after, 0o600)
        if _owned_transaction_content(path, "runtime-kit journal") != before:
            raise InstallerError("runtime-kit journal changed before phase advancement")
        _replace_same_parent(temporary, path, "runtime-kit journal")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _commit_marker_content(plan: RuntimePlan) -> bytes:
    return _canonical_json(
        {
            "schemaVersion": 1,
            "installationDigest": plan.installation_digest,
            "appliedPlanDigest": plan.plan_digest,
        }
    )


def _verify_commit_marker(plan: RuntimePlan) -> None:
    marker = plan.runtime_root / f".runtime-kit-committed-{plan.installation_digest.split(':', 1)[1]}"
    content = _owned_transaction_content(marker, "runtime-kit commit marker")
    value = _strict_object(content, "runtime-kit commit marker")
    if (
        value.get("schemaVersion") != 1
        or value.get("installationDigest") != plan.installation_digest
        or not DIGEST.fullmatch(str(value.get("appliedPlanDigest") or ""))
    ):
        raise InstallerError("runtime-kit commit marker does not bind the installed profile")


def apply_runtime_kit(plan: RuntimePlan, *, expected_plan_digest: str) -> None:
    if expected_plan_digest != plan.plan_digest or not DIGEST.fullmatch(expected_plan_digest):
        raise InstallerError("--plan-digest must exactly match the current immutable preview")
    if sys.platform != "linux":
        raise InstallerError("runtime-kit apply is refused on Darwin; rerun inside a protected Linux guest")
    lock = plan.runtime_root / ".runtime-kit.lock"
    journal = plan.runtime_root / ".runtime-kit-journal.json"
    _validate_recovery_evidence(lock, journal)
    # A fresh preview over an already applied, byte-identical profile is an
    # idempotent no-op only when durable completion evidence is intact.
    if not plan.changes:
        _verify_commit_marker(plan)
        return
    created_dirs: list[Path] = []
    created_files: list[PlannedFile] = []
    config_replaced = False
    lock_created = False
    journal_created = False
    token = secrets.token_hex(32)
    lock_content = _canonical_json(
        {
            "schemaVersion": 3,
            "phase": "locked",
            "transactionToken": token,
            "ownerPid": os.getpid(),
            "planDigest": plan.plan_digest,
            "installationDigest": plan.installation_digest,
            "namespaceStates": list(plan.namespace_pre_states),
        }
    )
    journal_value = {
        "schemaVersion": 3,
        "phase": "prepared",
        "transactionToken": token,
        "ownerPid": os.getpid(),
        "planDigest": plan.plan_digest,
        "installationDigest": plan.installation_digest,
        "configPath": str(plan.config_path),
        "configBefore": base64.b64encode(plan.config_before).decode("ascii"),
        "configBeforeState": plan.config_state.as_dict(),
        "configAfterSha256": _sha256(plan.config_after),
        "files": [
            {
                "path": str(item.path),
                "before": item.state.as_dict(),
                "afterMode": item.mode,
                "afterSha256": _sha256(item.content),
            }
            for item in plan.files
        ],
        "createdDirectories": [],
        "namespacePreStates": list(plan.namespace_pre_states),
        "namespaceStates": list(plan.namespace_pre_states),
    }
    journal_content = _canonical_json(journal_value)

    def advance(phase: str) -> None:
        nonlocal journal_content
        journal_value["phase"] = phase
        journal_value["createdDirectories"] = [
            {"path": str(path), "state": _directory_recovery_state(path)}
            for path in created_dirs
        ]
        journal_value["namespaceStates"] = _authorized_namespace_states(
            list(plan.namespace_pre_states), plan.runtime_root, created_dirs
        )
        updated = _canonical_json(journal_value)
        _replace_owned_transaction_file(journal, journal_content, updated)
        journal_content = updated

    def persist_directory_identities() -> None:
        advance(str(journal_value["phase"]))

    try:
        _mkdir_chain(plan.runtime_root, created_dirs)
        _validate_private_directory(plan.runtime_root, "runtime root")
        _validate_current_namespaces(
            list(plan.namespace_pre_states), plan.runtime_root, "runtime plan namespace states"
        )
        _write_exclusive(lock, lock_content, 0o600)
        lock_created = True
        _write_exclusive(journal, journal_content, 0o600)
        journal_created = True
        persist_directory_identities()
        for directory in (plan.clone_root, plan.lifecycle_root, plan.outbox_root, plan.files[0].path.parent):
            _mkdir_chain(directory, created_dirs, persist_directory_identities)
            _validate_private_directory(directory, "runtime transaction directory")
        for item in plan.files:
            if item.state.exists:
                if not _identity_matches(item.path, item.state):
                    raise InstallerError(f"runtime asset changed after preview: {item.path}")
                continue
            _write_exclusive(item.path, item.content, item.mode)
            created_files.append(item)
        advance("assets-written")
        config_replaced = plan.config_before != plan.config_after
        _replace_config(plan)
        advance("config-replaced")
        committed = plan.runtime_root / f".runtime-kit-committed-{plan.installation_digest.split(':', 1)[1]}"
        committed_content = _commit_marker_content(plan)
        _write_exclusive(committed, committed_content, 0o600)
        created_files.append(PlannedFile(committed, committed_content, 0o600, FileState(False)))
        advance("commit-marked")
        if _owned_transaction_content(lock, "runtime-kit lock") != lock_content:
            raise InstallerError("runtime-kit lock changed before commit")
        if _owned_transaction_content(journal, "runtime-kit journal") != journal_content:
            raise InstallerError("runtime-kit journal changed before commit")
        lock.unlink()
        lock_created = False
        journal.unlink()
        journal_created = False
        _fsync_directory(plan.runtime_root)
    except BaseException as original:
        if isinstance(original, PathSafetyError) and (lock_created or journal_created):
            raise InstallerError(
                "runtime-kit detected an unsafe path substitution after durable transaction evidence; "
                "the lock, journal, and substituted path were preserved. Inspect the recorded paths, "
                "restore the exact caller-owned non-symlink namespace, then run --recover for a new "
                "digest-bound recovery preview"
            ) from original
        rollback_errors: list[str] = []
        if config_replaced:
            try:
                current, _ = _read_regular(plan.config_path, "team configuration")
                if current == plan.config_before:
                    pass
                elif _sha256(current) != _sha256(plan.config_after):
                    raise InstallerError("team configuration no longer matches transaction post-image")
                else:
                    temporary = plan.config_path.with_name(f".{plan.config_path.name}.rollback.{os.getpid()}")
                    _write_exclusive(temporary, plan.config_before, plan.config_state.mode or 0o600)
                    _replace_same_parent(temporary, plan.config_path, "runtime rollback configuration")
            except BaseException as exc:
                rollback_errors.append(str(exc))
        for item in reversed(created_files):
            try:
                state = _state(item.path)
                if state.digest != _sha256(item.content):
                    raise InstallerError(f"created asset changed and was preserved: {item.path}")
                item.path.unlink()
                _fsync_directory(item.path.parent)
            except BaseException as exc:
                rollback_errors.append(str(exc))
        if lock_created:
            try:
                if _owned_transaction_content(lock, "runtime-kit lock") != lock_content:
                    raise InstallerError("runtime-kit lock changed and was preserved")
                lock.unlink()
                lock_created = False
            except BaseException as exc:
                rollback_errors.append(str(exc))
        if journal_created:
            try:
                if _owned_transaction_content(journal, "runtime-kit journal") != journal_content:
                    raise InstallerError("runtime-kit journal changed and was preserved")
                journal.unlink()
                journal_created = False
            except BaseException as exc:
                rollback_errors.append(str(exc))
        if not rollback_errors:
            try:
                for directory in reversed(created_dirs):
                    directory.rmdir()
            except OSError:
                pass
        message = "runtime-kit transaction failed"
        if rollback_errors:
            message += "; rollback requires operator recovery: " + "; ".join(rollback_errors)
        raise InstallerError(message) from original


def probe_runtime_kit(plan: RuntimePlan) -> dict[str, Any]:
    """Execute fixed controls; observations never promote configured readiness."""

    if plan.changes:
        raise InstallerError("runtime-kit probe requires the exact applied profile with no pending changes")
    _verify_commit_marker(plan)
    token = secrets.token_hex(8)
    sentinel = plan.runtime_root / f".runtime-probe-host-sentinel-{token}"
    sibling_parent = plan.clone_root / "runtime-probe-sibling"
    sibling = sibling_parent / f"probe#1-{token}"
    _write_exclusive(sentinel, b"must remain outside the agent mount\n", 0o600)
    _mkdir_chain(sibling, [])
    _validate_private_directory(sibling, "probe sibling workspace")
    base = subprocess.run(
        ["/usr/bin/git", "-C", str(plan.project), "rev-parse", "HEAD"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
        check=False,
    )
    if base.returncode or not re.fullmatch(r"[0-9a-f]{40,64}\n?", base.stdout):
        raise InstallerError("runtime-kit probe cannot bind the project HEAD")
    branch = f"agent-runtime/runtime-probe/{token}"
    helper = plan.target / "bin/standalone_workspace.py"
    created = subprocess.run(
        [
            "/usr/bin/python3", str(helper), "create", "--repo", str(plan.project),
            "--root", str(plan.clone_root), "--team", "runtime-probe", "--role", "probe",
            "--attempt", "1", "--task-key", token, "--branch", branch,
            "--base-ref", base.stdout.strip(),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        check=False,
    )
    if created.returncode:
        detail = created.stderr.decode("utf-8", errors="replace").strip()[:512]
        raise InstallerError(
            "runtime-kit probe could not create its standalone clone"
            + (f": {detail}" if detail else "")
        )
    try:
        clone_data = _strict_object(created.stdout, "probe clone identity")
        clone = Path(str(clone_data.get("path") or ""))
        git_common = subprocess.run(
            ["/usr/bin/git", "-C", str(plan.project), "rev-parse", "--git-common-dir"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
            check=False,
        )
        if git_common.returncode:
            raise InstallerError("runtime-kit probe cannot locate protected broker state")
        common = Path(git_common.stdout.strip())
        if not common.is_absolute():
            common = plan.project / common
        broker_state = common.resolve(strict=True) / "startup-factory-broker"
        runner = plan.files[-2].path
        environment = {
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/tmp",
            "STARTUP_FACTORY_AGENT_WORKTREE": str(clone),
            "STARTUP_FACTORY_SKILL_ROOT": str(plan.target),
            "STARTUP_FACTORY_ROLE": "runtime-probe",
            "STARTUP_FACTORY_TEAM": "runtime-probe",
            "STARTUP_FACTORY_FEATURE_ID": "runtime-probe",
            "STARTUP_FACTORY_PRESET": "deep-infra",
            "STARTUP_FACTORY_EXECUTION_KIND": "doctor",
            "STARTUP_FACTORY_TASK_ID": "-",
            "STARTUP_FACTORY_ATTEMPT": "0",
        }
        observed = subprocess.run(
            [
                str(runner), "--workdir", str(clone), "--", "/usr/bin/python3",
                str(plan.target / "bin/runtime-probe-agent.py"), "--workdir", str(clone),
                "--host-sentinel", str(sentinel), "--canonical-repo", str(plan.project),
                "--broker-state", str(broker_state), "--lifecycle-state", str(plan.lifecycle_root),
                "--sibling-workspace", str(sibling),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            env=environment,
            check=False,
        )
        if observed.returncode or observed.stderr or len(observed.stdout) > MAX_ENGINE_OUTPUT:
            detail = observed.stderr.decode("utf-8", errors="replace").strip()[:512]
            raise InstallerError(
                "runtime-kit fixed boundary controls failed" + (f": {detail}" if detail else "")
            )
        observations = _strict_object(observed.stdout, "runtime probe observations")
        denials = observations.get("denials")
        if (
            observations.get("schemaVersion") != 1
            or observations.get("worktreeWrite") is not True
            or re.fullmatch(r"[0-9a-f]{40,64}", str(observations.get("standaloneGitCommit") or "")) is None
            or not isinstance(denials, dict)
            or set(denials)
            != {
                "hostSentinel", "canonicalRepo", "brokerState", "lifecycleState",
                "siblingWorkspace", "loopbackNetwork", "metadataNetwork",
            }
            or not all(value is True for value in denials.values())
        ):
            raise InstallerError("runtime-kit fixed boundary observations are incomplete or failed")
        retired = subprocess.run(
            [
                "/usr/bin/python3", str(helper), "retire", "--repo", str(plan.project),
                "--root", str(plan.clone_root), "--clone", str(clone), "--branch", branch,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
            check=False,
        )
        if retired.returncode:
            raise InstallerError("runtime-kit probe observations passed but disposable clone retirement failed")
        sentinel.unlink()
        sibling.rmdir()
        sibling_parent.rmdir()
    except BaseException:
        # Failed observations remain available for operator inspection. A probe
        # never uses broad cleanup to hide evidence or promote readiness.
        raise
    evidence = {
        "schemaVersion": 1,
        "profile": PROFILE,
        "readinessEffect": "none",
        "planDigest": plan.plan_digest,
        "engineProofSha256": _sha256(_canonical_json(plan.engine_proof)),
        "imageProofSha256": _sha256(_canonical_json(plan.image_proof)),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "mounts": ["standalone-attempt-clone", "read-only-installed-tools"],
        "network": plan.network,
        "observations": observations,
        "result": "fixed-controls-passed-non-promoting",
    }
    evidence["evidenceDigest"] = _sha256(_canonical_json(evidence))
    return evidence
