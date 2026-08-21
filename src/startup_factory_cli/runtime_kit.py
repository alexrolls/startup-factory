"""Preview-first provisioning for the protected agent runtime profile."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
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
            if not directory.exists():
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


def _validate_existing_components(path: Path, label: str) -> None:
    for component in _components(path):
        if not os.path.lexists(component):
            break
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise InstallerError(f"{label} contains a symlink: {component}")
        if component != path and not stat.S_ISDIR(info.st_mode):
            raise InstallerError(f"{label} parent is not a directory: {component}")


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
    _validate_existing_components(path, label)
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except OSError as exc:
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


def _state(path: Path, *, maximum: int = 2 * 1024 * 1024) -> FileState:
    if not os.path.lexists(path):
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
    if not isinstance(info, dict):
        raise InstallerError("Podman info proof must be an object")
    version = info.get("version")
    host = info.get("host")
    security = host.get("security") if isinstance(host, dict) else None
    mappings = host.get("idMappings") if isinstance(host, dict) else None
    version_text = version.get("Version") if isinstance(version, dict) else None
    try:
        major = int(str(version_text).split(".", 1)[0])
    except (TypeError, ValueError):
        major = 0
    if major != 5 or not isinstance(security, dict) or security.get("rootless") is not True:
        raise InstallerError("runtime-kit requires machine-proved rootless Podman major version 5")
    def valid_mapping(rows: Any) -> bool:
        return bool(
            isinstance(rows, list)
            and rows
            and all(
                isinstance(row, dict)
                and set(row) == {"container_id", "host_id", "size"}
                and all(type(row[key]) is int and row[key] >= 0 for key in ("container_id", "host_id"))
                and type(row["size"]) is int
                and row["size"] > 0
                for row in rows
            )
            and any(row["container_id"] == 0 for row in rows)
        )

    if (
        not isinstance(mappings, dict)
        or set(mappings) != {"uidmap", "gidmap"}
        or not valid_mapping(mappings.get("uidmap"))
        or not valid_mapping(mappings.get("gidmap"))
    ):
        raise InstallerError("rootless Podman proof is missing UID/GID namespace mappings")
    inspected = _engine_json(engine, ["image", "inspect", "--format", "json", image], "local image")
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise InstallerError("Podman image proof must contain exactly one local image")
    repo_digests = inspected[0].get("RepoDigests")
    if not isinstance(repo_digests, list) or image not in repo_digests:
        raise InstallerError("local Podman image digest does not match the requested pinned image")
    image_id = inspected[0].get("Id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise InstallerError("local Podman image proof has an invalid image identity")
    normalized_engine = {
        "version": version_text,
        "rootless": True,
        "uidmap": mappings["uidmap"],
        "gidmap": mappings["gidmap"],
    }
    normalized_image = {"Id": image_id, "RepoDigests": sorted(set(repo_digests))}
    return normalized_engine, normalized_image


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
    content = template
    for token, value in values.items():
        if any(ord(character) < 32 for character in value):
            raise InstallerError("runtime runner binding contains a control character")
        quoted = "'" + value.replace("'", "'\"'\"'") + "'"
        content = content.replace(token, quoted.encode())
    if b"@@" in content:
        raise InstallerError("runtime runner template contains an unresolved placeholder")
    return content


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
    source_digest = _sha256(runner_template + policy + network_policy)
    version_name = "v1-" + source_digest.split(":", 1)[1][:16]
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
        engine_proof, image_proof,
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir_chain(path: Path, created: list[Path]) -> None:
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        created.append(directory)
        _fsync_directory(directory.parent)
    for directory in _components(path)[1:]:
        if directory.exists() and _is_within(directory, path.parent.parent):
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise InstallerError(f"runtime transaction directory became unsafe: {directory}")


def _validate_private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallerError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise InstallerError(f"{label} must be a caller-owned, non-symlink mode-0700 directory")


def _write_exclusive(path: Path, content: bytes, mode: int) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise InstallerError("runtime transaction requires secure no-follow writes")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _fsync_directory(path.parent)


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
        os.replace(temporary, plan.config_path)
        _fsync_directory(plan.config_path.parent)
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

    present = [path for path in (lock, journal) if os.path.lexists(path)]
    if not present:
        return
    details: list[str] = []
    for path, label in ((lock, "runtime-kit lock"), (journal, "runtime-kit journal")):
        if not os.path.lexists(path):
            details.append(f"{label} is missing")
            continue
        try:
            content = _owned_transaction_content(path, label)
            value = _strict_object(content, label)
            token = value.get("transactionToken")
            phase = value.get("phase")
            if (
                value.get("schemaVersion") != 2
                or not isinstance(token, str)
                or not re.fullmatch(r"[0-9a-f]{64}", token)
                or phase not in {"locked", "prepared", "assets-written", "config-replaced", "commit-marked"}
            ):
                raise InstallerError(f"{label} has an unsupported recovery schema")
            details.append(f"{label} records phase {phase}")
        except InstallerError as exc:
            details.append(str(exc))
    raise InstallerError(
        "incomplete runtime-kit recovery state requires operator inspection; " + "; ".join(details)
    )


def _replace_owned_transaction_file(path: Path, before: bytes, after: bytes) -> None:
    if _owned_transaction_content(path, "runtime-kit journal") != before:
        raise InstallerError("runtime-kit journal changed during the transaction")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}")
    try:
        _write_exclusive(temporary, after, 0o600)
        if _owned_transaction_content(path, "runtime-kit journal") != before:
            raise InstallerError("runtime-kit journal changed before phase advancement")
        os.replace(temporary, path)
        _fsync_directory(path.parent)
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
            "schemaVersion": 2,
            "phase": "locked",
            "transactionToken": token,
            "planDigest": plan.plan_digest,
            "installationDigest": plan.installation_digest,
        }
    )
    journal_value = {
        "schemaVersion": 2,
        "phase": "prepared",
        "transactionToken": token,
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
    }
    journal_content = _canonical_json(journal_value)

    def advance(phase: str) -> None:
        nonlocal journal_content
        journal_value["phase"] = phase
        journal_value["createdDirectories"] = [str(path) for path in created_dirs]
        updated = _canonical_json(journal_value)
        _replace_owned_transaction_file(journal, journal_content, updated)
        journal_content = updated

    try:
        _mkdir_chain(plan.runtime_root, created_dirs)
        _validate_private_directory(plan.runtime_root, "runtime root")
        _write_exclusive(lock, lock_content, 0o600)
        lock_created = True
        _write_exclusive(journal, journal_content, 0o600)
        journal_created = True
        for directory in (plan.clone_root, plan.lifecycle_root, plan.outbox_root, plan.files[0].path.parent):
            _mkdir_chain(directory, created_dirs)
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
                    os.replace(temporary, plan.config_path)
                    _fsync_directory(plan.config_path.parent)
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
