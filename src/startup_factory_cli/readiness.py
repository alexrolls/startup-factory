"""Offline initialization planning and readiness diagnostics."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping

from .installer import InstallerError, verify_installation
from .project_config import (
    PROJECT_CONFIG_RELATIVE_PATH,
    ConfigChange,
    apply_changes,
    plan_changes,
    read_project_config,
)


SCHEMA_VERSION = 1
MODES = ("solo", "team", "autonomous", "release")
APPLY_MODES = ("solo", "team")
_SKILL_MARKER = re.compile(r"(?m)^name:[ \t]*startup-factory[ \t]*$")
_ASSIGNMENT_VALUE = re.compile(r"^[A-Z][A-Z0-9_]*=(.*)$")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
_MAX_RUNTIME_FILE = 2 * 1024 * 1024
_MAX_ENGINE_OUTPUT = 256 * 1024


@dataclasses.dataclass(frozen=True)
class ReadinessCheck:
    id: str
    level: str
    status: str
    message: str
    remediation: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "level": self.level,
            "status": self.status,
            "message": self.message,
        }
        if self.remediation is not None:
            result["remediation"] = self.remediation
        return result


@dataclasses.dataclass(frozen=True)
class DoctorReport:
    mode: str
    project: Path
    target: Path
    checks: tuple[ReadinessCheck, ...]

    @property
    def overall(self) -> str:
        statuses = {check.status for check in self.checks}
        if "fail" in statuses:
            return "red"
        if statuses.intersection({"warn", "unknown"}):
            return "yellow"
        return "green"

    @property
    def ready(self) -> bool:
        return self.overall == "green"

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "action": "doctor",
            "schemaVersion": SCHEMA_VERSION,
            "mode": self.mode,
            "project": str(self.project),
            "target": str(self.target),
            "overall": self.overall,
            "ready": self.ready,
            "checks": [check.as_dict() for check in self.checks],
        }


@dataclasses.dataclass(frozen=True)
class InitResult:
    mode: str
    target: Path
    applied: bool
    apply_supported: bool
    changes: tuple[ConfigChange, ...]
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "action": "init",
            "schemaVersion": SCHEMA_VERSION,
            "mode": self.mode,
            "target": str(self.target),
            "applied": self.applied,
            "applySupported": self.apply_supported,
            "changes": [change.as_dict() for change in self.changes],
            "message": self.message,
        }


def initialize(
    target: Path,
    *,
    mode: str,
    product_management_tool: str | None,
    apply: bool,
) -> InitResult:
    """Preview or apply the phase-one, single-file initialization transaction."""

    if mode not in MODES:
        raise ValueError(f"unsupported readiness mode: {mode}")
    # Init may change preserved configuration, but only on top of a release-managed
    # installation whose immutable files and provenance still verify.
    verify_installation(target)
    config = read_project_config(target / PROJECT_CONFIG_RELATIVE_PATH)
    selected_adapter = product_management_tool or config.value("PRODUCT_MANAGEMENT_TOOL")
    adapter = target / "adapters" / f"{selected_adapter}.md"
    if adapter.is_symlink() or not adapter.is_file():
        raise InstallerError(
            f"selected project-management adapter is missing or not a regular file: {selected_adapter}"
        )
    apply_supported = mode in APPLY_MODES
    if not apply_supported:
        if apply:
            raise InstallerError(
                f"init --apply cannot enable {mode} mode; configure and prove protected "
                "execution requirements before using doctor"
            )
        return InitResult(
            mode=mode,
            target=target,
            applied=False,
            apply_supported=False,
            changes=(),
            message=(
                f"{mode} mode is inspection-only in schema version {SCHEMA_VERSION}; "
                "no configuration changes were planned"
            ),
        )

    updates = {"TEAM_MODE": "false" if mode == "solo" else "true"}
    if product_management_tool is not None:
        updates["PRODUCT_MANAGEMENT_TOOL"] = product_management_tool
    changes = plan_changes(config, updates)
    if apply:
        apply_changes(config, changes)
    return InitResult(
        mode=mode,
        target=target,
        applied=apply,
        apply_supported=True,
        changes=changes,
        message=(
            "configuration applied atomically"
            if apply
            else "preview only; pass --apply to write these changes"
        ),
    )


def _regular_text(path: Path) -> str | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def _installed(target: Path) -> bool:
    skill = _regular_text(target / "SKILL.md")
    return skill is not None and _SKILL_MARKER.search(skill) is not None


def _repository_detected(project: Path) -> bool:
    marker = project / ".git"
    return not marker.is_symlink() and (marker.is_file() or marker.is_dir())


def _strict_json_object(path: Path) -> dict[str, Any] | None:
    text = _regular_text(path)
    if text is None:
        return None

    def reject_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _exact_assignments(path: Path, keys: Iterable[str]) -> dict[str, str] | None:
    text = _regular_text(path)
    if text is None:
        return None
    requested = set(keys)
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = _ASSIGNMENT_VALUE.fullmatch(line)
        if match is None:
            continue
        key = line.split("=", 1)[0]
        if key not in requested:
            continue
        if key in result:
            return None
        value = match.group(1).strip()
        if " #" in value and not value.startswith('"'):
            value = value.split(" #", 1)[0].rstrip()
        result[key] = value
    return result if requested.issubset(result) else None


def _team_configuration(target: Path) -> tuple[bool, bool, bool]:
    command_keys = (
        "TEAM_LEAD_CMD",
        "PRINCIPAL_ARCHITECT_CMD",
        "SCEPTICAL_ARCHITECT_CMD",
        "INTEGRATOR_CMD",
    )
    runtime_keys = (
        *command_keys,
        "TRACKER_WRITERS",
        "AGENT_SANDBOX_ENFORCED",
        "BROKER_LIFECYCLE_ROOT",
    )
    validation_keys = (
        "VALIDATE_BUILD",
        "VALIDATE_TEST",
        "VALIDATE_LINT",
        "VALIDATE_FORMAT",
        "VALIDATE_SCRIPT",
    )
    values = _exact_assignments(target / "config/team.config.md", (*runtime_keys, *validation_keys))
    if values is None:
        return False, False, False
    commands_configured = all(values[key] != "null" for key in command_keys)
    validation_configured = any(values[key] != "null" for key in validation_keys)
    protected_configured = (
        values["TRACKER_WRITERS"] == "broker"
        and values["AGENT_SANDBOX_ENFORCED"] == "true"
        and values["BROKER_LIFECYCLE_ROOT"] != "null"
    )
    return commands_configured, validation_configured, protected_configured


def _autonomy_configured(target: Path, protected_team: bool) -> bool:
    automation = _strict_json_object(target / "config/automation.config.json")
    return bool(
        automation
        and automation.get("enabled") is True
        and automation.get("requireAgentSandbox") is True
        and automation.get("requireSingleTrackerWriter") is True
        and protected_team
    )


def _release_configured(target: Path) -> bool:
    deployment = _strict_json_object(target / "config/deployment.config.json")
    if not deployment:
        return False
    isolation = deployment.get("planningIsolation")
    hooks = deployment.get("hooks")
    required_hooks = (
        "plan",
        "apply",
        "status",
        "verify",
        "rollback",
        "verifyCi",
        "verifyDelivery",
        "verifyApproval",
    )
    return bool(
        deployment.get("enabled") is True
        and deployment.get("mode") == "approval-required"
        and deployment.get("stateRoot") is not None
        and deployment.get("credentialEnvFile") is not None
        and isinstance(isolation, Mapping)
        and isolation.get("enforced") is True
        and isolation.get("separateIdentity") is True
        and isolation.get("credentialPathsUnmounted") is True
        and isolation.get("statePathsUnmounted") is True
        and isolation.get("productionEgress") is False
        and isinstance(hooks, Mapping)
        and all(hooks.get(key) is not None for key in required_hooks)
    )


def secure_runtime_checks(*, configured: bool, manifest: str | None) -> tuple[ReadinessCheck, ...]:
    """Separate local runtime configuration from external boundary proof."""

    return (
        ReadinessCheck(
            "secure-runtime.configured",
            "configured",
            "pass" if configured else "fail",
            (
                f"protected runtime manifest is configured at {manifest}"
                if configured and manifest
                else "protected runtime configuration is incomplete"
            ),
            None if configured else "Preview and explicitly apply startup-factory runtime-kit on Linux.",
        ),
        ReadinessCheck(
            "secure-runtime.proved",
            "proved",
            "unknown",
            "offline checks and fixed probes do not prove an OS/container security boundary",
            "Use authenticated launcher doctor plus an independent external boundary attestation.",
        ),
    )


def _runtime_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _runtime_canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _runtime_read(
    path: Path,
    *,
    label: str,
    mode: int | None = None,
    executable: bool = False,
    maximum: int = _MAX_RUNTIME_FILE,
) -> bytes:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ValueError(f"{label} path is not canonical")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} path contains a symlink")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ValueError("secure no-follow opens are unavailable")
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ValueError(f"{label} is not a bounded single-link file")
        if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError(f"{label} has unsafe ownership or mode")
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            raise ValueError(f"{label} mode changed")
        if executable and not info.st_mode & 0o111:
            raise ValueError(f"{label} is not executable")
        content = bytearray()
        while len(content) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > maximum:
            raise ValueError(f"{label} exceeds its size limit")
        return bytes(content)
    finally:
        os.close(descriptor)


def _runtime_json(content: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ValueError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    value = json.loads(content, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _runtime_private_directory(path: Path, *, label: str) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ValueError(f"{label} path is not canonical")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} path contains a symlink")
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ValueError(f"{label} is not a caller-owned private directory")


def _runtime_path_present_nofollow(path: Path, *, label: str) -> bool:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ValueError(f"{label} path is not canonical")
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ValueError(f"{label} path is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} path contains a symlink: {current}")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"{label} path contains a non-directory ancestor: {current}")
    return True


def _runtime_engine_json(engine: Path, arguments: list[str], *, label: str) -> Any:
    result = subprocess.run(
        [str(engine), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "XDG_RUNTIME_DIR": f"/run/user/{os.geteuid()}",
        },
    )
    if result.returncode or result.stderr or len(result.stdout) > _MAX_ENGINE_OUTPUT:
        raise ValueError(f"{label} proof is invalid")

    def pairs(rows: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in rows:
            if key in output:
                raise ValueError(f"{label} proof contains a duplicate key")
            output[key] = value
        return output

    return json.loads(result.stdout, object_pairs_hook=pairs)


def _runtime_proofs(engine: Path, image: str) -> tuple[dict[str, Any], dict[str, Any]]:
    info = _runtime_engine_json(engine, ["info", "--format", "json"], label="engine")
    if not isinstance(info, dict):
        raise ValueError("engine proof is not an object")
    version = info.get("version")
    host = info.get("host")
    security = host.get("security") if isinstance(host, dict) else None
    mappings = host.get("idMappings") if isinstance(host, dict) else None
    version_text = version.get("Version") if isinstance(version, dict) else None

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
        not isinstance(version_text, str)
        or version_text.split(".", 1)[0] != "5"
        or not isinstance(security, dict)
        or security.get("rootless") is not True
        or not isinstance(mappings, dict)
        or set(mappings) != {"uidmap", "gidmap"}
        or not valid_mapping(mappings["uidmap"])
        or not valid_mapping(mappings["gidmap"])
    ):
        raise ValueError("engine proof is not rootless Podman 5")
    inspected = _runtime_engine_json(
        engine, ["image", "inspect", "--format", "json", image], label="image"
    )
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise ValueError("image proof cardinality changed")
    repository_digests = inspected[0].get("RepoDigests")
    image_id = inspected[0].get("Id")
    if (
        not isinstance(repository_digests, list)
        or not all(isinstance(item, str) for item in repository_digests)
        or image not in repository_digests
        or not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
    ):
        raise ValueError("image proof identity changed")
    return (
        {
            "version": version_text,
            "rootless": True,
            "uidmap": mappings["uidmap"],
            "gidmap": mappings["gidmap"],
        },
        {"Id": image_id, "RepoDigests": sorted(set(repository_digests))},
    )


def _secure_runtime_configuration(target: Path) -> tuple[bool, str | None] | None:
    """Validate an installed profile as configuration, never boundary proof.

    Legacy team configurations have no runtime-kit keys and retain their prior
    doctor behavior. Once any runtime-kit key exists, an incomplete or unsafe
    profile fails closed.
    """

    path = target / "config/team.config.md"
    text = _regular_text(path)
    if text is None:
        return None
    keys = (
        "TASK_WORKTREE_MODE",
        "BROKER_TASK_CLONE_ROOT",
        "BROKER_AGENT_OUTBOX_ROOT",
        "AGENT_SANDBOX_RUNNER",
        "AGENT_SANDBOX_ENFORCED",
        "BROKER_LIFECYCLE_ROOT",
        "AGENT_RUNTIME_MANIFEST",
    )
    if not any(
        f"{key}=" in text
        for key in ("TASK_WORKTREE_MODE", "BROKER_TASK_CLONE_ROOT", "AGENT_RUNTIME_MANIFEST")
    ):
        return None
    values = _exact_assignments(path, keys)
    if values is None:
        return False, None
    manifest_raw = values["AGENT_RUNTIME_MANIFEST"]
    if (
        values["TASK_WORKTREE_MODE"] != "standalone-clone"
        or values["AGENT_SANDBOX_ENFORCED"] != "true"
        or any(values[key] == "null" for key in keys[1:])
    ):
        return False, None if manifest_raw == "null" else manifest_raw
    try:
        resolved = {key: Path(values[key]) for key in keys[1:] if key != "AGENT_SANDBOX_ENFORCED"}
        clone_root = resolved["BROKER_TASK_CLONE_ROOT"]
        outbox_root = resolved["BROKER_AGENT_OUTBOX_ROOT"]
        lifecycle_root = resolved["BROKER_LIFECYCLE_ROOT"]
        runner = resolved["AGENT_SANDBOX_RUNNER"]
        manifest_path = resolved["AGENT_RUNTIME_MANIFEST"]
        for directory, label in (
            (clone_root, "clone root"),
            (outbox_root, "outbox root"),
            (lifecycle_root, "lifecycle root"),
        ):
            _runtime_private_directory(directory, label=label)
        runner_content = _runtime_read(runner, label="runner", mode=0o700, executable=True)
        manifest_content = _runtime_read(manifest_path, label="manifest", mode=0o600)
        runtime_root = manifest_path.parent.parent.parent
        if any(
            _runtime_path_present_nofollow(path, label="runtime recovery evidence")
            for path in (runtime_root / ".runtime-kit.lock", runtime_root / ".runtime-kit-journal.json")
        ):
            raise ValueError("unresolved runtime-kit transaction requires explicit recovery")
        manifest = _runtime_json(manifest_content, label="manifest")
        expected_keys = {
            "schemaVersion", "profile", "sourceAssetsSha256", "engine", "image", "runner",
            "policy", "network", "cloneRoot", "lifecycleRoot", "outboxRoot", "readiness",
            "skillRoot", "capabilities",
        }
        if (
            set(manifest) != expected_keys
            or manifest.get("schemaVersion") != 2
            or manifest.get("profile") != "rootless-podman-5"
            or manifest.get("cloneRoot") != str(clone_root)
            or manifest.get("lifecycleRoot") != str(lifecycle_root)
            or manifest.get("outboxRoot") != str(outbox_root)
            or manifest.get("skillRoot") != str(target)
            or manifest.get("readiness") != "configured_unproved"
            or manifest.get("capabilities")
            != {"autonomousDelivery": False, "productionDelivery": False}
        ):
            raise ValueError("runtime manifest schema or identity changed")
        runner_binding = manifest.get("runner")
        policy_binding = manifest.get("policy")
        network_binding = manifest.get("network")
        engine_binding = manifest.get("engine")
        image_binding = manifest.get("image")
        if runner_binding != {"path": str(runner), "sha256": _runtime_digest(runner_content)}:
            raise ValueError("runner binding changed")
        if not isinstance(policy_binding, dict) or set(policy_binding) != {"path", "sha256"}:
            raise ValueError("policy binding is malformed")
        if not isinstance(network_binding, dict) or set(network_binding) != {"name", "path", "sha256"}:
            raise ValueError("network binding is malformed")
        if network_binding.get("name") != "none":
            raise ValueError("unsupported runtime network")
        policy_path = Path(str(policy_binding["path"]))
        network_path = Path(str(network_binding["path"]))
        policy_content = _runtime_read(policy_path, label="runtime policy", mode=0o600)
        network_content = _runtime_read(network_path, label="network policy", mode=0o600)
        if policy_binding["sha256"] != _runtime_digest(policy_content):
            raise ValueError("runtime policy digest changed")
        if network_binding["sha256"] != _runtime_digest(network_content):
            raise ValueError("network policy digest changed")
        source_runner = _runtime_read(target / "runtime/runner-linux-container.sh", label="source runner")
        source_policy = _runtime_read(target / "runtime/container-policy.json", label="source policy")
        source_network = _runtime_read(target / "runtime/network-policy-none.json", label="source network policy")
        if manifest.get("sourceAssetsSha256") != _runtime_digest(
            source_runner + source_policy + source_network
        ):
            raise ValueError("source asset digest changed")
        if not isinstance(engine_binding, dict) or set(engine_binding) != {"path", "sha256", "proofSha256"}:
            raise ValueError("engine binding is malformed")
        engine = Path(str(engine_binding["path"]))
        engine_content = _runtime_read(
            engine, label="engine", executable=True, maximum=128 * 1024 * 1024
        )
        if engine_binding["sha256"] != _runtime_digest(engine_content):
            raise ValueError("engine digest changed")
        if (
            not isinstance(image_binding, dict)
            or set(image_binding) != {"reference", "proofSha256", "pull"}
            or image_binding.get("pull") != "never"
            or not isinstance(image_binding.get("reference"), str)
            or _IMAGE.fullmatch(image_binding["reference"]) is None
        ):
            raise ValueError("image binding is malformed")
        engine_proof, image_proof = _runtime_proofs(engine, image_binding["reference"])
        if engine_binding["proofSha256"] != _runtime_digest(_runtime_canonical_json(engine_proof)):
            raise ValueError("engine proof digest changed")
        if image_binding["proofSha256"] != _runtime_digest(_runtime_canonical_json(image_proof)):
            raise ValueError("image proof digest changed")
        config_content = _runtime_read(path, label="team configuration")
        desired = {
            "schemaVersion": 1,
            "profile": "rootless-podman-5",
            "runtimeRoot": str(runtime_root),
            "engineSha256": engine_binding["sha256"],
            "engineProofSha256": engine_binding["proofSha256"],
            "image": image_binding["reference"],
            "imageProofSha256": image_binding["proofSha256"],
            "files": [
                {"path": str(policy_path), "mode": 0o600, "sha256": policy_binding["sha256"]},
                {"path": str(network_path), "mode": 0o600, "sha256": network_binding["sha256"]},
                {"path": str(runner), "mode": 0o700, "sha256": runner_binding["sha256"]},
                {"path": str(manifest_path), "mode": 0o600, "sha256": _runtime_digest(manifest_content)},
            ],
            "configAfterSha256": _runtime_digest(config_content),
        }
        installation_digest = _runtime_digest(_runtime_canonical_json(desired))
        marker = runtime_root / (
            ".runtime-kit-committed-" + installation_digest.split(":", 1)[1]
        )
        marker_content = _runtime_read(marker, label="commit marker", mode=0o600)
        marker_value = _runtime_json(marker_content, label="commit marker")
        if (
            marker_value.get("schemaVersion") != 1
            or marker_value.get("installationDigest") != installation_digest
            or _DIGEST.fullmatch(str(marker_value.get("appliedPlanDigest") or "")) is None
        ):
            raise ValueError("commit marker binding changed")
        return True, manifest_raw
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        return False, manifest_raw


def diagnose(project: Path, target: Path, *, mode: str) -> DoctorReport:
    """Inspect local files only; configured commands and hooks are never evaluated."""

    if mode not in MODES:
        raise ValueError(f"unsupported readiness mode: {mode}")
    project = project.resolve(strict=True)
    checks: list[ReadinessCheck] = []
    installed = _installed(target)
    checks.append(
        ReadinessCheck(
            "installation.detected",
            "detected",
            "pass" if installed else "fail",
            "Startup Factory installation marker found" if installed else "installation marker missing",
            None if installed else "Install Startup Factory at the selected target.",
        )
    )
    installation_verified = False
    verification_error: str | None = None
    if installed:
        try:
            verify_installation(target)
            installation_verified = True
        except InstallerError as exc:
            verification_error = str(exc)
    checks.append(
        ReadinessCheck(
            "installation.verified",
            "proved",
            "pass" if installation_verified else "fail",
            "release-managed provenance and immutable files verified"
            if installation_verified
            else (
                "installation marker is not backed by valid release-managed provenance"
                if verification_error is None
                else f"installation verification failed: {verification_error}"
            ),
            None
            if installation_verified
            else "Repair or reinstall Startup Factory before initialization or delivery.",
        )
    )
    repository = _repository_detected(project)
    checks.append(
        ReadinessCheck(
            "repository.detected",
            "detected",
            "pass" if repository else "warn",
            "Git repository marker found" if repository else "Git repository marker not found",
            None if repository else "Run doctor from the intended Git project root.",
        )
    )

    config_path = target / PROJECT_CONFIG_RELATIVE_PATH
    config_regular = not config_path.is_symlink() and config_path.is_file()
    checks.append(
        ReadinessCheck(
            "project-config.detected",
            "detected",
            "pass" if config_regular else "fail",
            "project configuration is a regular file"
            if config_regular
            else "project configuration is missing or unsafe",
            None if config_regular else "Restore config/project-management.config.md as a regular file.",
        )
    )
    config = None
    config_error: str | None = None
    if config_regular:
        try:
            config = read_project_config(config_path)
        except InstallerError as exc:
            config_error = str(exc)
    checks.append(
        ReadinessCheck(
            "project-config.valid",
            "configured",
            "pass" if config is not None else "fail",
            "editable project configuration keys are valid and unique"
            if config is not None
            else (config_error or "project configuration could not be parsed"),
            None if config is not None else "Keep exactly one valid assignment for each editable key.",
        )
    )

    adapter_valid = False
    if config is not None:
        adapter = target / "adapters" / f"{config.value('PRODUCT_MANAGEMENT_TOOL')}.md"
        adapter_valid = not adapter.is_symlink() and adapter.is_file()
    checks.append(
        ReadinessCheck(
            "tracker-adapter.configured",
            "configured",
            "pass" if adapter_valid else "fail",
            "selected tracker adapter is present"
            if adapter_valid
            else "selected tracker adapter is missing or unsafe",
            None if adapter_valid else "Select an adapter name that exists below adapters/.",
        )
    )

    expected_team_mode = "false" if mode == "solo" else "true"
    mode_matches = config is not None and config.value("TEAM_MODE") == expected_team_mode
    checks.append(
        ReadinessCheck(
            "workflow-mode.configured",
            "configured",
            "pass" if mode_matches else "fail",
            f"TEAM_MODE matches {mode} mode"
            if mode_matches
            else f"TEAM_MODE does not match {mode} mode",
            None
            if mode_matches
            else (
                f"Preview startup-factory init --mode {mode}; protected modes require manual setup."
            ),
        )
    )

    if mode == "solo":
        local_proved = installation_verified and config is not None and adapter_valid and mode_matches
        checks.append(
            ReadinessCheck(
                "local-configuration.proved",
                "proved",
                "pass" if local_proved else "fail",
                "local solo configuration was re-read and verified"
                if local_proved
                else "local solo configuration could not be proved",
            )
        )
        checks.append(
            ReadinessCheck(
                "tracker-operation.proved",
                "proved",
                "unknown",
                "offline doctor does not perform a tracker read/write operation",
                "Run an authenticated tracker operation before relying on delivery readiness.",
            )
        )
        return DoctorReport(mode, project, target, tuple(checks))

    team_path = target / "config/team.config.md"
    team_detected = not team_path.is_symlink() and team_path.is_file()
    checks.append(
        ReadinessCheck(
            "team-config.detected",
            "detected",
            "pass" if team_detected else "fail",
            "team configuration is a regular file"
            if team_detected
            else "team configuration is missing or unsafe",
        )
    )
    commands, validation, protected_team = _team_configuration(target)
    checks.append(
        ReadinessCheck(
            "team-runtime.configured",
            "configured",
            "pass" if commands else "fail",
            "mandatory team role commands are configured"
            if commands
            else "mandatory team role commands are missing, duplicated, or disabled",
        )
    )
    checks.append(
        ReadinessCheck(
            "validation.configured",
            "configured",
            "pass" if validation else "warn",
            "at least one repository validation command is configured"
            if validation
            else "no repository validation command is configured",
            None if validation else "Set a VALIDATE_* command or VALIDATE_SCRIPT before delivery.",
        )
    )
    checks.append(
        ReadinessCheck(
            "tracker-operation.proved",
            "proved",
            "unknown",
            "offline doctor does not perform a tracker read/write operation",
            "Run an authenticated tracker operation before relying on delivery readiness.",
        )
    )
    secure_runtime = _secure_runtime_configuration(target)
    if secure_runtime is not None:
        configured, manifest = secure_runtime
        checks.extend(secure_runtime_checks(configured=configured, manifest=manifest))

    if mode == "team":
        checks.append(
            ReadinessCheck(
                "team-runtime.proved",
                "proved",
                "unknown",
                "offline doctor does not execute or authenticate configured agent commands",
                "Use the team launcher's doctor step to prove command and authentication readiness.",
            )
        )
        return DoctorReport(mode, project, target, tuple(checks))

    autonomy = _autonomy_configured(target, protected_team)
    checks.append(
        ReadinessCheck(
            "autonomous-controls.configured",
            "configured",
            "pass" if autonomy else "fail",
            "autonomous controls are configured"
            if autonomy
            else "autonomous controls are incomplete or disabled",
        )
    )
    checks.append(
        ReadinessCheck(
            "protected-autonomy.proved",
            "proved",
            "unknown",
            "offline doctor has no trusted proof of sandbox and broker isolation",
            "Prove protected execution through the authenticated runtime before autonomous use.",
        )
    )

    if mode == "release":
        release = _release_configured(target)
        checks.append(
            ReadinessCheck(
                "release-controls.configured",
                "configured",
                "pass" if release else "fail",
                "release controls and hooks are configured"
                if release
                else "release controls, isolation, or hooks are incomplete",
            )
        )
        checks.append(
            ReadinessCheck(
                "protected-release.proved",
                "proved",
                "unknown",
                "offline doctor has no trusted approval, CI, or delivery attestation",
                "Use authenticated release verification to prove each required attestation.",
            )
        )
    return DoctorReport(mode, project, target, tuple(checks))
