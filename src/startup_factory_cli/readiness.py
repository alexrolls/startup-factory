"""Offline initialization planning and readiness diagnostics."""

from __future__ import annotations

import dataclasses
import json
import os
import re
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
    resolved: dict[str, Path] = {}
    for key in (
        "BROKER_TASK_CLONE_ROOT",
        "AGENT_SANDBOX_RUNNER",
        "BROKER_LIFECYCLE_ROOT",
        "AGENT_RUNTIME_MANIFEST",
    ):
        candidate = Path(values[key])
        if not candidate.is_absolute() or Path(os.path.normpath(str(candidate))) != candidate:
            return False, manifest_raw
        resolved[key] = candidate
    runner = resolved["AGENT_SANDBOX_RUNNER"]
    manifest_path = resolved["AGENT_RUNTIME_MANIFEST"]
    clone_root = resolved["BROKER_TASK_CLONE_ROOT"]
    lifecycle_root = resolved["BROKER_LIFECYCLE_ROOT"]
    try:
        runner_info = runner.lstat()
        manifest_info = manifest_path.lstat()
        root_info = clone_root.lstat()
        lifecycle_info = lifecycle_root.lstat()
    except OSError:
        return False, manifest_raw
    if (
        runner.is_symlink()
        or not runner.is_file()
        or runner_info.st_uid != os.geteuid()
        or runner_info.st_mode & 0o022
        or not runner_info.st_mode & 0o100
        or manifest_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_info.st_uid != os.geteuid()
        or manifest_info.st_mode & 0o077
        or clone_root.is_symlink()
        or not clone_root.is_dir()
        or root_info.st_uid != os.geteuid()
        or root_info.st_mode & 0o077
        or lifecycle_root.is_symlink()
        or not lifecycle_root.is_dir()
        or lifecycle_info.st_uid != os.geteuid()
        or lifecycle_info.st_mode & 0o077
    ):
        return False, manifest_raw
    manifest = _strict_json_object(manifest_path)
    configured = bool(
        manifest
        and manifest.get("schemaVersion") == 1
        and manifest.get("profile") == "rootless-podman-5"
        and manifest.get("cloneRoot") == str(clone_root)
        and manifest.get("lifecycleRoot") == str(lifecycle_root)
        and manifest.get("readiness") == "configured_unproved"
        and manifest.get("capabilities")
        == {"autonomousDelivery": False, "productionDelivery": False}
    )
    return configured, manifest_raw


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
