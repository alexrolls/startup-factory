"""Offline initialization planning and readiness diagnostics."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterable, Mapping

from .config_values import ConfigValueError, read_config_file, value_for
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


def _exact_assignments(
    path: Path, keys: Iterable[str]
) -> dict[str, str | None] | None:
    try:
        parsed = read_config_file(path, "team config")
    except ConfigValueError:
        return None
    requested = set(keys)
    if not requested.issubset(parsed):
        return None
    return {key: value_for(parsed, key) for key in requested}


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
    commands_configured = all(values[key] is not None for key in command_keys)
    validation_configured = any(values[key] is not None for key in validation_keys)
    broker_configured = values["TRACKER_WRITERS"] == "broker"
    return commands_configured, validation_configured, broker_configured


def _configured_path_value(raw: str | None) -> str | None:
    """Return the already-normalized scalar used for protected local paths."""

    return raw


def _sandbox_runner_readiness(
    target: Path, project: Path
) -> tuple[bool, str, str | None]:
    """Validate the configured runner's structure without executing it."""

    remediation = (
        "Provision a root-managed OS isolation runner under a canonical system path "
        "whose complete ancestor chain is root-owned and non-writable by the operator, "
        "group, or world. Keep it outside the repository and installed runtime, then "
        "set its canonical absolute path as "
        "AGENT_SANDBOX_RUNNER and set AGENT_SANDBOX_ENFORCED=true in "
        "config/team.config.md. Startup Factory does not ship this runner."
    )
    values = _exact_assignments(
        target / "config/team.config.md",
        ("AGENT_SANDBOX_ENFORCED", "AGENT_SANDBOX_RUNNER"),
    )
    if values is None:
        return (
            False,
            "sandbox enforcement or runner configuration is missing or duplicated",
            remediation,
        )
    if values["AGENT_SANDBOX_ENFORCED"] != "true":
        return False, "AGENT_SANDBOX_ENFORCED is not true", remediation
    configured = _configured_path_value(values["AGENT_SANDBOX_RUNNER"])
    if configured is None:
        return False, "AGENT_SANDBOX_RUNNER is not configured", remediation
    if not configured:
        return False, "AGENT_SANDBOX_RUNNER has an invalid scalar value", remediation
    runner = Path(configured)
    if (
        not runner.is_absolute()
        or configured != os.path.normpath(configured)
        or str(runner) != configured
    ):
        return (
            False,
            "AGENT_SANDBOX_RUNNER is not an absolute normalized path",
            remediation,
        )
    try:
        metadata = runner.lstat()
    except OSError as exc:
        return False, f"AGENT_SANDBOX_RUNNER is unavailable: {exc}", remediation
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return (
            False,
            "AGENT_SANDBOX_RUNNER is not a non-symlink regular file",
            remediation,
        )
    if not metadata.st_mode & 0o111 or not os.access(runner, os.X_OK):
        return False, "AGENT_SANDBOX_RUNNER is not executable", remediation
    if metadata.st_uid != 0:
        return (
            False,
            "AGENT_SANDBOX_RUNNER is not root-owned",
            remediation,
        )
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        return (
            False,
            "AGENT_SANDBOX_RUNNER is group- or world-writable",
            remediation,
        )
    try:
        resolved = runner.resolve(strict=True)
        project_boundary = project.resolve(strict=True)
        target_boundary = target.resolve(strict=True)
    except OSError as exc:
        return False, f"cannot resolve AGENT_SANDBOX_RUNNER boundary: {exc}", remediation
    if resolved != runner:
        return (
            False,
            "AGENT_SANDBOX_RUNNER is not its canonical absolute path",
            remediation,
        )
    for boundary, label in (
        (project_boundary, "project repository"),
        (target_boundary, "installed runtime"),
    ):
        try:
            resolved.relative_to(boundary)
        except ValueError:
            continue
        return (
            False,
            f"AGENT_SANDBOX_RUNNER is inside the {label}",
            remediation,
        )
    ancestor = resolved.parent
    while True:
        try:
            ancestor_metadata = ancestor.lstat()
        except OSError as exc:
            return (
                False,
                f"cannot inspect AGENT_SANDBOX_RUNNER ancestor {ancestor}: {exc}",
                remediation,
            )
        if stat.S_ISLNK(ancestor_metadata.st_mode) or not stat.S_ISDIR(
            ancestor_metadata.st_mode
        ):
            return (
                False,
                f"AGENT_SANDBOX_RUNNER ancestor is not a real directory: {ancestor}",
                remediation,
            )
        if ancestor_metadata.st_uid != 0:
            return (
                False,
                f"AGENT_SANDBOX_RUNNER ancestor is not root-owned: {ancestor}",
                remediation,
            )
        if stat.S_IMODE(ancestor_metadata.st_mode) & 0o022:
            return (
                False,
                f"AGENT_SANDBOX_RUNNER ancestor is group- or world-writable: {ancestor}",
                remediation,
            )
        try:
            operator_can_write = os.access(ancestor, os.W_OK, effective_ids=True)
        except (NotImplementedError, TypeError):
            operator_can_write = os.access(ancestor, os.W_OK)
        if operator_can_write:
            return (
                False,
                f"AGENT_SANDBOX_RUNNER ancestor is writable by the operator: {ancestor}",
                remediation,
            )
        if ancestor == ancestor.parent:
            break
        ancestor = ancestor.parent
    try:
        operator_can_write_runner = os.access(runner, os.W_OK, effective_ids=True)
    except (NotImplementedError, TypeError):
        operator_can_write_runner = os.access(runner, os.W_OK)
    if operator_can_write_runner:
        return (
            False,
            "AGENT_SANDBOX_RUNNER is writable by the operator",
            remediation,
        )
    return (
        True,
        "external sandbox runner and its complete path chain are root-protected; "
        "the runner was not executed",
        None,
    )


def _lifecycle_root_readiness(
    target: Path, project: Path
) -> tuple[bool, str, str | None]:
    """Validate configured lifecycle storage without creating or modifying it."""

    remediation = (
        "Pre-create a private mode-0700 directory outside the repository, installed "
        "runtime, and shared temporary directories; deny agent sandboxes access; then "
        "set its canonical absolute path as BROKER_LIFECYCLE_ROOT in config/team.config.md."
    )
    values = _exact_assignments(
        target / "config/team.config.md", ("BROKER_LIFECYCLE_ROOT",)
    )
    if values is None:
        return False, "BROKER_LIFECYCLE_ROOT is missing or duplicated", remediation
    configured = _configured_path_value(values["BROKER_LIFECYCLE_ROOT"])
    if configured is None:
        return False, "BROKER_LIFECYCLE_ROOT is not configured", remediation
    if not configured:
        return False, "BROKER_LIFECYCLE_ROOT has an invalid scalar value", remediation
    root = Path(configured)
    if (
        not root.is_absolute()
        or configured != os.path.normpath(configured)
        or str(root) != configured
    ):
        return (
            False,
            "BROKER_LIFECYCLE_ROOT is not an absolute normalized path",
            remediation,
        )
    for shared in (Path("/tmp"), Path("/private/tmp")):
        try:
            root.relative_to(shared)
        except ValueError:
            pass
        else:
            return (
                False,
                "BROKER_LIFECYCLE_ROOT is below a shared temporary directory",
                remediation,
            )
    try:
        resolved = root.resolve(strict=True)
        project_boundary = project.resolve(strict=True)
        target_boundary = target.resolve(strict=True)
    except OSError as exc:
        return False, f"BROKER_LIFECYCLE_ROOT is unavailable: {exc}", remediation
    if resolved != root:
        return (
            False,
            "BROKER_LIFECYCLE_ROOT or one of its ancestors is a symlink",
            remediation,
        )
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            return False, f"cannot inspect lifecycle path {current}: {exc}", remediation
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return (
                False,
                f"lifecycle path component is not a non-symlink directory: {current}",
                remediation,
            )
        if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(
            metadata.st_mode
        ) & 0o022:
            return (
                False,
                f"lifecycle path component has unsafe ownership or write permissions: {current}",
                remediation,
            )
    if stat.S_IMODE(root.lstat().st_mode) != 0o700:
        return False, "BROKER_LIFECYCLE_ROOT must have mode 0700", remediation
    if not os.access(root, os.R_OK | os.W_OK | os.X_OK):
        return (
            False,
            "BROKER_LIFECYCLE_ROOT is not usable by the current operator identity",
            remediation,
        )
    for boundary, label in (
        (project_boundary, "project repository"),
        (target_boundary, "installed runtime"),
    ):
        try:
            common = Path(os.path.commonpath((str(root), str(boundary))))
        except ValueError:
            continue
        if common in {root, boundary}:
            return (
                False,
                f"BROKER_LIFECYCLE_ROOT is not disjoint from the {label}",
                remediation,
            )
    return (
        True,
        "external lifecycle authority directory is canonical, private, and locally usable",
        None,
    )


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
    commands, validation, broker_configured = _team_configuration(target)
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
    configured_failure = "warn" if mode == "team" else "fail"
    checks.append(
        ReadinessCheck(
            "tracker-writer-boundary.configured",
            "configured",
            "pass" if broker_configured else configured_failure,
            "tracker writes are restricted to the authenticated broker"
            if broker_configured
            else "TRACKER_WRITERS is not restricted to the authenticated broker",
            None
            if broker_configured
            else (
                "Set TRACKER_WRITERS=broker before relying on authenticated review, "
                "integration, or release authority."
            ),
        )
    )
    sandbox_ready, sandbox_message, sandbox_remediation = _sandbox_runner_readiness(
        target, project
    )
    checks.append(
        ReadinessCheck(
            "sandbox-runner.configured",
            "configured",
            "pass" if sandbox_ready else configured_failure,
            sandbox_message,
            sandbox_remediation,
        )
    )
    lifecycle_ready, lifecycle_message, lifecycle_remediation = (
        _lifecycle_root_readiness(target, project)
    )
    checks.append(
        ReadinessCheck(
            "lifecycle-authority.configured",
            "configured",
            "pass" if lifecycle_ready else "fail",
            lifecycle_message,
            lifecycle_remediation,
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

    protected_team = broker_configured and sandbox_ready and lifecycle_ready
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
