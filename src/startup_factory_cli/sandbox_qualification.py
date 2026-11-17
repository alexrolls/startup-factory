"""Offline Docker Sandboxes qualification inventory.

Runtime discovery is an observation, never permission to execute the discovered
file. This milestone performs no live checks and cannot issue a qualification
receipt or enable autonomous execution.
"""

from __future__ import annotations

import dataclasses
import os
import platform
import shutil
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
BACKEND = "docker-sandboxes"


@dataclasses.dataclass(frozen=True)
class QualificationCheck:
    id: str
    title: str
    required_evidence: tuple[str, ...]
    remediation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "required": True,
            "status": "needs-validation",
            "passed": False,
            "evidence": [],
            "requiredEvidence": list(self.required_evidence),
            "remediation": self.remediation,
        }


REQUIRED_CHECKS = (
    QualificationCheck(
        "version-platform",
        "Qualified runtime version and platform",
        (
            "Exact CLI/daemon release and installation checksums.",
            "Hypervisor prerequisites and structured-output fixtures for this platform.",
        ),
        "Qualify one pinned CLI/daemon/platform combination on a dedicated test host; "
        "finding an sbx executable does not prove its version or trust.",
    ),
    QualificationCheck(
        "mountless-startup",
        "Mountless startup without inherited host integrations",
        (
            "Observed mounts, volumes, kit identity, and effective integration settings.",
            "No host workspace, HOME, keychain, skills store, Docker socket, or host MCP access.",
        ),
        "Create a disposable mountless fixture with an approved kit, then inspect its "
        "actual resources before supplying source or credentials.",
    ),
    QualificationCheck(
        "policy-before-execution",
        "Deny-by-default policy before guest execution",
        (
            "Policy is effective before kit setup or any guest command.",
            "Controlled blocked and allowed network fixtures, including private and metadata routes.",
        ),
        "Prove the creation-time network policy on a dedicated fixture; applying "
        "restrictions after startup cannot pass this gate.",
    ),
    QualificationCheck(
        "object-identity",
        "Stable sandbox object and generation identity",
        (
            "Create, inspect, exec, stop, and remove address the same backend object.",
            "Name replacement and daemon restart cannot substitute another generation.",
            "Atomic object binding, or a dedicated-account exclusive controller with protected endpoints and permanent name reservations.",
        ),
        "Qualify atomic object binding or a dedicated-account exclusive controller "
        "with permanently reserved names and fenced epochs; inspections alone do "
        "not prevent a replacement race.",
    ),
    QualificationCheck(
        "exec-protocol",
        "Bounded non-TTY exec transport",
        (
            "Stdin/stdout preserve protocol frames and stderr remains separate.",
            "Backpressure, slow readers, disconnects, exit codes, and cancellation are bounded.",
        ),
        "Run the fixed bridge against bounded transport fixtures before relying on "
        "exec streams for publication or control.",
    ),
    QualificationCheck(
        "resource-limits",
        "Host-enforced resource and output limits",
        (
            "Finite CPU, memory, root/workspace/Docker disk, input, output, and log limits.",
            "Safe guest-root pressure tests and retained-storage accounting preserve host headroom.",
        ),
        "Measure hard limits on the qualified backend, including sparse disk growth; "
        "a polling monitor alone does not establish a disk cap.",
    ),
    QualificationCheck(
        "cancellation-cleanup",
        "Cancellation, orphan recovery, and confirmed removal",
        (
            "Publication is fenced before exact-generation stop/removal.",
            "Relay/controller failure, timeout, and daemon restart leave no live guest, ports, or owned storage.",
        ),
        "Prove independent watchdog/reconciliation and exact-object cleanup; killing "
        "the host CLI process does not prove the VM stopped.",
    ),
    QualificationCheck(
        "credentials",
        "Scoped model access without privileged credential fallback",
        (
            "Model access is scoped to the assigned sandbox without a plaintext guest token.",
            "No tracker, GitHub write, production, SSH, keychain, or global privileged-service fallback.",
        ),
        "Use dummy identities to test scoped credentials, removal/global fallback, "
        "and model quotas; do not inspect or import personal credential stores.",
    ),
)
REQUIRED_CHECK_IDS = tuple(check.id for check in REQUIRED_CHECKS)


@dataclasses.dataclass(frozen=True)
class QualificationReport:
    platform_system: str
    architecture: str
    runtime_path: str | None
    runtime_detected: bool
    runtime_discovery: str

    @property
    def ready(self) -> bool:
        return False

    @property
    def qualified(self) -> bool:
        return False

    @property
    def autonomous_ready(self) -> bool:
        return False

    @property
    def checks(self) -> tuple[QualificationCheck, ...]:
        return REQUIRED_CHECKS

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "action": "sandbox.qualify",
            "schemaVersion": SCHEMA_VERSION,
            "backend": BACKEND,
            "mode": "offline",
            "reportKind": "offline-preflight",
            "status": "needs-validation",
            "ready": self.ready,
            "qualified": self.qualified,
            "autonomousReady": self.autonomous_ready,
            "liveChecksExecuted": False,
            "platform": {
                "system": self.platform_system,
                "architecture": self.architecture,
                "qualified": False,
            },
            "runtime": {
                "name": "sbx",
                "path": self.runtime_path,
                "detected": self.runtime_detected,
                "discovery": self.runtime_discovery,
                "executed": False,
                "version": None,
                "trustVerified": False,
            },
            "checks": [check.as_dict() for check in self.checks],
            "message": (
                "Offline inventory only: no Docker command or live qualification check "
                "was executed. This report is not a containment receipt and cannot "
                "enable autonomous Docker execution."
            ),
        }


def qualify(*, sbx_path: Path | None = None) -> QualificationReport:
    """Describe required evidence without executing or configuring a runtime."""
    discovery = "explicit" if sbx_path is not None else "path"
    candidate = os.fspath(sbx_path) if sbx_path is not None else shutil.which("sbx")
    runtime_path: str | None = None
    detected = False
    if candidate is not None:
        runtime_path = os.path.abspath(os.path.expanduser(candidate))
        try:
            detected = Path(runtime_path).is_file() and os.access(runtime_path, os.X_OK)
        except OSError:
            # Unreadable metadata leaves discovery unproven, never executable.
            detected = False
    elif sbx_path is None:
        discovery = "not-found"
    return QualificationReport(
        platform_system=platform.system(),
        architecture=platform.machine(),
        runtime_path=runtime_path,
        runtime_detected=detected,
        runtime_discovery=discovery,
    )
