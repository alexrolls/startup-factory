#!/usr/bin/env python3
"""Custom tracker code stays pinned through supervisor and release snapshots."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


pm_agent = load_module(ROOT / "bin" / "pm-agent.py", "custom_tracker_pm_agent_test")

with tempfile.TemporaryDirectory() as raw_tmp:
    tmp = Path(raw_tmp)
    skill = tmp / "protected-skill"
    project = tmp / "project"
    project.mkdir()

    for relative in pm_agent.RELEASE_SNAPSHOT_FILES.values():
        source = ROOT / relative
        destination = skill / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    (skill / "config" / "project-management.config.md").write_text(
        "PRODUCT_MANAGEMENT_TOOL=Acme\n"
        "STATUS_CONFIG=config/statuses.config.json\n"
    )
    custom_relative = Path("extensions/tracker-backends/Acme.py")
    custom_backend = skill / custom_relative
    custom_backend.parent.mkdir(parents=True, exist_ok=True)
    custom_backend.write_text(
        "class Backend:\n"
        "    def __init__(self, context):\n"
        "        self.context = context\n"
    )

    snapshot_files = dict(pm_agent.RELEASE_SNAPSHOT_FILES)
    custom_key = "tracker-backend.Acme.py"
    snapshot_files[custom_key] = custom_relative
    trusted = {
        name: digest(skill / relative)
        for name, relative in snapshot_files.items()
    }

    state_root = tmp / "supervisor-state"
    state_root.mkdir(mode=0o700)
    deployment_config = tmp / "deployment.json"
    deployment = {
        "schemaVersion": 1,
        "enabled": True,
        "mode": "automatic",
        "stateRoot": str(state_root),
        "planningEnvironmentAllowlist": [],
        "trackerEnvironmentAllowlist": ["TRACKER_ADAPTER"],
        "environmentAllowlist": [],
        "trustedCodeDigests": trusted,
        "timeoutsSeconds": {
            "plan": 1,
            "apply": 1,
            "status": 1,
            "verify": 1,
            "rollback": 1,
            "verifyDelivery": 1,
            "verifyApproval": 1,
        },
    }
    deployment_config.write_text(json.dumps(deployment, sort_keys=True))

    saved_environment = dict(os.environ)
    try:
        os.environ["STARTUP_FACTORY_DEPLOYMENT_CONFIG"] = str(deployment_config)
        os.environ["STARTUP_FACTORY_RELEASE_FEATURE"] = str(
            skill / "bin" / "release-feature.py"
        )
        os.environ["TRACKER_ADAPTER"] = "Acme"
        command, observed_config, release_environment = pm_agent.validate_release_handoff(
            project,
            dry_run=False,
        )
    finally:
        os.environ.clear()
        os.environ.update(saved_environment)

    assert command is not None
    assert observed_config is not None
    assert Path(observed_config).read_bytes() == deployment_config.read_bytes()
    assert release_environment is not None
    assert release_environment["TRACKER_ADAPTER"] == "Acme"
    release_script = Path(command[-1])
    supervisor_snapshot = release_script.parent.parent
    snapshotted_backend = supervisor_snapshot / custom_relative
    assert snapshotted_backend.read_bytes() == custom_backend.read_bytes()
    assert stat.S_IMODE(snapshotted_backend.stat().st_mode) == 0o400

    sys.path.insert(0, str(supervisor_snapshot / "bin"))
    try:
        saved_environment = dict(os.environ)
        os.environ["TRACKER_ADAPTER"] = "Acme"
        release_feature = load_module(
            release_script,
            "custom_tracker_release_feature_test",
        )
        specs = release_feature.trusted_file_specs()
        assert custom_key in specs
        assert specs[custom_key][1] == custom_relative
        config_digest, captured = release_feature.validate_release_trust(
            deployment_config,
            deployment,
            project,
        )
        assert captured[custom_key] == custom_backend.read_bytes()
        executor_state = tmp / "executor-state"
        executor_state.mkdir(mode=0o700)
        materialized = release_feature.materialize_trusted_code(
            executor_state,
            config_digest,
            captured,
            trusted,
        )
        assert (materialized / custom_relative).read_bytes() == custom_backend.read_bytes()
        assert stat.S_IMODE((materialized / custom_relative).stat().st_mode) == 0o400
    finally:
        os.environ.clear()
        os.environ.update(saved_environment)
        sys.path.pop(0)

print("ALL PASS")
