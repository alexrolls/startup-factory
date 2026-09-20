from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import cli  # noqa: E402
import startup_factory_cli.project_config as project_config  # noqa: E402
from startup_factory_cli.installer import InstallerError  # noqa: E402
from startup_factory_cli.project_config import (  # noqa: E402
    MAX_PROJECT_CONFIG_BYTES,
    apply_changes,
    apply_changes_at,
    plan_changes,
    read_project_config,
    read_project_config_at,
)
from tests.packaging.test_cli_installer import base_payload, write_bundle  # noqa: E402


PROJECT_CONFIG = b"""# Project configuration\r
PRODUCT_MANAGEMENT_TOOL=Markdown\r
PRODUCT_MANAGEMENT_TOOL_EXAMPLE=Ignored\r
TEAM_MODE=true         # keep this comment\r
STRICT_STATUS=true\r
"""

TEAM_CONFIG = """TEAM_LEAD_CMD="lead"
PRINCIPAL_ARCHITECT_CMD="principal"
SCEPTICAL_ARCHITECT_CMD="sceptical"
INTEGRATOR_CMD="integrator"
TRACKER_WRITERS=broker
AGENT_SANDBOX_RUNNER="__SANDBOX_RUNNER__"
AGENT_SANDBOX_ENFORCED=true
BROKER_LIFECYCLE_ROOT=__LIFECYCLE_ROOT__
VALIDATE_BUILD=null
VALIDATE_TEST="python -m unittest"
VALIDATE_LINT=null
VALIDATE_FORMAT=null
VALIDATE_SCRIPT=null
"""


def run_cli(*arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = cli.main(list(arguments))
    return result, stdout.getvalue(), stderr.getvalue()


class CliReadinessTest(unittest.TestCase):
    def setUp(self) -> None:
        # Keep the synthetic authority root outside shared /tmp on Linux. The
        # production doctor correctly rejects lifecycle state below shared
        # temporary directories, which would otherwise make positive doctor
        # fixtures platform-dependent.
        self.temp = tempfile.TemporaryDirectory(
            prefix=".startup-factory-cli-readiness-",
            dir=str(ROOT),
        )
        self.addCleanup(self.temp.cleanup)
        # macOS exposes /var through a symlink. Resolve the test sandbox so the
        # production reader can reject every symlinked ancestor unambiguously.
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / ".git").mkdir()
        self.target = self.root / "installed" / "startup-factory"
        self.lifecycle = self.root / "protected-lifecycle"
        self.lifecycle.mkdir(mode=0o700)
        # The production contract deliberately refuses operator-owned test
        # wrappers. /usr/bin/env is never executed by the offline doctor, but
        # provides a portable root-owned, root-ancestor structural fixture on
        # the supported macOS/Linux platforms.
        self.sandbox_runner = Path("/usr/bin/env")
        payload = base_payload()
        payload["config/project-management.config.md"] = (PROJECT_CONFIG, 0o640)
        payload["adapters/Markdown.md"] = (b"markdown\n", 0o644)
        payload["adapters/Linear.md"] = (b"linear\n", 0o644)
        for relative in (
            "extensions/integration-packs/schema.json",
            "extensions/integration-packs/tracker/markdown.json",
        ):
            payload[relative] = ((ROOT / relative).read_bytes(), 0o644)
        bundle = write_bundle(self.root / "readiness.tar.gz", payload=payload)
        code, output, error = run_cli(
            "install",
            "--project",
            str(self.project),
            "--install-dir",
            str(self.target),
            "--bundle",
            str(bundle),
            "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)
        self.config = self.target / "config/project-management.config.md"
        (self.target / "config/team.config.md").write_text(
            TEAM_CONFIG.replace("__LIFECYCLE_ROOT__", str(self.lifecycle)).replace(
                "__SANDBOX_RUNNER__", str(self.sandbox_runner)
            ),
            encoding="utf-8",
        )
        (self.target / "config/automation.config.json").write_text(
            json.dumps(
                {
                    "enabled": True,
                    "requireAgentSandbox": True,
                    "requireSingleTrackerWriter": True,
                }
            ),
            encoding="utf-8",
        )
        (self.target / "config/deployment.config.json").write_text(
            json.dumps(
                {
                    "enabled": True,
                    "mode": "approval-required",
                    "stateRoot": "/protected/release",
                    "credentialEnvFile": "/protected/release.env",
                    "planningIsolation": {
                        "enforced": True,
                        "separateIdentity": True,
                        "credentialPathsUnmounted": True,
                        "statePathsUnmounted": True,
                        "productionEgress": False,
                    },
                    "hooks": {
                        key: f"/protected/{key}"
                        for key in (
                            "plan",
                            "apply",
                            "status",
                            "verify",
                            "rollback",
                            "verifyCi",
                            "verifyDelivery",
                            "verifyApproval",
                        )
                    },
                }
            ),
            encoding="utf-8",
        )

    def invoke(self, command: str, *extra: str) -> tuple[int, str, str]:
        return run_cli(
            command,
            "--project",
            str(self.project),
            "--install-dir",
            str(self.target),
            *extra,
        )

    def invoke_pack(self, action: str, *extra: str) -> tuple[int, str, str]:
        return run_cli(
            "integration-pack",
            action,
            "--project",
            str(self.project),
            "--install-dir",
            str(self.target),
            *extra,
        )

    def test_installed_integration_pack_cli_has_json_and_human_surfaces(self) -> None:
        code, output, error = self.invoke_pack("list", "--json")
        self.assertEqual((code, error), (0, ""), output + error)
        catalog = json.loads(output)
        self.assertEqual(
            [pack["id"] for pack in catalog["packs"]],
            ["tracker-markdown"],
        )

        project_pack_root = self.project / ".startup-factory/integration-packs"
        project_pack_root.mkdir(parents=True)
        project_pack = json.loads(
            (ROOT / "extensions/integration-packs/tracker/markdown.json").read_text(
                encoding="utf-8"
            )
        )
        project_pack["id"] = "tracker-project-markdown"
        project_pack["displayName"] = "Project Markdown"
        project_pack["credentials"] = {
            "policy": "required-environment",
            "required": ["ACME_ACCESS_TOKEN"],
        }
        (project_pack_root / "markdown.json").write_text(
            json.dumps(project_pack, sort_keys=True), encoding="utf-8"
        )

        code, output, error = self.invoke_pack("list")
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertIn("Available integration packs: 2", output)
        self.assertIn("tracker-markdown [tracker]", output)
        self.assertIn("tracker-project-markdown [tracker]", output)
        self.assertIn("validate a pack", output)

        code, output, error = self.invoke_pack("validate", "tracker-markdown")
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertIn("Validated integration pack: tracker-markdown [tracker]", output)
        self.assertIn("Source digest: sha256:", output)

        code, output, error = self.invoke_pack(
            "doctor", "tracker-project-markdown", "--json"
        )
        self.assertEqual((code, error), (1, ""), output + error)
        local_report = json.loads(output)
        self.assertEqual(local_report["overall"], "red")
        self.assertFalse(local_report["localReady"])
        self.assertEqual(local_report["credentials"]["missing"], ["ACME_ACCESS_TOKEN"])
        self.assertTrue(
            any(
                "listed credential environment names" in action
                for action in local_report["operatorActions"]
            )
        )

        code, output, error = self.invoke_pack("validate", "missing-pack", "--json")
        self.assertEqual((code, output), (1, ""))
        self.assertEqual(
            json.loads(error)["error"],
            "integration pack id is unknown or ambiguous: missing-pack",
        )

    def test_installed_pack_preview_apply_and_doctor_are_guided_and_secret_safe(self) -> None:
        self.config.write_bytes(PROJECT_CONFIG.replace(b"TEAM_MODE=true", b"TEAM_MODE=false"))
        code, output, error = self.invoke_pack(
            "preview", "tracker-markdown", "--json"
        )
        self.assertEqual((code, error), (0, ""), output + error)
        plan = json.loads(output)
        self.assertEqual(plan["operation"], "update-project-config")
        self.assertEqual(plan["changes"][0]["key"], "TEAM_MODE")
        plan_path = self.project / "tracker-markdown-plan.json"
        plan_path.write_text(output, encoding="utf-8")

        code, output, error = self.invoke_pack("apply", str(plan_path))
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertIn("Applied integration pack: tracker-markdown [tracker]", output)
        self.assertIn("external proof remains separate", output)
        self.assertIn(b"TEAM_MODE=true", self.config.read_bytes())

        secret = "operator-secret-must-not-appear"
        with mock.patch.dict(os.environ, {"UNRELATED_TOKEN": secret}):
            code, output, error = self.invoke_pack(
                "doctor", "tracker-markdown", "--json"
            )
        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        self.assertEqual(report["configured"]["status"], "configured")
        self.assertEqual(report["proved"]["status"], "unknown")
        self.assertEqual(report["credentials"]["status"], "not-required")
        self.assertEqual(report["overall"], "yellow")
        self.assertTrue(report["localReady"])
        self.assertFalse(report["ready"])
        self.assertTrue(report["operatorActions"])
        self.assertFalse(any("authenticate an adapter" in item for item in report["operatorActions"]))
        self.assertNotIn(secret, output)

        code, output, error = self.invoke_pack("doctor", "tracker-markdown")
        self.assertEqual((code, error), (1, ""), output + error)
        self.assertIn("Integration-pack doctor: yellow (tracker-markdown [tracker])", output)
        self.assertIn("[proved] unknown", output)
        self.assertIn("Operator actions:", output)

    def test_init_previews_by_default_without_writing(self) -> None:
        before = self.config.read_bytes()
        code, output, error = self.invoke("init", "--mode", "solo", "--json")
        self.assertEqual((code, error), (0, ""), output + error)
        result = json.loads(output)
        self.assertEqual(result["schemaVersion"], 1)
        self.assertFalse(result["applied"])
        self.assertTrue(result["applySupported"])
        self.assertEqual(
            result["changes"],
            [{"key": "TEAM_MODE", "before": "true", "after": "false"}],
        )
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(list(self.config.parent.glob(".*.tmp")), [])

    def test_init_applies_both_exact_keys_and_preserves_all_other_bytes_and_mode(self) -> None:
        code, output, error = self.invoke(
            "init",
            "--mode",
            "solo",
            "--product-management-tool",
            "Linear",
            "--apply",
            "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)
        result = json.loads(output)
        self.assertTrue(result["applied"])
        expected = PROJECT_CONFIG.replace(
            b"PRODUCT_MANAGEMENT_TOOL=Markdown", b"PRODUCT_MANAGEMENT_TOOL=Linear"
        ).replace(b"TEAM_MODE=true", b"TEAM_MODE=false")
        self.assertEqual(self.config.read_bytes(), expected)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o640)
        self.assertIn(b"PRODUCT_MANAGEMENT_TOOL_EXAMPLE=Ignored", self.config.read_bytes())

    def test_duplicate_exact_key_is_rejected_before_mutation(self) -> None:
        self.config.write_bytes(PROJECT_CONFIG + b"TEAM_MODE=false\n")
        before = self.config.read_bytes()
        code, _, error = self.invoke("init", "--mode", "solo", "--apply", "--json")
        self.assertEqual(code, 1)
        self.assertIn("duplicate exact key: TEAM_MODE", error)
        self.assertEqual(self.config.read_bytes(), before)

    def test_config_symlink_is_refused_without_touching_target(self) -> None:
        sentinel = self.root / "sentinel-config"
        sentinel.write_bytes(PROJECT_CONFIG)
        self.config.unlink()
        self.config.symlink_to(sentinel)
        code, _, error = self.invoke("init", "--mode", "solo", "--apply", "--json")
        self.assertEqual(code, 1)
        self.assertIn("preserved config is missing or not regular", error)
        self.assertEqual(sentinel.read_bytes(), PROJECT_CONFIG)

    def test_init_refuses_missing_selected_adapter_before_mutation(self) -> None:
        before = self.config.read_bytes()
        code, _, error = self.invoke(
            "init",
            "--mode",
            "solo",
            "--product-management-tool",
            "Missing",
            "--apply",
            "--json",
        )
        self.assertEqual(code, 1)
        self.assertIn("selected project-management adapter", error)
        self.assertIn("Missing", error)
        self.assertEqual(self.config.read_bytes(), before)

    def test_init_refuses_tampered_immutable_installation(self) -> None:
        before = self.config.read_bytes()
        runtime = self.target / "bin/runtime.sh"
        runtime.write_text("tampered\n", encoding="utf-8")
        code, _, error = self.invoke("init", "--mode", "solo", "--apply", "--json")
        self.assertEqual(code, 1)
        self.assertIn("digest mismatch", error)
        self.assertEqual(self.config.read_bytes(), before)

    def test_concurrent_change_is_detected_before_atomic_replace(self) -> None:
        loaded = read_project_config(self.config)
        changes = plan_changes(loaded, {"TEAM_MODE": "false"})
        concurrent = PROJECT_CONFIG.replace(b"STRICT_STATUS=true", b"STRICT_STATUS=false")
        self.config.write_bytes(concurrent)
        with self.assertRaisesRegex(InstallerError, "changed while init was preparing"):
            apply_changes(loaded, changes)
        self.assertEqual(self.config.read_bytes(), concurrent)

    def test_atomic_exchange_restores_a_change_made_at_the_commit_boundary(self) -> None:
        loaded = read_project_config(self.config)
        changes = plan_changes(loaded, {"TEAM_MODE": "false"})
        concurrent = PROJECT_CONFIG.replace(
            b"STRICT_STATUS=true", b"STRICT_STATUS=false"
        )
        original_exchange = project_config._atomic_exchange_at
        exchanges = 0

        def racing_exchange(
            parent_descriptor: int, first_name: str, second_name: str
        ) -> None:
            nonlocal exchanges
            exchanges += 1
            if exchanges == 1:
                self.config.write_bytes(concurrent)
            original_exchange(parent_descriptor, first_name, second_name)

        with mock.patch.object(
            project_config, "_atomic_exchange_at", side_effect=racing_exchange
        ):
            with self.assertRaisesRegex(InstallerError, "atomic exchange boundary"):
                apply_changes(loaded, changes)

        self.assertEqual(exchanges, 2)
        self.assertEqual(self.config.read_bytes(), concurrent)
        self.assertEqual(list(self.config.parent.glob(f".{self.config.name}.*.tmp")), [])

    def test_ambiguous_post_exchange_change_retains_recovery_bytes(self) -> None:
        loaded = read_project_config(self.config)
        changes = plan_changes(loaded, {"TEAM_MODE": "false"})
        after_exchange = PROJECT_CONFIG.replace(
            b"STRICT_STATUS=true", b"STRICT_STATUS=false"
        )
        original_exchange = project_config._atomic_exchange_at
        exchanges = 0

        def racing_exchange(
            parent_descriptor: int, first_name: str, second_name: str
        ) -> None:
            nonlocal exchanges
            exchanges += 1
            original_exchange(parent_descriptor, first_name, second_name)
            if exchanges == 1:
                self.config.write_bytes(after_exchange)

        with mock.patch.object(
            project_config, "_atomic_exchange_at", side_effect=racing_exchange
        ):
            with self.assertRaisesRegex(InstallerError, "recoverable original bytes"):
                apply_changes(loaded, changes)

        recovery = list(self.config.parent.glob(f".{self.config.name}.*.tmp"))
        self.assertEqual(exchanges, 1)
        self.assertEqual(self.config.read_bytes(), after_exchange)
        self.assertEqual(len(recovery), 1)
        self.assertEqual(recovery[0].read_bytes(), PROJECT_CONFIG)

    def test_missing_platform_exchange_primitive_fails_closed(self) -> None:
        loaded = read_project_config(self.config)
        changes = plan_changes(loaded, {"TEAM_MODE": "false"})
        with mock.patch.object(project_config.sys, "platform", "unsupported-os"):
            with self.assertRaisesRegex(InstallerError, "exchange is unsupported"):
                apply_changes(loaded, changes)
        self.assertEqual(self.config.read_bytes(), PROJECT_CONFIG)
        self.assertEqual(list(self.config.parent.glob(f".{self.config.name}.*.tmp")), [])

    def test_dirfd_api_reads_and_updates_beneath_verified_root(self) -> None:
        root_descriptor = os.open(
            self.target,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            loaded = read_project_config_at(root_descriptor)
            changes = plan_changes(loaded, {"TEAM_MODE": "false"})
            apply_changes_at(loaded, changes, root_descriptor)
        finally:
            os.close(root_descriptor)
        self.assertIn(b"TEAM_MODE=false", self.config.read_bytes())

    def test_oversize_config_and_nonblocking_fifo_are_rejected(self) -> None:
        self.config.write_bytes(b"x" * (MAX_PROJECT_CONFIG_BYTES + 1))
        with self.assertRaisesRegex(InstallerError, "exceeds .*byte limit"):
            read_project_config(self.config)

        self.config.unlink()
        os.mkfifo(self.config)
        real_open = os.open

        def audited_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if path == self.config.name and dir_fd is not None:
                self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch(
            "startup_factory_cli.project_config.os.open", side_effect=audited_open
        ):
            with self.assertRaisesRegex(InstallerError, "not a regular file"):
                read_project_config(self.config)

    def test_in_place_change_during_read_is_rejected_by_post_read_snapshot(self) -> None:
        real_fstat = os.fstat
        regular_snapshots = 0

        def racing_fstat(descriptor: int) -> os.stat_result:
            nonlocal regular_snapshots
            metadata = real_fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                regular_snapshots += 1
                if regular_snapshots == 2:
                    self.config.write_bytes(
                        PROJECT_CONFIG.replace(
                            b"STRICT_STATUS=true", b"STRICT_STATUS=false"
                        )
                    )
                    metadata = real_fstat(descriptor)
            return metadata

        with mock.patch(
            "startup_factory_cli.project_config.os.fstat", side_effect=racing_fstat
        ):
            with self.assertRaisesRegex(InstallerError, "changed while it was being read"):
                read_project_config(self.config)

    def test_final_name_swap_after_read_is_rejected_without_following_link(self) -> None:
        outside = self.root / "outside-final-name"
        outside.mkdir()
        outside_config = outside / self.config.name
        outside_config.write_bytes(PROJECT_CONFIG)
        retained = self.root / "retained-final-name-config"
        real_stat = os.stat
        swapped = False

        def racing_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
            nonlocal swapped
            if path == self.config.name and kwargs.get("dir_fd") is not None and not swapped:
                swapped = True
                self.config.rename(retained)
                self.config.symlink_to(outside_config)
            return real_stat(path, *args, **kwargs)

        with mock.patch(
            "startup_factory_cli.project_config.os.stat", side_effect=racing_stat
        ):
            with self.assertRaisesRegex(InstallerError, "changed while it was being read"):
                read_project_config(self.config)

        self.assertTrue(swapped)
        self.assertEqual(outside_config.read_bytes(), PROJECT_CONFIG)

    def test_parent_swap_cannot_redirect_config_read_through_symlink(self) -> None:
        outside = self.root / "outside-read"
        outside.mkdir()
        outside_config = outside / self.config.name
        outside_content = PROJECT_CONFIG.replace(b"TEAM_MODE=true", b"TEAM_MODE=false")
        outside_config.write_bytes(outside_content)
        original_parent = self.config.parent
        retained_parent = self.root / "retained-read-config"
        real_open = os.open
        swapped = False

        def racing_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            if path == self.config.name and dir_fd is not None and not swapped:
                swapped = True
                original_parent.rename(retained_parent)
                original_parent.symlink_to(outside, target_is_directory=True)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("startup_factory_cli.project_config.os.open", side_effect=racing_open):
            loaded = read_project_config(self.config)

        self.assertTrue(swapped)
        self.assertEqual(loaded.value("TEAM_MODE"), "true")
        self.assertEqual(outside_config.read_bytes(), outside_content)

    def test_parent_swap_cannot_redirect_atomic_write_through_symlink(self) -> None:
        loaded = read_project_config(self.config)
        changes = plan_changes(loaded, {"TEAM_MODE": "false"})
        outside = self.root / "outside-write"
        outside.mkdir()
        outside_config = outside / self.config.name
        outside_config.write_bytes(PROJECT_CONFIG)
        original_parent = self.config.parent
        retained_parent = self.root / "retained-write-config"
        real_open = os.open
        swapped = False

        def racing_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            is_temporary = isinstance(path, str) and path.startswith(f".{self.config.name}.")
            if is_temporary and dir_fd is not None and not swapped:
                swapped = True
                original_parent.rename(retained_parent)
                original_parent.symlink_to(outside, target_is_directory=True)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("startup_factory_cli.project_config.os.open", side_effect=racing_open):
            apply_changes(loaded, changes)

        self.assertTrue(swapped)
        self.assertIn(b"TEAM_MODE=false", (retained_parent / self.config.name).read_bytes())
        self.assertEqual(outside_config.read_bytes(), PROJECT_CONFIG)
        self.assertEqual(list(retained_parent.glob(".*.tmp")), [])

    def test_protected_modes_are_preview_only_and_apply_is_rejected(self) -> None:
        before = self.config.read_bytes()
        for mode in ("autonomous", "release"):
            with self.subTest(mode=mode):
                code, output, error = self.invoke("init", "--mode", mode, "--json")
                self.assertEqual((code, error), (0, ""), output + error)
                self.assertFalse(json.loads(output)["applySupported"])
                code, _, error = self.invoke(
                    "init", "--mode", mode, "--apply", "--json"
                )
                self.assertEqual(code, 1)
                self.assertIn("cannot enable", error)
        self.assertEqual(self.config.read_bytes(), before)

    def test_valid_solo_doctor_stays_non_green_without_tracker_operation_proof(self) -> None:
        code, output, error = self.invoke(
            "init", "--mode", "solo", "--apply", "--json"
        )
        self.assertEqual((code, error), (0, ""), output + error)
        code, output, error = self.invoke("doctor", "--mode", "solo", "--json")
        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        self.assertEqual(report["overall"], "yellow")
        self.assertFalse(report["ready"])
        self.assertEqual(
            [check["id"] for check in report["checks"]],
            [
                "installation.detected",
                "installation.verified",
                "repository.detected",
                "project-config.detected",
                "project-config.valid",
                "tracker-adapter.configured",
                "workflow-mode.configured",
                "local-configuration.proved",
                "tracker-operation.proved",
            ],
        )
        self.assertEqual(
            {check["level"] for check in report["checks"]},
            {"detected", "configured", "proved"},
        )
        self.assertEqual(
            {check["status"] for check in report["checks"]}, {"pass", "unknown"}
        )
        tracker_proof = report["checks"][-1]
        self.assertEqual(tracker_proof["id"], "tracker-operation.proved")
        self.assertEqual(tracker_proof["status"], "unknown")

    def test_team_doctor_is_non_green_when_runtime_proof_is_unknown(self) -> None:
        before = self.target.stat().st_mtime_ns
        code, output, error = self.invoke("doctor", "--mode", "team", "--json")
        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        self.assertEqual(report["overall"], "yellow")
        self.assertFalse(report["ready"])
        proof = next(check for check in report["checks"] if check["id"] == "team-runtime.proved")
        self.assertEqual((proof["level"], proof["status"]), ("proved", "unknown"))
        lifecycle = next(
            check
            for check in report["checks"]
            if check["id"] == "lifecycle-authority.configured"
        )
        self.assertEqual((lifecycle["level"], lifecycle["status"]), ("configured", "pass"))
        sandbox = next(
            check
            for check in report["checks"]
            if check["id"] == "sandbox-runner.configured"
        )
        self.assertEqual((sandbox["level"], sandbox["status"]), ("configured", "pass"))
        self.assertIn("was not executed", sandbox["message"])
        self.assertEqual(self.target.stat().st_mtime_ns, before)

    def test_team_doctor_warns_when_external_sandbox_runner_is_absent(self) -> None:
        team_config = self.target / "config/team.config.md"
        team_config.write_text(
            team_config.read_text(encoding="utf-8").replace(
                f'AGENT_SANDBOX_RUNNER="{self.sandbox_runner}"',
                "AGENT_SANDBOX_RUNNER=null",
            ),
            encoding="utf-8",
        )

        code, output, error = self.invoke("doctor", "--mode", "team", "--json")

        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        sandbox = next(
            check
            for check in report["checks"]
            if check["id"] == "sandbox-runner.configured"
        )
        self.assertEqual((report["overall"], report["ready"]), ("yellow", False))
        self.assertEqual((sandbox["level"], sandbox["status"]), ("configured", "warn"))
        self.assertIn("not configured", sandbox["message"])
        self.assertIn("does not ship this runner", sandbox["remediation"])

    def test_team_doctor_reports_disabled_sandbox_enforcement(self) -> None:
        team_config = self.target / "config/team.config.md"
        team_config.write_text(
            team_config.read_text(encoding="utf-8").replace(
                "AGENT_SANDBOX_ENFORCED=true",
                "AGENT_SANDBOX_ENFORCED=false",
            ),
            encoding="utf-8",
        )

        code, output, error = self.invoke("doctor", "--mode", "team", "--json")

        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        sandbox = next(
            check
            for check in report["checks"]
            if check["id"] == "sandbox-runner.configured"
        )
        self.assertEqual((report["overall"], report["ready"]), ("yellow", False))
        self.assertEqual(sandbox["status"], "warn")
        self.assertIn("is not true", sandbox["message"])

    def test_team_doctor_rejects_unsafe_runner_structure_without_executing_it(self) -> None:
        team_config = self.target / "config/team.config.md"
        original = team_config.read_text(encoding="utf-8")
        unsafe_cases = (
            ("relative-runner", "absolute normalized path"),
            (str(self.project / "runner"), "not root-owned"),
        )
        (self.project / "runner").write_text("#!/bin/sh\nexit 98\n", encoding="utf-8")
        (self.project / "runner").chmod(0o700)

        for runner, expected in unsafe_cases:
            with self.subTest(runner=runner):
                team_config.write_text(
                    original.replace(
                        f'AGENT_SANDBOX_RUNNER="{self.sandbox_runner}"',
                        f'AGENT_SANDBOX_RUNNER="{runner}"',
                    ),
                    encoding="utf-8",
                )
                code, output, error = self.invoke(
                    "doctor", "--mode", "team", "--json"
                )
                self.assertEqual((code, error), (1, ""), output + error)
                report = json.loads(output)
                sandbox = next(
                    check
                    for check in report["checks"]
                    if check["id"] == "sandbox-runner.configured"
                )
                self.assertEqual(sandbox["status"], "warn")
                self.assertIn(expected, sandbox["message"])

        # This system executable would not understand the sandbox-runner
        # protocol. Reaching this assertion proves the offline doctor only
        # inspected metadata and never executed it.
        self.assertTrue(self.sandbox_runner.exists())

    def test_team_doctor_reports_broker_writer_boundary_explicitly(self) -> None:
        team_config = self.target / "config/team.config.md"
        team_config.write_text(
            team_config.read_text(encoding="utf-8").replace(
                "TRACKER_WRITERS=broker", "TRACKER_WRITERS=all"
            ),
            encoding="utf-8",
        )

        code, output, error = self.invoke("doctor", "--mode", "team", "--json")

        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        boundary = next(
            check
            for check in report["checks"]
            if check["id"] == "tracker-writer-boundary.configured"
        )
        self.assertEqual((report["overall"], report["ready"]), ("yellow", False))
        self.assertEqual(boundary["status"], "warn")
        self.assertIn("TRACKER_WRITERS", boundary["message"])

        code, output, error = self.invoke(
            "doctor", "--mode", "autonomous", "--json"
        )
        self.assertEqual((code, error), (1, ""), output + error)
        protected_report = json.loads(output)
        protected_boundary = next(
            check
            for check in protected_report["checks"]
            if check["id"] == "tracker-writer-boundary.configured"
        )
        self.assertEqual(protected_report["overall"], "red")
        self.assertEqual(protected_boundary["status"], "fail")

    def test_team_doctor_fails_closed_and_guides_missing_lifecycle_authority(self) -> None:
        team_config = self.target / "config/team.config.md"
        team_config.write_text(
            team_config.read_text(encoding="utf-8").replace(
                f"BROKER_LIFECYCLE_ROOT={self.lifecycle}",
                "BROKER_LIFECYCLE_ROOT=null",
            ),
            encoding="utf-8",
        )
        code, output, error = self.invoke("doctor", "--mode", "team", "--json")
        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        lifecycle = next(
            check
            for check in report["checks"]
            if check["id"] == "lifecycle-authority.configured"
        )
        self.assertEqual(lifecycle["status"], "fail")
        self.assertIn("not configured", lifecycle["message"])
        self.assertIn("mode-0700", lifecycle["remediation"])
        self.assertIn("deny agent sandboxes access", lifecycle["remediation"])

    def test_team_doctor_rejects_shared_temporary_lifecycle_authority(self) -> None:
        shared_parent = Path("/tmp").resolve()
        with tempfile.TemporaryDirectory(
            prefix="startup-factory-lifecycle-", dir=str(shared_parent)
        ) as shared_name:
            shared = Path(shared_name).resolve()
            shared.chmod(0o700)
            team_config = self.target / "config/team.config.md"
            team_config.write_text(
                team_config.read_text(encoding="utf-8").replace(
                    f"BROKER_LIFECYCLE_ROOT={self.lifecycle}",
                    f"BROKER_LIFECYCLE_ROOT={shared}",
                ),
                encoding="utf-8",
            )

            code, output, error = self.invoke("doctor", "--mode", "team", "--json")

        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        lifecycle = next(
            check
            for check in report["checks"]
            if check["id"] == "lifecycle-authority.configured"
        )
        self.assertEqual((report["overall"], report["ready"]), ("red", False))
        self.assertEqual(lifecycle["status"], "fail")
        self.assertIn("below a shared temporary directory", lifecycle["message"])

    def test_team_doctor_rejects_lifecycle_authority_inside_repository(self) -> None:
        unsafe = self.project / "authority"
        unsafe.mkdir(mode=0o700)
        team_config = self.target / "config/team.config.md"
        team_config.write_text(
            team_config.read_text(encoding="utf-8").replace(
                f"BROKER_LIFECYCLE_ROOT={self.lifecycle}",
                f"BROKER_LIFECYCLE_ROOT={unsafe}",
            ),
            encoding="utf-8",
        )
        code, output, error = self.invoke("doctor", "--mode", "team", "--json")
        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        lifecycle = next(
            check
            for check in report["checks"]
            if check["id"] == "lifecycle-authority.configured"
        )
        self.assertEqual(lifecycle["status"], "fail")
        self.assertIn("not disjoint", lifecycle["message"])

    def test_marker_only_fake_installation_is_detected_but_not_verified(self) -> None:
        fake = self.root / "fake-startup-factory"
        (fake / "config").mkdir(parents=True)
        (fake / "adapters").mkdir()
        (fake / "SKILL.md").write_text(
            "---\nname: startup-factory\ndescription: fake\n---\n", encoding="utf-8"
        )
        fake_config = PROJECT_CONFIG.replace(b"TEAM_MODE=true", b"TEAM_MODE=false")
        (fake / "config/project-management.config.md").write_bytes(fake_config)
        (fake / "adapters/Markdown.md").write_text("fake\n", encoding="utf-8")

        code, output, error = run_cli(
            "doctor",
            "--project",
            str(self.project),
            "--install-dir",
            str(fake),
            "--mode",
            "solo",
            "--json",
        )
        self.assertEqual((code, error), (1, ""), output + error)
        report = json.loads(output)
        checks = {check["id"]: check for check in report["checks"]}
        self.assertEqual(checks["installation.detected"]["status"], "pass")
        self.assertEqual(checks["installation.verified"]["status"], "fail")
        self.assertEqual(report["overall"], "red")
        self.assertFalse(report["ready"])

    def test_autonomous_and_release_doctor_never_turn_unknown_proof_green(self) -> None:
        for mode, proof_id in (
            ("autonomous", "protected-autonomy.proved"),
            ("release", "protected-release.proved"),
        ):
            with self.subTest(mode=mode):
                code, output, error = self.invoke("doctor", "--mode", mode, "--json")
                self.assertEqual((code, error), (1, ""), output + error)
                report = json.loads(output)
                proof = next(check for check in report["checks"] if check["id"] == proof_id)
                self.assertEqual(proof["status"], "unknown")
                self.assertNotEqual(report["overall"], "green")


if __name__ == "__main__":
    unittest.main()
