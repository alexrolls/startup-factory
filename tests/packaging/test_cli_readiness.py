from __future__ import annotations

import contextlib
import io
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import cli  # noqa: E402
from startup_factory_cli.installer import InstallerError  # noqa: E402
from startup_factory_cli.project_config import (  # noqa: E402
    apply_changes,
    plan_changes,
    read_project_config,
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
AGENT_SANDBOX_ENFORCED=true
BROKER_LIFECYCLE_ROOT=/protected/lifecycle
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
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / ".git").mkdir()
        self.target = self.root / "installed" / "startup-factory"
        payload = base_payload()
        payload["config/project-management.config.md"] = (PROJECT_CONFIG, 0o640)
        payload["adapters/Markdown.md"] = (b"markdown\n", 0o644)
        payload["adapters/Linear.md"] = (b"linear\n", 0o644)
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
        (self.target / "config/team.config.md").write_text(TEAM_CONFIG, encoding="utf-8")
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

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(self, command: str, *extra: str) -> tuple[int, str, str]:
        return run_cli(
            command,
            "--project",
            str(self.project),
            "--install-dir",
            str(self.target),
            *extra,
        )

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
        self.assertEqual(self.target.stat().st_mtime_ns, before)

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
