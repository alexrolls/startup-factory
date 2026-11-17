from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import cli, sandbox_qualification  # noqa: E402


EXPECTED_CHECK_IDS = (
    "version-platform",
    "mountless-startup",
    "policy-before-execution",
    "object-identity",
    "exec-protocol",
    "resource-limits",
    "cancellation-cleanup",
    "credentials",
)


def run_cli(*arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = cli.main(list(arguments))
    return result, stdout.getvalue(), stderr.getvalue()


class SandboxQualificationTest(unittest.TestCase):
    def assert_unqualified(self, report: dict) -> None:
        self.assertTrue(report["ok"])
        self.assertEqual(report["schemaVersion"], 1)
        self.assertEqual(report["action"], "sandbox.qualify")
        self.assertEqual(report["backend"], "docker-sandboxes")
        self.assertEqual(report["mode"], "offline")
        self.assertEqual(report["reportKind"], "offline-preflight")
        self.assertEqual(report["status"], "needs-validation")
        for key in ("qualified", "ready", "autonomousReady", "liveChecksExecuted"):
            self.assertIs(report[key], False, key)
        self.assertIs(report["platform"]["qualified"], False)
        self.assertIs(report["runtime"]["executed"], False)
        self.assertIs(report["runtime"]["trustVerified"], False)
        self.assertIsNone(report["runtime"]["version"])
        self.assertEqual(tuple(check["id"] for check in report["checks"]), EXPECTED_CHECK_IDS)
        for check in report["checks"]:
            self.assertIs(check["required"], True)
            self.assertIs(check["passed"], False)
            self.assertEqual(check["status"], "needs-validation")
            self.assertEqual(check["evidence"], [])
            self.assertTrue(check["requiredEvidence"])
            self.assertTrue(all(isinstance(item, str) and item for item in check["requiredEvidence"]))
            self.assertTrue(check["remediation"])

    def test_missing_runtime_reports_every_mandatory_gate_without_installation(self) -> None:
        with (
            mock.patch.object(sandbox_qualification.shutil, "which", return_value=None),
            mock.patch.object(cli, "resolve_target", side_effect=AssertionError("installation lookup")),
        ):
            code, output, error = run_cli("sandbox", "qualify", "--json")
        self.assertEqual((code, error), (1, ""))
        report = json.loads(output)
        self.assert_unqualified(report)
        self.assertEqual(report["runtime"]["discovery"], "not-found")
        self.assertIsNone(report["runtime"]["path"])
        self.assertFalse(report["runtime"]["detected"])

    def test_detected_executable_does_not_establish_version_or_containment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sf-qualification-") as temporary:
            root = Path(temporary)
            runtime = root / "sbx"
            marker = root / "executed"
            runtime.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
            runtime.chmod(0o755)
            before = runtime.read_bytes()
            with (
                mock.patch.object(sandbox_qualification.shutil, "which", return_value=str(runtime)),
                mock.patch("subprocess.run", side_effect=AssertionError("runtime execution")),
                mock.patch("subprocess.Popen", side_effect=AssertionError("runtime execution")),
            ):
                code, output, error = run_cli("sandbox", "qualify", "--json")
            self.assertEqual((code, error), (1, ""))
            report = json.loads(output)
            self.assert_unqualified(report)
            self.assertTrue(report["runtime"]["detected"])
            self.assertEqual(report["runtime"]["path"], os.path.abspath(runtime))
            self.assertEqual(report["runtime"]["discovery"], "path")
            self.assertEqual(runtime.read_bytes(), before)
            self.assertFalse(marker.exists())

    def test_explicit_runtime_path_is_passive_and_does_not_search_path(self) -> None:
        with (
            mock.patch.object(sandbox_qualification.shutil, "which", side_effect=AssertionError("PATH lookup")),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(sandbox_qualification.os, "access", return_value=True),
        ):
            report = sandbox_qualification.qualify(sbx_path=Path("/fixture/bin/sbx")).as_dict()
        self.assert_unqualified(report)
        self.assertEqual(report["runtime"]["path"], "/fixture/bin/sbx")
        self.assertEqual(report["runtime"]["discovery"], "explicit")
        self.assertTrue(report["runtime"]["detected"])

    def test_unavailable_explicit_runtime_stays_unproven(self) -> None:
        with mock.patch.object(Path, "is_file", side_effect=PermissionError("fixture")):
            report = sandbox_qualification.qualify(sbx_path=Path("/fixture/bin/sbx")).as_dict()
        self.assert_unqualified(report)
        self.assertFalse(report["runtime"]["detected"])

    def test_report_does_not_read_files_write_state_execute_commands_or_open_network(self) -> None:
        with (
            mock.patch.object(sandbox_qualification.shutil, "which", return_value=None),
            mock.patch.object(sandbox_qualification.platform, "system", return_value="Linux"),
            mock.patch.object(sandbox_qualification.platform, "machine", return_value="aarch64"),
            mock.patch("builtins.open", side_effect=AssertionError("file access")),
            mock.patch("os.open", side_effect=AssertionError("file access")),
            mock.patch("os.system", side_effect=AssertionError("command execution")),
            mock.patch("subprocess.run", side_effect=AssertionError("command execution")),
            mock.patch("subprocess.Popen", side_effect=AssertionError("command execution")),
            mock.patch("socket.socket", side_effect=AssertionError("network access")),
            mock.patch.object(Path, "read_bytes", side_effect=AssertionError("file read")),
            mock.patch.object(Path, "read_text", side_effect=AssertionError("file read")),
            mock.patch.object(Path, "write_bytes", side_effect=AssertionError("file write")),
            mock.patch.object(Path, "write_text", side_effect=AssertionError("file write")),
            mock.patch.object(Path, "mkdir", side_effect=AssertionError("directory creation")),
        ):
            code, output, error = run_cli("sandbox", "qualify", "--json")
        self.assertEqual((code, error), (1, ""))
        report = json.loads(output)
        self.assert_unqualified(report)
        self.assertEqual(report["platform"]["system"], "Linux")
        self.assertEqual(report["platform"]["architecture"], "aarch64")

    def test_text_report_explains_exit_status_and_lists_required_work(self) -> None:
        with mock.patch.object(sandbox_qualification.shutil, "which", return_value=None):
            code, output, error = run_cli("sandbox", "qualify")
        self.assertEqual((code, error), (1, ""))
        self.assertIn("needs validation (offline)", output)
        self.assertIn("cannot enable autonomous Docker execution", output)
        self.assertIn("no executable sbx detected", output)
        for identifier in EXPECTED_CHECK_IDS:
            self.assertIn(f"[needs-validation] {identifier}:", output)

    def test_cli_has_no_enablement_or_untrusted_evidence_input(self) -> None:
        for option in ("--enable", "--apply", "--evidence", "--backend"):
            with self.subTest(option=option):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                    cli.main(["sandbox", "qualify", option])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("unrecognized arguments", stderr.getvalue())

    def test_returned_json_cannot_mutate_subsequent_required_gates(self) -> None:
        with mock.patch.object(sandbox_qualification.shutil, "which", return_value=None):
            report = sandbox_qualification.qualify()
            altered = report.as_dict()
            altered["checks"][0]["passed"] = True
            altered["checks"].clear()
            self.assert_unqualified(report.as_dict())


if __name__ == "__main__":
    unittest.main()
