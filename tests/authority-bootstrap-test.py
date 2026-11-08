#!/usr/bin/env python3
"""Portable discovery fixtures plus real bootstrap trust-boundary checks."""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "bin" / "authority-bootstrap.sh"
SOURCE = BOOTSTRAP.read_text(encoding="utf-8")
FUNCTIONS = SOURCE.split("\nauthority_python_selection=", 1)[0]


class AuthorityBootstrapTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-bootstrap-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)

    def shell(self, body: str, *, definitions: str = FUNCTIONS) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-s"],
            input="set -euo pipefail\nSKILL_DIR=" + shlex.quote(str(ROOT)) + "\n"
            + definitions + "\n" + body,
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.fixture)},
            capture_output=True,
            text=True,
            check=False,
        )

    def executable(self, relative: str, content: str = "#!/bin/sh\nexit 0\n") -> Path:
        path = self.fixture / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_discovers_homebrew_versioned_formulas_without_unversioned_python(self) -> None:
        prefix = self.fixture / "homebrew"
        formula = self.executable("homebrew/opt/python@3.12/libexec/bin/python3")
        versioned = self.executable("homebrew/bin/python3.11")
        self.executable("homebrew/bin/python3.11-config")
        result = self.shell("authority_python_homebrew_candidates " + shlex.quote(str(prefix)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [str(formula), str(versioned)])
        self.assertFalse((prefix / "bin/python3").exists())

    def test_absent_homebrew_prefix_produces_no_literal_glob_candidates(self) -> None:
        result = self.shell("authority_python_homebrew_candidates " + shlex.quote(str(self.fixture / "absent")))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def simulated_selection(self, *, caller_path: str = "", unsafe_parent: bool = False) -> subprocess.CompletedProcess[str]:
        # No writes to global Homebrew directories: discovery maps one synthetic
        # fixed-prefix candidate to the real runtime. The selector's root check,
        # isolated Python probe, and identity comparison all still execute.
        python = shlex.quote(str(Path(sys.executable).resolve()))
        return self.shell(
            f"""
STARTUP_FACTORY_CALLER_PATH={shlex.quote(caller_path)}
authority_python_homebrew_candidates() {{
  [ "$1" != /opt/homebrew ] || printf '%s\\n' /opt/homebrew/opt/python@3.12/libexec/bin/python3
  return 0
}}
canonical_authority_executable() {{
  case "$1" in
    /opt/homebrew/opt/python@3.12/libexec/bin/python3|/usr/local/preferred/bin/python3) printf '%s\\n' {python} ;;
    *) return 1 ;;
  esac
}}
authority_python_parent_chain_is_protected() {{
  printf '%s\\n' "$1" >&2
  {'return 1' if unsafe_parent else 'return 0'}
}}
select_authority_python
"""
        )

    def test_selects_versioned_homebrew_before_legacy_system_fallback(self) -> None:
        result = self.simulated_selection()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split("\t", 1)[0], str(Path(sys.executable).resolve()))
        self.assertIn("/opt/homebrew/opt/python@3.12/libexec/bin/python3", result.stderr)
        self.assertNotIn("Python candidates rejected", result.stderr)

    def test_preserves_caller_path_preference(self) -> None:
        result = self.simulated_selection(caller_path="/usr/local/preferred/bin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/usr/local/preferred/bin/python3", result.stderr)
        self.assertNotIn("/opt/homebrew/opt/python@3.12/libexec/bin/python3", result.stderr)

    def test_rejects_unsafe_homebrew_parent_before_execution(self) -> None:
        result = self.simulated_selection(unsafe_parent=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("parent directory ownership or permissions are unsafe", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_failure_reports_rejections_and_recovery_command(self) -> None:
        # Keep the production final failure handler while preventing reliance on
        # whichever globally installed Python versions the test host has.
        before_initialization, initialization = SOURCE.split("\nauthority_python_selection=", 1)
        definitions = before_initialization + """
canonical_authority_executable() { return 1; }
authority_python_homebrew_candidates() { return 0; }
authority_python_selection=""" + initialization
        result = self.shell(":", definitions=definitions)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/opt/homebrew/bin/python3: missing", result.stderr)
        self.assertIn("/usr/bin/python3: missing", result.stderr)
        self.assertIn("trusted canonical Python >=3.10 is unavailable", result.stderr)
        self.assertIn("brew install python", result.stderr)

    def test_old_python_probe_explains_detected_version(self) -> None:
        probe = re.search(r'"\$canonical" -I -B -c \'\n(.*?)\n\' "\$canonical"', SOURCE, re.S)
        self.assertIsNotNone(probe)
        assert probe
        with mock.patch.object(sys, "version_info", (3, 9, 6)), \
                mock.patch.object(sys, "version", "3.9.6 (fixture)"), \
                mock.patch.object(sys, "argv", ["-c", sys.executable]):
            with self.assertRaisesRegex(SystemExit, "Python 3.9.6 is too old; version 3.10 or newer is required"):
                exec(compile(probe.group(1), "bootstrap-version-probe", "exec"), {})

    def test_untrusted_path_python_is_never_executed(self) -> None:
        canary = self.fixture / "executed"
        hostile = self.executable("hostile/python3", "#!/bin/sh\ntouch " + shlex.quote(str(canary)) + "\n")
        result = self.shell(
            "STARTUP_FACTORY_CALLER_PATH=" + shlex.quote(str(hostile.parent)) + "\n"
            "select_authority_python || :\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(canary.exists(), result.stderr)

    def test_symlink_to_untrusted_python_is_rejected_before_execution(self) -> None:
        canary = self.fixture / "executed"
        hostile = self.executable("hostile/python3", "#!/bin/sh\ntouch " + shlex.quote(str(canary)) + "\n")
        # The synthetic candidate is outside /tmp so canonical-root rejection
        # is exercised rather than only the early temporary-directory guard.
        result = self.shell(
            """
STARTUP_FACTORY_CALLER_PATH=/usr/local/fixture/bin
authority_python_homebrew_candidates() { return 0; }
canonical_authority_executable() {
  [ "$1" = /usr/local/fixture/bin/python3 ] || return 1
  printf '%s\\n' """ + shlex.quote(str(hostile)) + "\n}\nselect_authority_python\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical path is outside the approved executable locations", result.stderr)
        self.assertFalse(canary.exists())


if __name__ == "__main__":
    unittest.main()
