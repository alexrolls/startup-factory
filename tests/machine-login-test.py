#!/usr/bin/env python3
"""Dedicated-home login and presentation-only doctor report regressions."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli.config_values import parse_config_bytes, value_for
SPEC = importlib.util.spec_from_file_location("machine_login", ROOT / "bin/machine-login.py")
LOGIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOGIN)
SOURCE = (ROOT / "bin/launch-team.sh").read_text(encoding="utf-8")


class MachineLoginTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-machine-login-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name).resolve()
        self.agent = self.fixture / "agent-home"
        self.agent.mkdir(mode=0o700)
        self.account = self.fixture / "account-home"
        (self.account / "Library/Keychains").mkdir(parents=True, mode=0o700)
        (self.account / "Library/Keychains/login.keychain-db").write_text("fixture credential store")

    def shell(self, body: str, *, definitions: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-s"],
            input="set -euo pipefail\n" + definitions + "\n" + body,
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.account), "USER": "untrusted-user",
                 "ANTHROPIC_API_KEY": "secret-must-not-pass", "OPENAI_API_KEY": "also-secret"},
            text=True, capture_output=True, check=False,
        )

    def test_empty_macos_home_refuses_before_touching_keychains(self) -> None:
        with self.assertRaisesRegex(LOGIN.MachineSetupError, "--share-macos-keychain") as failure:
            LOGIN.prepare_macos_keychains(self.agent, self.account, False)
        self.assertIn("Never click 'Reset To Defaults'", str(failure.exception))
        self.assertFalse((self.agent / "Library").exists())
        self.assertEqual((self.account / "Library/Keychains/login.keychain-db").read_text(), "fixture credential store")

    def test_explicit_keychain_sharing_is_idempotent_and_preserves_original(self) -> None:
        LOGIN.prepare_macos_keychains(self.agent, self.account, True)
        destination = self.agent / "Library/Keychains"
        self.assertTrue(destination.is_symlink())
        self.assertEqual(destination.resolve(), self.account / "Library/Keychains")
        LOGIN.prepare_macos_keychains(self.agent, self.account, True)
        LOGIN.prepare_macos_keychains(self.agent, self.account, False)
        self.assertEqual((self.agent / "Library").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.account / "Library/Keychains/login.keychain-db").read_text(), "fixture credential store")

    def test_keychain_opt_in_refuses_existing_directory_or_foreign_link(self) -> None:
        library = self.agent / "Library"
        library.mkdir(mode=0o700)
        destination = library / "Keychains"
        destination.mkdir()
        with self.assertRaisesRegex(LOGIN.MachineSetupError, "refusing to replace"):
            LOGIN.prepare_macos_keychains(self.agent, self.account, True)
        destination.rmdir()
        destination.symlink_to(self.fixture)
        with self.assertRaisesRegex(LOGIN.MachineSetupError, "refusing to replace"):
            LOGIN.prepare_macos_keychains(self.agent, self.account, True)
        self.assertEqual(destination.resolve(), self.fixture)

    def test_keychain_opt_in_refuses_library_symlink(self) -> None:
        (self.agent / "Library").symlink_to(self.account / "Library")
        with self.assertRaisesRegex(LOGIN.MachineSetupError, "real directory"):
            LOGIN.prepare_macos_keychains(self.agent, self.account, True)

    def test_sandbox_environment_pins_home_and_account_identity_and_strips_secrets(self) -> None:
        environment = "prepare_agent_env() {" + SOURCE.split("prepare_agent_env() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        definitions = environment + f"""
python3() {{ {shlex.quote(sys.executable)} "$@"; }}
validate_agent_env_allowlist() {{ :; }}
read_key() {{ [ "$1" != AGENT_ENV_ALLOWLIST ] || printf '%s' 'PATH USER LOGNAME'; }}
die() {{ printf '%s\\n' "$*" >&2; exit 1; }}
PUBLICATION_AUTHORITY_ENABLED=false
AGENT_SANDBOX_HOME_PATH={shlex.quote(str(self.agent))}
"""
        result = self.shell('prepare_agent_env login setup setup full-stack setup - 0\n/usr/bin/env "${AGENT_ENV_ARGS[@]}" /usr/bin/env', definitions=definitions)
        self.assertEqual(result.returncode, 0, result.stderr)
        environment = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(environment["HOME"], str(self.agent))
        self.assertEqual(environment["USER"], pwd.getpwuid(os.geteuid()).pw_name)
        self.assertEqual(environment["LOGNAME"], environment["USER"])
        self.assertNotIn("ANTHROPIC_API_KEY", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)

    def login_harness(self, cli: str, enforced: bool) -> subprocess.CompletedProcess[str]:
        # Exercise the production shell function with a fixed fixture CLI; the
        # independent shared CLI-validator tests cover executable trust.
        executable = self.fixture / "fixture-cli"
        executable.write_text("#!/bin/sh\n/usr/bin/printf '%s\\n' \"$@\"\n/usr/bin/env\n", encoding="utf-8")
        executable.chmod(0o700)
        runner = self.fixture / "runner"
        runner.write_text('#!/bin/sh\nprintf "runner:%s:%s:%s\\n" "$1" "$2" "$3"\nshift 3\nexec "$@"\n', encoding="utf-8")
        runner.chmod(0o700)
        login = "login() {" + SOURCE.split("\nlogin() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        definitions = login + f"""
AGENT_SANDBOX_HOME_PATH={shlex.quote(str(self.agent))}
AGENT_SANDBOX_RUNNER_PATH={shlex.quote(str(runner))}
REPO_ROOT={shlex.quote(str(self.fixture))}
SKILL_DIR={shlex.quote(str(ROOT))}
read_key() {{
  case "$1" in
    CLAUDE_CLI_PATH|CODEX_CLI_PATH) printf '%s' {shlex.quote(str(executable))} ;;
    AGENT_SANDBOX_ENFORCED) printf '%s' {'true' if enforced else 'false'} ;;
  esac
}}
python3() {{ printf '%s\\n' {shlex.quote(str(executable))}; }}
prepare_agent_env() {{ AGENT_ENV_ARGS=(-i PATH=/usr/bin:/bin HOME="$AGENT_SANDBOX_HOME_PATH" USER=fixture-user); }}
validate_sandbox_runner_config() {{ :; }}
die() {{ printf '%s\\n' "$*" >&2; exit 1; }}
"""
        return self.shell("login " + cli, definitions=definitions)

    def test_login_uses_fixed_provider_argv_and_sanitized_environment(self) -> None:
        for cli, expected in (("claude", "auth\nlogin\n"), ("codex", "login\n")):
            with self.subTest(cli=cli):
                result = self.login_harness(cli, False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertIn("HOME=" + str(self.agent), result.stdout)
                self.assertNotIn("secret-must-not-pass", result.stdout)
                self.assertNotIn("OPENAI_API_KEY", result.stdout)

    def test_login_uses_configured_runner_without_a_shell_command(self) -> None:
        result = self.login_harness("codex", True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"runner:--workdir:{self.fixture}:--\nlogin\n", result.stdout)
        self.assertNotIn("bash -c", result.stdout)

    def test_login_prepends_a_pinned_interpreter_as_an_argv_element(self) -> None:
        interpreter = self.fixture / "node interpreter"
        interpreter.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n', encoding="utf-8")
        interpreter.chmod(0o700)
        login = "login() {" + SOURCE.split("\nlogin() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        definitions = login + f"""
AGENT_SANDBOX_HOME_PATH={shlex.quote(str(self.agent))}
REPO_ROOT={shlex.quote(str(self.fixture))}
SKILL_DIR={shlex.quote(str(ROOT))}
read_key() {{
  case "$1" in
    CODEX_CLI_PATH) printf '%s' '/fixture/codex.js' ;;
    CODEX_CLI_INTERPRETER_PATH) printf '%s' {shlex.quote(str(interpreter))} ;;
    AGENT_SANDBOX_ENFORCED) printf '%s' false ;;
  esac
}}
python3() {{ printf '%s\\037%s\\n' '/fixture/codex.js' {shlex.quote(str(interpreter))}; }}
prepare_agent_env() {{ AGENT_ENV_ARGS=(-i PATH=/usr/bin:/bin); }}
die() {{ printf '%s\\n' "$*" >&2; exit 1; }}
"""
        result = self.shell("login codex", definitions=definitions)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/fixture/codex.js\nlogin\n", result.stdout)

    def test_login_does_not_require_lifecycle_tracker_or_board(self) -> None:
        predispatch = SOURCE.split('# The team fence', 1)[0].rsplit('case "${1:-}" in', 1)[1]
        login_validation = predispatch.split("  login)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("validate_agent_sandbox_home", login_validation)
        self.assertIn("validate_sandbox_runner_config", login_validation)
        self.assertIn("configure_runtime_path", login_validation)
        self.assertNotIn("validate_config\n", login_validation)
        self.assertNotIn("lifecycle", login_validation)


class DoctorResultTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-doctor-result-")
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        self.workspace = self.repository / ".teamwork/doctor-check"
        self.destination = self.workspace / "preflight/doctor-result.json"

    def write(self, status: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([
            sys.executable, str(ROOT / "bin/doctor-result.py"),
            "--repo", str(self.repository), "--workspace", str(self.workspace),
            "--preset", "full-stack", "--team", "doctor-check", "--feature", "doctor-check",
            "--started-at", "2026-11-07T08:00:00Z", "--status", status,
        ], text=True, capture_output=True, check=False)

    def test_success_and_failure_are_timestamped_and_non_authoritative(self) -> None:
        for status in ("passed", "running", "failed"):
            result = self.write(status)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(self.destination.read_text())
            self.assertIs(value["authoritative"], False)
            self.assertEqual(value["status"], status)
            self.assertTrue(value["updatedAt"].endswith("Z"))
            self.assertEqual(value["completedAt"] is None, status == "running")
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.destination.parent.glob(".doctor-result-*")), [])

    def test_result_symlink_and_parent_symlink_never_redirect_writes(self) -> None:
        self.destination.parent.mkdir(parents=True)
        target = self.repository / "unrelated"
        target.write_text("preserve")
        self.destination.symlink_to(target)
        self.assertNotEqual(self.write("failed").returncode, 0)
        self.assertEqual(target.read_text(), "preserve")
        self.destination.unlink()
        self.destination.parent.rmdir()
        self.destination.parent.symlink_to(self.repository)
        self.assertNotEqual(self.write("failed").returncode, 0)
        self.assertFalse((self.repository / "doctor-result.json").exists())

    def test_no_argument_doctor_records_preflight_failure_and_clears_prior_success(self) -> None:
        # No lifecycle or external-home provisioning: this real launch fails
        # before any CLI request, but must replace an older successful report.
        skill = self.repository / ".agents/skills/startup-factory"
        skill.mkdir(parents=True)
        for name in ("bin", "src", "config", "teams", "roles", "reference"):
            shutil.copytree(ROOT / name, skill / name)
        subprocess.run(["git", "init", "-q", str(self.repository)], check=True)
        config = skill / "config/team.config.md"
        config.write_text('AGENT_ENV_ALLOWLIST="PATH LANG"\nAGENT_SANDBOX_HOME=null\nAGENT_SANDBOX_ENFORCED=false\nBROKER_LIFECYCLE_ROOT=null\nTRACKER_WRITERS=broker\n')
        self.assertEqual(self.write("passed").returncode, 0)
        result = subprocess.run(
            ["bash", str(skill / "bin/launch-team.sh"), "doctor"], cwd=self.repository,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.repository)},
            text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("doctor: BROKER_LIFECYCLE_ROOT", result.stderr)
        value = json.loads(self.destination.read_text())
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["preset"], "full-stack")
        self.assertEqual(value["team"], "doctor-check")

    def test_setup_login_and_doctor_complete_in_isolated_project_without_operator_home_changes(self) -> None:
        # State cannot live in shared /tmp. A disposable workspace directory
        # contains the independent Git project, installed skill, fake CLI,
        # synthetic operator HOME, and private state, and is removed afterward.
        # GitHub's checkout path leaves only a small Unix socket path budget.
        with tempfile.TemporaryDirectory(prefix=".", dir=ROOT) as directory:
            base = Path(directory).resolve()
            project, skill, binaries, operator = (base / name for name in ("project", "skill", "cli-bin", "operator-home"))
            for path in (project, skill, binaries, operator):
                path.mkdir(mode=0o700)
            for name in ("bin", "src", "config", "teams", "roles", "reference"):
                shutil.copytree(ROOT / name, skill / name)
            shutil.copy2(ROOT / "tests/fixtures/statuses.default-profile.json", skill / "config/statuses.config.json")
            (skill / "config/team.config.md").write_text(
                'AGENT_ENV_ALLOWLIST="PATH LANG LC_ALL TERM"\nAGENT_SANDBOX_HOME=null\n'
                'AGENT_SANDBOX_ENFORCED=false\nBROKER_LIFECYCLE_ROOT=null\nTRACKER_WRITERS=broker\n'
                'TEAMWORK_ROOT=.teamwork\n'
                "TEAM_DEFAULT_CMD=\"codex --prompt \\\"$(cat '{prompt_file}')\\\"\"\n"
            )
            (skill / "config/project-management.config.md").write_text("PRODUCT_MANAGEMENT_TOOL=Markdown\nMARKDOWN_ROOT=.workspace/task-manager\n")
            codex = binaries / "codex"
            codex.write_text('''#!/bin/sh
set -eu
case "$1" in
  login)
    [ "$USER" != ambient-user ]
    [ -z "${OPENAI_API_KEY:-}" ]
    printf signed-in > "$HOME/.fixture-auth"
    printf 'fixture login complete\\n'
    ;;
  --prompt)
    if [ ! -f "$HOME/.fixture-auth" ]; then
      printf 'Not logged in. Please run /login\\n' >&2
      exit 1
    fi
    printf '%s\\n' "$2" | /usr/bin/tail -n 1
    ;;
  *) exit 91 ;;
esac
''')
            codex.chmod(0o700)
            subprocess.run(["git", "init", "-q", str(project)], check=True)
            environment = {
                "PATH": str(binaries) + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(operator), "USER": "ambient-user", "OPENAI_API_KEY": "do-not-inherit",
            }

            def run(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(skill / "bin" / script), *arguments], cwd=project,
                    env=environment, text=True, capture_output=True, check=False,
                )

            setup = run("setup-machine.sh", "--skip-doctor", "--state-root", str(base / "s"))
            self.assertEqual(setup.returncode, 0, setup.stderr)
            agent_home = value_for(parse_config_bytes((skill / "config/team.config.md").read_bytes()), "AGENT_SANDBOX_HOME")
            self.assertTrue((project / ".workspace/task-manager").is_dir())
            failed = run("launch-team.sh", "doctor")
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("login codex", failed.stderr)
            self.assertIn("AGENT_SANDBOX_HOME=" + agent_home, failed.stderr)
            login = run("launch-team.sh", "login", "codex")
            self.assertEqual(login.returncode, 0, login.stderr)
            doctor = run("launch-team.sh", "doctor")
            self.assertEqual(doctor.returncode, 0, doctor.stderr)
            result = json.loads((project / ".teamwork/doctor-check/preflight/doctor-result.json").read_text())
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["verifiedCommands"], 1)
            self.assertEqual(list(operator.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
