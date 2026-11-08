#!/usr/bin/env python3
"""Machine setup validates first, provisions private state, and remains repeatable."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli import machine_setup as setup
from startup_factory_cli.config_values import parse_config_bytes, value_for


class MachineSetupTest(unittest.TestCase):
    def setUp(self) -> None:
        # Never provision the developer's actual HOME; lifecycle state also
        # deliberately cannot use the shared system temporary directory.
        # Keep the fixture name short enough for GitHub's longer checkout path
        # plus the production Unix socket locator's fixed suffix.
        self.temporary = tempfile.TemporaryDirectory(prefix=".", dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.project = self.root / "project"
        self.skill = self.root / "installed-skill"
        self.home = self.root / "operator-home"
        self.bin = self.root / "cli-bin"
        for path in (self.project, self.skill, self.home, self.bin):
            path.mkdir(mode=0o700)
        (self.skill / "bin").mkdir(mode=0o700)
        (self.skill / "config").mkdir(mode=0o700)
        shutil.copy2(ROOT / "bin/authority_config.py", self.skill / "bin/authority_config.py")
        self.team = self.skill / "config/team.config.md"
        self.pm = self.skill / "config/project-management.config.md"
        self.original = (
            "# Team configuration\n\n```\n"
            "AGENT_SANDBOX_HOME=null # private CLI home\n"
            "BROKER_LIFECYCLE_ROOT=null # private broker state\n"
            'TEAM_LEAD_CMD="/usr/bin/true"\n'
            'VALIDATE_TEST="echo do not execute configuration"\n'
            "```\n"
        )
        self.team.write_text(self.original, encoding="utf-8")
        self.pm.write_text("PRODUCT_MANAGEMENT_TOOL=Markdown\nMARKDOWN_ROOT=.workspace/task-manager\n", encoding="utf-8")
        self.state = self.root / "s"
        self.path = f"{self.bin}:/usr/bin:/bin"

    def provision(self, **updates):
        arguments = dict(skill=self.skill, project=self.project, operator_home=str(self.home), caller_path=self.path, state_root=str(self.state))
        arguments.update(updates)
        return setup.provision(**arguments)

    def values(self):
        return parse_config_bytes(self.team.read_bytes())

    def cli(self, name: str, directory: Path | None = None) -> Path:
        executable = (directory or self.bin) / name
        executable.write_text("#!/bin/sh\nexit 99 # must never run during setup\n", encoding="utf-8")
        executable.chmod(0o755)
        return executable

    def assert_unprovisioned(self):
        self.assertFalse(self.state.exists())
        self.assertFalse((self.project / ".workspace").exists())

    def test_setup_rerun_is_noop_and_changes_only_two_machine_path_keys(self):
        result = self.provision()
        self.assertEqual(result.agent_home, self.state / "h")
        self.assertEqual(result.lifecycle_root, self.state / "l")
        self.assertEqual(result.markdown_root, self.project / ".workspace/task-manager")
        for directory in (self.state, result.agent_home, result.lifecycle_root, result.markdown_root):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        lines = self.team.read_text().splitlines()
        changed = [before.split("=", 1)[0] for before, after in zip(self.original.splitlines(), lines) if before != after]
        self.assertEqual(changed, ["AGENT_SANDBOX_HOME", "BROKER_LIFECYCLE_ROOT"])
        identity = self.team.stat().st_ino
        raw = self.team.read_bytes()
        rerun = self.provision()
        self.assertFalse(rerun.config_changed)
        self.assertEqual(self.team.stat().st_ino, identity)
        self.assertEqual(self.team.read_bytes(), raw)

    def test_default_paths_are_project_specific_under_test_home(self):
        # Fixture HOME lives under the repository and is longer than a normal
        # user home. Exercise default path selection independently of its
        # dedicated socket-length boundary regression below.
        with mock.patch.object(setup, "_validate_lifecycle_socket"):
            result = self.provision(state_root=None)
        base = result.agent_home.parent
        self.assertEqual(base.parent, self.home / ".local/share/sf")
        self.assertRegex(base.name, r"^[a-f0-9]{12}$")
        self.assertEqual(result.lifecycle_root.parent, base)

    def test_preserves_explicit_configured_paths(self):
        agent = self.root / "a"
        lifecycle = self.root / "l"
        self.team.write_text(self.original.replace("AGENT_SANDBOX_HOME=null", f'AGENT_SANDBOX_HOME="{agent}"').replace("BROKER_LIFECYCLE_ROOT=null", f'BROKER_LIFECYCLE_ROOT="{lifecycle}"'))
        before = self.team.read_bytes()
        result = self.provision()
        self.assertEqual(result.agent_home, agent)
        self.assertEqual(result.lifecycle_root, lifecycle)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.team.read_bytes(), before)

    def test_pins_supported_cli_once_and_preserves_normalized_command_tail(self):
        claude = self.cli("claude")
        codex = self.cli("codex")
        marker = self.root / "must-not-exist"
        command = f'''claude -p "$(touch '{marker}')" --permission-mode acceptEdits'''
        self.team.write_text(self.original.replace('TEAM_LEAD_CMD="/usr/bin/true"', f"TEAM_LEAD_CMD={setup._encode(command)}\nBACKEND_CMD=codex exec --approve-for-me"))
        result = self.provision()
        values = self.values()
        self.assertEqual(value_for(values, "TEAM_LEAD_CMD"), str(claude) + command[len("claude"):])
        self.assertEqual(value_for(values, "BACKEND_CMD"), str(codex) + " exec --approve-for-me")
        self.assertEqual(value_for(values, "CLAUDE_CLI_PATH"), str(claude))
        self.assertEqual(value_for(values, "CODEX_CLI_PATH"), str(codex))
        self.assertEqual(result.rewritten_commands, 2)
        self.assertFalse(marker.exists())
        self.assertFalse(self.provision().config_changed)

    def test_cli_symlink_keeps_stable_entrypoint_across_upgrade(self):
        target_directory = self.root / "CLI files"
        target_directory.mkdir(mode=0o700)
        target = self.cli("claude-real", target_directory)
        (self.bin / "claude").symlink_to(target)
        self.team.write_text(self.original.replace('TEAM_LEAD_CMD="/usr/bin/true"', "TEAM_LEAD_CMD=claude --version"))
        self.provision()
        self.assertEqual(value_for(self.values(), "CLAUDE_CLI_PATH"), str(self.bin / "claude"))
        self.assertEqual(value_for(self.values(), "TEAM_LEAD_CMD"), f"{self.bin / 'claude'} --version")
        replacement = self.cli("claude-next-version", target_directory)
        (self.bin / "claude").unlink()
        (self.bin / "claude").symlink_to(replacement)
        target.unlink()
        self.assertFalse(self.provision().config_changed)

    def test_cli_symlink_cannot_hide_shared_temporary_intermediate(self):
        with tempfile.TemporaryDirectory(prefix="sf-cli-link-", dir="/tmp") as shared:
            intermediate = Path(shared) / "intermediate"
            intermediate.symlink_to("/usr/bin/true")
            entrypoint = self.bin / "claude"
            entrypoint.symlink_to(intermediate)
            with self.assertRaisesRegex(setup.MachineSetupError, "shared temporary"):
                setup.validate_cli_executable(str(entrypoint))

    def test_node_cli_runs_with_sanitized_path_and_pinned_interpreter(self):
        codex = self.cli("codex")
        codex.write_text('#!/usr/bin/env node\nconsole.log("Codex fixture");\n')
        node = self.cli("node")
        node.write_text('#!/bin/sh\nprintf "node:%s:%s\\n" "$1" "$2"\n')
        self.team.write_text(self.original.replace('TEAM_LEAD_CMD="/usr/bin/true"', "TEAM_LEAD_CMD=codex --version"))
        result = self.provision()
        command = value_for(self.values(), "TEAM_LEAD_CMD")
        self.assertEqual(command, f"{node} {codex} --version")
        self.assertEqual(value_for(self.values(), "CODEX_CLI_INTERPRETER_PATH"), str(node))
        completed = subprocess.run(["/bin/sh", "-c", command], env={"PATH": result.runtime_path}, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), f"node:{codex}:--version")
        self.assertFalse(self.provision(caller_path="/usr/bin:/bin").config_changed)

    def test_node_claude_preserves_launcher_runtime_classification(self):
        claude = self.cli("claude")
        claude.write_text('#!/usr/bin/env node\nconsole.log("Claude fixture");\n')
        node = self.cli("node")
        self.team.write_text(self.original.replace('TEAM_LEAD_CMD="/usr/bin/true"', "TEAM_LEAD_CMD=claude -p prompt"))
        self.provision()
        command = value_for(self.values(), "TEAM_LEAD_CMD")
        self.assertTrue(command.startswith(f"STARTUP_FACTORY_LLM_RUNTIME=claude {node} {claude}"))
        launcher = (ROOT / "bin/launch-team.sh").read_text()
        function = launcher.split("classify_command_runtime() {", 1)[1].split("\n}\n", 1)[0]
        script = "classify_command_runtime() {" + function + '\n}\nclassify_command_runtime "$1"\n'
        completed = subprocess.run(["/bin/bash", "-c", script, "classify", command], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "claude")
        self.assertFalse(self.provision(caller_path="/usr/bin:/bin").config_changed)

    def test_node_cli_missing_interpreter_fails_before_mutation(self):
        codex = self.cli("codex")
        codex.write_text('#!/usr/bin/env node\nconsole.log("Codex fixture");\n')
        self.team.write_text(self.original.replace('TEAM_LEAD_CMD="/usr/bin/true"', "TEAM_LEAD_CMD=codex --version"))
        find = setup._find_cli
        def without_node(name, path, boundaries):
            if name == "node":
                raise setup.MachineSetupError("node is unavailable")
            return find(name, path, boundaries)
        before = self.team.read_bytes()
        with mock.patch.object(setup, "_find_cli", side_effect=without_node):
            with self.assertRaisesRegex(setup.MachineSetupError, "requires Node"):
                self.provision()
        self.assertEqual(self.team.read_bytes(), before)
        self.assert_unprovisioned()

    def test_absent_markdown_root_uses_adapter_default_without_config_edit(self):
        self.pm.write_text("PRODUCT_MANAGEMENT_TOOL=Markdown\n")
        before = self.pm.read_bytes()
        self.assertEqual(self.provision().markdown_root, self.project / ".workspace/task-manager")
        self.assertEqual(self.pm.read_bytes(), before)

    def test_other_tracker_does_not_create_markdown_directory(self):
        self.pm.write_text("PRODUCT_MANAGEMENT_TOOL=GitHubIssues\nMARKDOWN_ROOT=.workspace/task-manager\n")
        self.assertIsNone(self.provision().markdown_root)
        self.assertFalse((self.project / ".workspace").exists())

    def test_publication_socket_path_boundary_and_preflight_failure(self):
        # The locator appends /p/ and a 32-byte token to the lifecycle path.
        setup._validate_lifecycle_socket(Path("/" + "a" * 63))
        with self.assertRaisesRegex(setup.MachineSetupError, "too long"):
            setup._validate_lifecycle_socket(Path("/" + "a" * 64))
        before = self.team.read_bytes()
        with self.assertRaisesRegex(setup.MachineSetupError, "shorter --state-root"):
            self.provision(state_root=str(self.root / ("long-state-" * 8)))
        self.assertEqual(self.team.read_bytes(), before)
        self.assert_unprovisioned()

    def test_unsafe_state_roots_make_no_writes(self):
        symlink = self.root / "state-link"
        symlink.symlink_to(self.home, target_is_directory=True)
        file = self.root / "not-a-directory"
        file.write_text("existing")
        unsafe = self.root / "writable-state"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        for candidate in (self.project / "state", self.skill / "state", symlink / "state", file / "state", unsafe / "state", Path("/tmp/sf-setup-forbidden")):
            with self.subTest(root=candidate):
                before = self.team.read_bytes()
                with self.assertRaises(setup.MachineSetupError):
                    self.provision(state_root=str(candidate))
                self.assertEqual(self.team.read_bytes(), before)
                self.assert_unprovisioned()

    def test_existing_private_paths_require_0700_and_disjointness(self):
        bad = self.root / "bad-agent-home"
        bad.mkdir(mode=0o755)
        self.team.write_text(self.original.replace("AGENT_SANDBOX_HOME=null", f'AGENT_SANDBOX_HOME="{bad}"'))
        before = self.team.read_bytes()
        with self.assertRaisesRegex(setup.MachineSetupError, "0700"):
            self.provision()
        self.assertEqual(self.team.read_bytes(), before)
        self.assert_unprovisioned()
        self.team.write_text(self.original.replace("AGENT_SANDBOX_HOME=null", f'AGENT_SANDBOX_HOME="{self.state}"'))
        with self.assertRaisesRegex(setup.MachineSetupError, "disjoint"):
            self.provision()
        self.assert_unprovisioned()

    def test_missing_cli_and_repo_local_cli_fail_before_provisioning(self):
        self.team.write_text(self.original.replace('TEAM_LEAD_CMD="/usr/bin/true"', "TEAM_LEAD_CMD=claude -p hello"))
        before = self.team.read_bytes()
        with self.assertRaisesRegex(setup.MachineSetupError, "unavailable"):
            self.provision()
        self.assert_unprovisioned()
        executable = self.cli("claude", self.project)
        with self.assertRaisesRegex(setup.MachineSetupError, "disjoint"):
            self.provision(caller_path=f"{executable.parent}:/usr/bin")
        self.assertEqual(self.team.read_bytes(), before)
        self.assert_unprovisioned()

    def test_auto_cli_cannot_hide_repo_intermediate_symlink(self):
        intermediate = self.project / "intermediate"
        intermediate.symlink_to("/usr/bin/true")
        entrypoint = self.bin / "claude"
        entrypoint.symlink_to(intermediate)
        self.team.write_text(self.original.replace('TEAM_LEAD_CMD="/usr/bin/true"', "TEAM_LEAD_CMD=claude -p hello"))
        with self.assertRaisesRegex(setup.MachineSetupError, "disjoint"):
            self.provision()
        self.assert_unprovisioned()

    def test_markdown_symlink_and_duplicate_config_fail_without_state_writes(self):
        (self.project / ".workspace").symlink_to(self.home, target_is_directory=True)
        with self.assertRaises(setup.MachineSetupError):
            self.provision()
        self.assertFalse(self.state.exists())
        (self.project / ".workspace").unlink()
        self.team.write_text(self.original + "AGENT_SANDBOX_HOME=null\n")
        with self.assertRaisesRegex(setup.ConfigValueError, "duplicate"):
            self.provision()
        self.assert_unprovisioned()

    def test_atomic_update_refuses_concurrent_config_edit(self):
        snapshot = setup._read(self.team)
        replacement = setup._render(snapshot, {"AGENT_SANDBOX_HOME": str(self.state / "h")})
        concurrent = self.original + "# concurrent operator edit\n"
        self.team.write_text(concurrent)
        with self.assertRaisesRegex(setup.InstallerError, "changed"):
            setup._write(snapshot, replacement)
        self.assertEqual(self.team.read_text(), concurrent)

    def test_wrapper_help_and_default_doctor_invocation(self):
        for name in ("setup-machine.sh", "authority-bootstrap.sh"):
            shutil.copy2(ROOT / "bin" / name, self.skill / "bin" / name)
        shutil.copytree(ROOT / "src", self.skill / "src")
        log = self.root / "doctor-argv"
        launcher = self.skill / "bin/launch-team.sh"
        launcher.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{log}"\nexit 7\n')
        launcher.chmod(0o755)
        subprocess.run(["/usr/bin/git", "init", "-q", str(self.project)], check=True)
        environment = dict(os.environ, HOME=str(self.home), PATH=self.path)
        command = [str(self.skill / "bin/setup-machine.sh"), "--state-root", str(self.state)]
        completed = subprocess.run(command, cwd=self.project, env=environment, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(log.read_text(), "doctor\n")
        self.assertIn("Running team doctor", completed.stdout)
        log.unlink()
        completed = subprocess.run(command + ["--skip-doctor"], cwd=self.project, env=environment, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(log.exists())
        self.assertIn("Readiness pending", completed.stdout)
        completed = subprocess.run([str(self.skill / "bin/setup-machine.sh"), "--help"], cwd=self.root, env=environment, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--skip-doctor", completed.stdout)


if __name__ == "__main__":
    unittest.main()
