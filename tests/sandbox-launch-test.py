#!/usr/bin/env python3
"""Launcher command selection and finite guest instructions."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "bin"), str(ROOT / "src")]
spec = importlib.util.spec_from_file_location("sf_launch", ROOT / "bin/sandbox-launch.py")
launch = importlib.util.module_from_spec(spec); spec.loader.exec_module(launch)
from startup_factory_cli.config_values import parse_config_bytes


class SandboxLaunchTest(unittest.TestCase):
    def test_explicit_linux_command_required_no_native_fallback(self):
        config = parse_config_bytes(b'TEAM_DEFAULT_CMD="touch /host-marker"\n')
        with self.assertRaisesRegex(ValueError, "explicit Linux"): launch.guest_template(config, "backend")

    def test_task_profile_and_role_override_order(self):
        config = parse_config_bytes(b'SANDBOX_DEFAULT_CMD="default {prompt_file}"\nSANDBOX_BACKEND_CMD="role {prompt_file}"\nSANDBOX_TASK_FAST_CMD="fast {prompt_file}"\n')
        self.assertEqual(launch.guest_template(config, "backend", profile="fast"), "fast {prompt_file}")
        self.assertEqual(launch.guest_template(config, "backend", profile="standard"), "role {prompt_file}")
        self.assertEqual(launch.guest_template(config, "qa"), "default {prompt_file}")

    def test_finite_prompt_uses_private_repository_and_scoped_guest_broker(self):
        prompt = launch.guest_prompt("backend", "", "team", "feature", "T-1", 1, "task").decode()
        self.assertIn("/workspace/project", prompt)
        self.assertIn("sandbox_guest_context.py", prompt)
        self.assertIn("submit-artifact.sh team feature T-1 1 backend", prompt)
        self.assertIn("one isolated task assignment", prompt)
        self.assertLess(len(prompt.encode()), 65536)

    def test_doctor_preserves_exact_challenge_and_rejects_unknown_role(self):
        raw = b"Reply exactly: RANDOM_CHALLENGE\n"
        self.assertEqual(launch.guest_prompt("backend", "", "team", "feature", "-", 0, "doctor", doctor_prompt=raw), raw)
        with self.assertRaises(ValueError): launch.guest_prompt("../../outside", "", "team", "feature", "T-1", 1, "task")

    def test_prepare_entrypoint_encodes_guest_setup_and_never_selects_native_template(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("SF_REGISTRY_TEST_ROOT")) as tmp:
            repo = Path(tmp); repo.chmod(0o700)
            workspace = repo / ".teamwork/team"; workspace.mkdir(parents=True, mode=0o700)
            (workspace / "executions").mkdir(mode=0o700)
            record = workspace / "executions" / (launch.task_key("T-1") + ".json")
            record.write_text(json.dumps({"modelProfile": "fast"})); record.chmod(0o600)
            deployment = SimpleNamespace(profile_path="/protected/profile", bundle_root=str(ROOT),
                registry_root="/protected/registry", receipt_path="/protected/receipt",
                lifecycle_root="/protected/lifecycle", programs={"runner": {"path": "/protected/runner"}, "python": {"path": str(Path(sys.executable).resolve())}},
                projects=[{"projectId": launch.project_id(repo), "repository": str(repo)}])
            config = parse_config_bytes(b'TEAM_DEFAULT_CMD="touch /HOST-MUST-NEVER-RUN"\nSANDBOX_TASK_FAST_CMD="model --prompt {prompt_file}"\nWORKTREE_SETUP="printf setup"\nBROKER_LIFECYCLE_ROOT=/protected/lifecycle\n')
            git = mock.Mock(spec=launch.HostGit); git.read_ref.return_value = "a" * 40
            with mock.patch.object(launch, "load_deployment", return_value=deployment), \
                 mock.patch.object(launch, "load_profile", return_value=SimpleNamespace(namespace="sf-test")), \
                 mock.patch.object(launch, "verify_deployment"), \
                 mock.patch.object(launch, "verify_deployment_enrollment"), \
                 mock.patch.object(launch, "SandboxRegistry"), \
                 mock.patch.object(launch, "HostGit", return_value=git), \
                 mock.patch.object(launch, "read_config_file", return_value=config), \
                 mock.patch.object(launch, "prepare_request", return_value=Path("/protected/job")) as prepare, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(launch.main(["prepare", "--deployment", "/protected/deployment", "--repo", str(repo),
                    "--workspace", str(workspace), "--team", "team", "--feature", "feature", "--role", "backend",
                    "--task", "T-1", "--attempt", "1", "--kind", "task", "--capability", "cap-" + "1" * 32,
                    "--transport", "/protected/native.sock"]), 0)
            kwargs = prepare.call_args.kwargs
            self.assertEqual(kwargs["scope"].role, "backend")
            self.assertEqual(kwargs["base_commit"], "a" * 40)
            self.assertEqual(kwargs["target_ref"], "refs/heads/agent-task/team/" + launch.task_key("T-1"))
            # The real closed backend contract rejects any control character.
            launch.GuestCommand.from_dict(kwargs["guest_command"].as_dict())
            self.assertNotIn("HOST-MUST-NEVER-RUN", str(kwargs["guest_command"].argv))


if __name__ == "__main__": unittest.main()
