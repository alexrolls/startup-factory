#!/usr/bin/env python3
"""Exact-index validation fixtures; run only inside the offline test sandbox."""
from __future__ import annotations
import copy
import importlib.util
import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "bin"), str(ROOT / "src")]
import sandbox_validation as validation
from sandbox_source import build_source_package, initialize_guest
from sandbox_acceptance import project_id

FIXTURE = runpy.run_path(str(ROOT / "tests/sandbox-artifacts-test.py"), run_name="validation_artifact_fixture")
spec = importlib.util.spec_from_file_location("validation_recovery_fixture", ROOT / "bin/recovery_validation.py")
recovery = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = recovery
spec.loader.exec_module(recovery)


class SandboxValidationTests(FIXTURE["ArtifactTests"]):
    # Reuse only the raw Git fixture helpers, not the other suite's test cases.
    def setUp(self):
        super().setUp()
        self.workspace_root = self.repo / ".teamwork"
        self.workspace_root.mkdir(mode=0o700)
        self.workspace = self.workspace_root / "team-one"
        self.workspace.mkdir(mode=0o700)
        self.deployment = SimpleNamespace(profile_path="/fixture/profile.json", controller_uid=os.geteuid(),
            controller_gid=os.getegid(), projects=({"projectId": project_id(self.repo),
            "repository": str(self.repo), "workspaceRoot": str(self.workspace_root)},))
        self.profile = SimpleNamespace(namespace="sf-validation", digest="sha256:" + "1" * 64,
            policy_digest="sha256:" + "2" * 64, image="registry.example.com/agent@sha256:" + "3" * 64)
        self.config = {"AGENT_EXECUTION_BACKEND": "docker-sandboxes", "AGENT_SANDBOX_ENFORCED": "true",
            "AGENT_SANDBOX_DEPLOYMENT": "/fixture/deployment.json", "WORKTREE_SETUP": None,
            "VALIDATE_SCRIPT": None, **{key: None for key in validation.VALIDATION_KEYS}}
        self.prepared = None

    def prepare(self, deployment, **kwargs):
        self.assertIs(deployment, self.deployment)
        self.prepared = kwargs
        self.assertEqual(kwargs["kind"], "validation")
        self.assertEqual(kwargs["scope"].task_id, "-")
        self.assertEqual(kwargs["scope"].attempt, 0)
        self.assertIsNone(kwargs["capability_id"])
        self.assertIsNone(kwargs["transport"])
        return self.scratch / "prepared.request.json"

    def result(self, code=0):
        p = self.prepared
        return {"exitCode": code, "promotionReceipt": None, "binding": {
            "schemaVersion": 1, "backend": "docker-sandboxes", "namespace": self.profile.namespace,
            "name": "sf-" + "4" * 32, "sandboxId": "02418900-048d-44e9-86dc-9e036e546554",
            "createdAt": "2026-11-17T10:08:29+01:00", "generation": "gen-" + "5" * 32,
            "epoch": 1, "profileDigest": self.profile.digest, "policyDigest": self.profile.policy_digest,
            "image": self.profile.image, "inputDigest": "sha256:" + "6" * 64,
            "baseCommit": p["base_commit"], "state": "work-complete", "acceptedCommit": None,
            "acceptedTree": None, "acceptedExportDigest": None}}

    def run_guest(self, deployment, request, diagnostic=None):
        self.assertEqual(request.name, "prepared.request.json")
        vm = self.scratch / "guest"
        vm.mkdir(mode=0o700)
        project = vm / "project"
        package = build_source_package(self.prepared["base_commit"], self.git.read_object, contains_secret=lambda _text: False)
        initialize_guest(package, project)
        prompt = vm / "prompt.md"
        prompt.write_bytes(self.prepared["prompt"])
        code = validation.GUEST_VALIDATION_CODE.replace("'/opt/startup-factory/prompt.md'", repr(str(prompt))).replace("'/workspace/project'", repr(str(project)))
        completed = subprocess.run([sys.executable, "-I", "-B", "-c", code], cwd=vm,
            env={"PATH": "/usr/bin:/bin", "HOME": str(vm), "LC_ALL": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.last_guest = completed
        self.guest = project
        return self.result(completed.returncode)

    def invoke(self, *, tree=None, client=None, **kwargs):
        with mock.patch.object(validation, "load_deployment", return_value=self.deployment), \
             mock.patch.object(validation, "load_profile", return_value=self.profile), \
             mock.patch.object(validation, "verify_deployment"), \
             mock.patch.object(validation, "prepare_request", side_effect=self.prepare), \
             mock.patch.object(validation, "run_client", side_effect=client or self.run_guest):
            return validation.run_validation(repository=self.repo, workspace=self.workspace,
                team="team-one", feature="FEATURE-1", role="validator",
                tree=tree or self.git.commit_tree(self.base), config=self.config, changed=[], **kwargs)

    def test_exact_staged_merge_tree_is_validated_instead_of_head_or_worktree(self):
        (self.repo / "hello.txt").write_text("staged merge candidate\n")
        self.fixture_git("add", "hello.txt")
        tree = self.fixture_git("write-tree").strip().decode()
        (self.repo / "hello.txt").write_text("unstaged host content\n")
        self.assertEqual(self.invoke(tree=tree, command="test \"$(cat hello.txt)\" = 'staged merge candidate'"), 0,
            self.last_guest.stderr)
        self.assertEqual(self.fixture_git("rev-parse", "HEAD").strip().decode(), self.base)
        self.assertEqual(self.git.commit_tree(self.prepared["base_commit"]), tree)
        self.assertEqual((self.repo / "hello.txt").read_text(), "unstaged host content\n")
        self.assertNotEqual(self.prepared["base_commit"], self.base)

    def test_guest_setup_and_script_run_with_literal_changed_path_arguments(self):
        script = self.repo / "check.sh"
        script.write_text("#!/bin/sh\nset -eu\ntest -f prepared-by-setup\nprintf '%s\\0' \"$@\" > observed-args\nprintf guest-only > guest-output\n")
        script.chmod(0o755)
        self.fixture_git("add", "check.sh")
        tree = self.fixture_git("write-tree").strip().decode()
        self.config.update(WORKTREE_SETUP="printf setup > prepared-by-setup", VALIDATE_SCRIPT="check.sh")
        changed = ["one space.txt", "line\nbreak.txt", "$(touch escaped)"]
        with mock.patch.object(validation, "load_deployment", return_value=self.deployment), \
             mock.patch.object(validation, "load_profile", return_value=self.profile), \
             mock.patch.object(validation, "verify_deployment"), \
             mock.patch.object(validation, "prepare_request", side_effect=self.prepare), \
             mock.patch.object(validation, "run_client", side_effect=self.run_guest):
            code = validation.run_validation(repository=self.repo, workspace=self.workspace,
                team="team-one", feature="FEATURE-1", role="validator", tree=tree,
                config=self.config, changed=changed)
        self.assertEqual(code, 0, self.last_guest.stderr)
        self.assertEqual((self.guest / "observed-args").read_bytes(), b"\0".join(p.encode() for p in changed) + b"\0")
        self.assertFalse((self.repo / "prepared-by-setup").exists())
        self.assertFalse((self.repo / "guest-output").exists())
        self.assertFalse((self.guest / "escaped").exists())

    def test_first_guest_failure_stops_later_checks_and_propagates_actual_status(self):
        self.config.update(VALIDATE_BUILD="exit 23", VALIDATE_TEST="touch should-not-run")
        self.assertEqual(self.invoke(), 23)
        self.assertFalse((self.guest / "should-not-run").exists())

    def test_root_project_and_enforced_policy_are_checked_before_local_object_write(self):
        for mutation in ({"AGENT_SANDBOX_ENFORCED": "false"}, {"AGENT_EXECUTION_BACKEND": "unknown"}):
            original = dict(self.config)
            self.config.update(mutation)
            with mock.patch.object(validation, "HostGit") as git:
                with self.assertRaises(validation.SandboxValidationError):
                    self.invoke()
                git.assert_not_called()
            self.config = original
        self.deployment.projects = ()
        with mock.patch.object(validation, "HostGit") as git:
            with self.assertRaises(validation.SandboxValidationError):
                self.invoke()
            git.assert_not_called()

    def test_tampered_completion_cannot_substitute_another_tree_or_import(self):
        for mutate in (lambda result: result["binding"].update(baseCommit=self.base),
                       lambda result: result.update(promotionReceipt={"commit": self.base})):
            def client(*args, **kwargs):
                result = self.result()
                mutate(result)
                return result
            with self.assertRaises(validation.SandboxValidationError):
                self.invoke(client=client)

    def test_nul_paths_are_literal_and_closed_plan_bounds_fail_before_dispatch(self):
        self.assertEqual(validation.parse_changed(b"one space\0line\nbreak\0"), ["one space", "line\nbreak"])
        for raw in (b"unterminated", b"../escape\0", b"duplicate\0duplicate\0", b"/absolute\0"):
            with self.assertRaises(validation.SandboxValidationError):
                validation.parse_changed(raw)
        for kwargs in ({"script": "../escape"}, {"workdir": "/host"}, {"command": "x" * 65536}):
            with self.assertRaises(validation.SandboxValidationError):
                validation.plan(self.config, [], tree="1" * 40, **kwargs)

    def test_recovery_docker_branch_never_launches_or_checks_a_native_script(self):
        config = dict(self.config, VALIDATE_SCRIPT="missing-script", AGENT_ENV_ALLOWLIST="SECRET_CANARY")
        with mock.patch.object(validation, "run_validation", return_value=17) as guest, \
             mock.patch.object(recovery, "_run_bounded") as native, \
             mock.patch.object(recovery, "validate_runner") as runner, \
             mock.patch.object(recovery, "validation_script") as script:
            code = recovery.run_validation(self.repo, config, [b"line\nbreak"], workspace=self.workspace,
                team="team-one", feature="FEATURE-1", tree="1" * 40)
        self.assertEqual(code, 17)
        self.assertEqual(guest.call_args.kwargs["changed"], ["line\nbreak"])
        native.assert_not_called(); runner.assert_not_called(); script.assert_not_called()
        with self.assertRaises(recovery.RecoveryValidationError):
            recovery.run_validation(self.repo, config, [])

    def test_integrator_shell_dispatches_exact_current_index_and_nul_paths(self):
        for file in ("integrate-task.sh", "finalize-integrations.sh"):
            subprocess.run(["/bin/bash", "-n", str(ROOT / "bin" / file)], check=True, timeout=5)
        source = (ROOT / "bin/integrate-task.sh").read_text()
        function = source.split("run_validation() {", 1)[1].split("\nload_preparation()", 1)[0]
        installed = self.scratch / "installed"
        (installed / "bin").mkdir(parents=True)
        capture = self.scratch / "dispatch.json"
        (installed / "bin/sandbox-validation.py").write_text(
            "import json,pathlib,sys\npathlib.Path(" + repr(str(capture)) + ").write_text(json.dumps({'argv':sys.argv[1:],'changed':sys.stdin.buffer.read().hex()}))\n")
        (self.repo / "changed file.txt").write_text("candidate")
        self.fixture_git("add", "changed file.txt")
        self.fixture_git("commit", "-q", "-m", "task candidate")
        head = self.fixture_git("rev-parse", "HEAD").strip().decode()
        (self.repo / "hello.txt").write_text("merged index\n")
        self.fixture_git("add", "hello.txt")
        tree = self.fixture_git("write-tree").strip().decode()
        variables = {"repo": self.repo, "workspace": self.workspace, "team": "team-one",
            "feature": "FEATURE-1", "SKILL_DIR": installed, "CONFIG": installed / "config.md",
            "review_base_commit": self.base, "task_branch_head": head}
        script = "set -euo pipefail\n" + "\n".join(name + "=" + shlex.quote(str(value)) for name, value in variables.items()) + "\n"
        script += "read_key() { case \"$1\" in AGENT_EXECUTION_BACKEND) printf docker-sandboxes;; *) printf 'touch MUST_NOT_RUN';; esac; }\n"
        script += "git_unprivileged() { /usr/bin/env -i PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false \"$@\"; }\n"
        script += "python3() { /usr/bin/python3 \"$@\"; }\nrun_validation() {" + function
        script += "\nrun_validation \"$repo\" /unused-native-file-list\n"
        completed = subprocess.run(["/bin/bash", "-c", script], cwd=self.scratch,
            env={"PATH": "/usr/bin:/bin"}, capture_output=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        recorded = json.loads(capture.read_text())
        self.assertEqual(recorded["argv"][recorded["argv"].index("--tree") + 1], tree)
        self.assertEqual(bytes.fromhex(recorded["changed"]), b"changed file.txt\0")
        self.assertFalse((self.repo / "MUST_NOT_RUN").exists())

    def test_real_validation_entrypoints_refuse_missing_deployment_without_native_fallback(self):
        config = dict(self.config, AGENT_ENV_ALLOWLIST="PATH", VALIDATE_BUILD="touch SHOULD_NOT_RUN")
        path = self.repo / "validation.config.md"
        path.write_text("\n".join(key + "=" + ("null" if value is None else json.dumps(value)) for key, value in config.items()) + "\n")
        common = ["--repo", str(self.repo), "--workspace", str(self.workspace), "--team", "team-one",
            "--feature", "FEATURE-1", "--tree", self.git.commit_tree(self.base), "--config", str(path), "--changed-files", "-"]
        for entry, expected in (("sandbox-validation.py", 125), ("recovery_validation.py", 2)):
            completed = subprocess.run(["/usr/bin/python3", "-I", "-B", str(ROOT / "bin" / entry), *common],
                input=b"hello.txt\0", cwd=self.repo, env={"PATH": "/usr/bin:/bin"}, capture_output=True, timeout=5)
            self.assertEqual(completed.returncode, expected, completed.stderr)
            self.assertFalse((self.repo / "SHOULD_NOT_RUN").exists())


# Do not inherit the unrelated ArtifactTests methods into this test inventory.
for _name in list(vars(FIXTURE["ArtifactTests"])):
    if _name.startswith("test_") and _name not in vars(SandboxValidationTests):
        setattr(SandboxValidationTests, _name, None)

if __name__ == "__main__":
    unittest.main()
