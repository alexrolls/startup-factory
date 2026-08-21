from __future__ import annotations

import contextlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import cli, runtime_kit  # noqa: E402
from tests.packaging.test_cli_installer import base_payload, write_bundle  # noqa: E402


IMAGE = "registry.example.invalid/startup-factory@sha256:" + "a" * 64


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


class GovernedRuntimeLauncherTest(unittest.TestCase):
    def test_gate_role_receives_only_isolated_clone_tools_and_scoped_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            project = root / "project"
            project.mkdir(mode=0o700)
            subprocess.run(["git", "-C", str(project), "init", "-q", "-b", "main"], check=True)
            subprocess.run(["git", "-C", str(project), "config", "user.name", "Fixture"], check=True)
            subprocess.run(["git", "-C", str(project), "config", "user.email", "fixture@example.invalid"], check=True)
            probe = project / "agent-probe.sh"
            probe.write_text(
                "#!/bin/sh\nset -eu\nmkdir -p .startup-factory-output\n"
                "printf '%s\\n' \"$PWD\" \"$1\" \"${STARTUP_FACTORY_AGENT_WORKTREE:-missing}\" "
                "\"${STARTUP_FACTORY_CANONICAL_REPO:-unset}\" \"${STARTUP_FACTORY_CANONICAL_WORKSPACE:-unset}\" "
                "\"${STARTUP_FACTORY_OUTBOX_INGRESS:-missing}\" > .startup-factory-output/agent-result.txt\n"
                "printf '[design-note]\\nisolated gate submission\\n' > .startup-factory-output/body.md\n"
                "\"$STARTUP_FACTORY_SKILL_ROOT/bin/submit-artifact.sh\" feature-runtime F-1 T-1 1 backend design-note "
                ".startup-factory-output/body.md - > .startup-factory-output/entry-path.txt\n"
            )
            probe.chmod(0o755)
            (project / "base.txt").write_text("base\n")
            subprocess.run(["git", "-C", str(project), "add", "."], check=True)
            subprocess.run(["git", "-C", str(project), "commit", "-qm", "base"], check=True)
            subprocess.run(["git", "-C", str(project), "branch", "feature-runtime"], check=True)

            engine_log = root / "engine.log"
            engine = root / "podman"
            engine.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = info ]; then printf '%s\\n' '"
                '{"version":{"Version":"5.4.2"},"host":{"security":{"rootless":true},"idMappings":{"uidmap":[{"container_id":0,"host_id":1000,"size":1}],"gidmap":[{"container_id":0,"host_id":1000,"size":1}]}}}'
                "'; elif [ \"$1\" = image ]; then printf '%s\\n' '"
                f'[{{"RepoDigests":["{IMAGE}"],"Id":"sha256:{"b" * 64}"}}]'
                "'; elif [ \"$1\" = run ]; then printf '%s\\n' \"$@\" > '"
                + str(engine_log)
                + "'; while [ \"$#\" -gt 0 ]; do if [ \"$1\" = '"
                + IMAGE
                + "' ]; then shift; exec \"$@\"; fi; shift; done; exit 65; else exit 64; fi\n"
            )
            engine.chmod(0o700)

            payload = base_payload()
            for root_name in ("bin", "config", "reference", "roles", "teams", "runtime", "adapters", "extensions"):
                for source in (ROOT / root_name).rglob("*"):
                    if source.is_file() and not source.is_symlink():
                        relative = source.relative_to(ROOT).as_posix()
                        payload[relative] = (source.read_bytes(), stat.S_IMODE(source.stat().st_mode))
            team_config = payload["config/team.config.md"][0].decode()
            replacements = {
                "BACKEND_CMD": '"./agent-probe.sh {prompt_file}"',
                "TEAM_DEFAULT_CMD": '"./agent-probe.sh {prompt_file}"',
                "AGENT_ENV_ALLOWLIST": '"PATH TMPDIR LANG LC_ALL TERM"',
                "TRACKER_WRITERS": "broker",
            }
            for key, value in replacements.items():
                team_config, count = re.subn(rf"(?m)^{key}=.*$", f"{key}={value}", team_config)
                self.assertEqual(count, 1, key)
            payload["config/team.config.md"] = (team_config.encode(), 0o640)
            bundle = write_bundle(root / "bundle.tar.gz", payload=payload)
            target = root / "installed" / "startup-factory"
            code, output, error = invoke(
                "install", "--project", str(project), "--install-dir", str(target),
                "--bundle", str(bundle), "--json",
            )
            self.assertEqual((code, error), (0, ""), output + error)
            runtime_root = root / "protected-runtime"
            code, output, error = invoke(
                "runtime-kit", "--project", str(project), "--install-dir", str(target),
                "--runtime-root", str(runtime_root), "--engine", str(engine), "--image", IMAGE,
                "--host-platform", "linux", "--json",
            )
            self.assertEqual((code, error), (0, ""), output + error)
            plan_digest = json.loads(output)["planDigest"]
            with mock.patch.object(runtime_kit.sys, "platform", "linux"):
                code, output, error = invoke(
                    "runtime-kit", "--project", str(project), "--install-dir", str(target),
                    "--runtime-root", str(runtime_root), "--engine", str(engine), "--image", IMAGE,
                    "--host-platform", "linux", "--apply", "--plan-digest", plan_digest, "--json",
                )
            self.assertEqual((code, error), (0, ""), output + error)

            launch = target / "bin/launch-team.sh"
            result = subprocess.run(
                [str(launch), "start", "feature-runtime", "F-1", "backend"],
                cwd=project,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": str(root), "TEAM_RUNNER": "background"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            clone = runtime_root / "attempt-clones/feature-runtime/backend#1-gate-backend"
            agent_result = clone / ".startup-factory-output/agent-result.txt"
            for _ in range(100):
                if agent_result.exists():
                    break
                time.sleep(0.02)
            role_log = project / ".teamwork/feature-runtime/pids/backend.log"
            self.assertTrue(
                agent_result.is_file(),
                result.stdout + result.stderr + (role_log.read_text() if role_log.exists() else "<no role log>"),
            )
            lines = agent_result.read_text().splitlines()
            self.assertEqual(lines[0], str(clone))
            prompt_path = Path(lines[1])
            self.assertEqual(prompt_path.parent, clone / ".startup-factory-input")
            self.assertRegex(prompt_path.name, r"^role-prompt-[0-9a-f]{16}\.md$")
            self.assertEqual(lines[2], str(clone))
            self.assertEqual(lines[3:5], ["unset", "unset"])
            self.assertRegex(lines[5], rf"^{re.escape(str(runtime_root / 'outbox-ingress'))}/cap-[0-9a-f]{{32}}$")
            entry_receipt = clone / ".startup-factory-output/entry-path.txt"
            for _ in range(100):
                if entry_receipt.exists() and entry_receipt.stat().st_size:
                    break
                time.sleep(0.02)
            self.assertTrue(entry_receipt.exists() and entry_receipt.stat().st_size, role_log.read_text() if role_log.exists() else "<no role log>")
            entry_path = Path(entry_receipt.read_text().strip())
            self.assertEqual(entry_path.parent, Path(lines[5]))
            entry = json.loads(entry_path.read_text())
            self.assertEqual(entry["producerCapability"]["id"], entry_path.parent.name)
            self.assertEqual(Path(entry["bodyPath"]).parent, entry_path.parent)
            self.assertFalse((project / ".teamwork/feature-runtime/outbox/pending").exists())
            rendered_prompt = prompt_path.read_text()
            self.assertNotIn(str(project), rendered_prompt)
            self.assertNotIn(str(project / ".teamwork"), rendered_prompt)
            invocation = engine_log.read_text()
            self.assertIn(f"type=bind,src={clone},dst={clone},rw", invocation)
            self.assertIn(f"type=bind,src={target},dst={target},ro", invocation)
            self.assertNotIn(str(project), invocation)
            self.assertNotIn(str(project / ".git"), invocation)
            self.assertNotIn(str(project / ".teamwork"), invocation)
            self.assertNotIn(str(runtime_root / "lifecycle"), invocation)
            self.assertEqual(subprocess.check_output(["git", "-C", str(clone), "status", "--porcelain=v1", "-uall"], text=True), "")


if __name__ == "__main__":
    unittest.main()
