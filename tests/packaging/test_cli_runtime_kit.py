from __future__ import annotations

import contextlib
import io
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import cli, runtime_kit  # noqa: E402
from tests.packaging.test_cli_installer import base_payload, write_bundle  # noqa: E402


TEAM_CONFIG = b"""TRACKER_WRITERS=broker # preserved comment
AGENT_SANDBOX_RUNNER=null
AGENT_SANDBOX_ENFORCED=false
BROKER_LIFECYCLE_ROOT=null
VALIDATE_TEST=null
"""
IMAGE = "registry.example.invalid/startup-factory@sha256:" + "a" * 64


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


class RuntimeKitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir(mode=0o700)
        (self.project / ".git").mkdir(mode=0o700)
        self.runtime_root = self.root / "runtime"
        self.engine = self.root / "podman"
        self.engine.write_text(
            """#!/bin/sh
if [ "$1" = info ]; then
  printf '%s\\n' '{"version":{"Version":"5.4.2"},"host":{"security":{"rootless":true},"idMappings":{"uidmap":[{"container_id":0,"host_id":1000,"size":1}],"gidmap":[{"container_id":0,"host_id":1000,"size":1}]}}}'
elif [ "$1" = image ]; then
  printf '%s\\n' '[{"RepoDigests":["__IMAGE__"],"Id":"sha256:"}]'
else
  exit 64
fi
""".replace("__IMAGE__", IMAGE),
            encoding="utf-8",
        )
        self.engine.chmod(0o700)
        payload = base_payload()
        payload["config/team.config.md"] = (TEAM_CONFIG, 0o640)
        for relative in (
            "runtime/runner-linux-container.sh",
            "runtime/container-policy.json",
            "runtime/network-policy-none.json",
        ):
            source = ROOT / relative
            payload[relative] = (source.read_bytes(), stat.S_IMODE(source.stat().st_mode))
        bundle = write_bundle(self.root / "bundle.tar.gz", payload=payload)
        self.target = self.root / "installed" / "startup-factory"
        code, output, error = invoke(
            "install", "--project", str(self.project), "--install-dir", str(self.target),
            "--bundle", str(bundle), "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def runtime(self, *extra: str) -> tuple[int, str, str]:
        return invoke(
            "runtime-kit", "--project", str(self.project), "--install-dir", str(self.target),
            "--runtime-root", str(self.runtime_root), "--engine", str(self.engine),
            "--image", IMAGE, "--host-platform", "linux", "--json", *extra,
        )

    def test_preview_is_non_mutating_and_proof_remains_unknown(self) -> None:
        before = (self.target / "config/team.config.md").read_bytes()
        code, output, error = self.runtime()
        self.assertEqual((code, error), (0, ""), output + error)
        result = json.loads(output)
        self.assertFalse(result["applied"])
        self.assertEqual(result["readiness"], "configured_unproved")
        self.assertFalse(result["ready"])
        self.assertEqual(result["checks"][1]["status"], "unknown")
        self.assertRegex(result["planDigest"], r"^sha256:[0-9a-f]{64}$")
        self.assertFalse(self.runtime_root.exists())
        self.assertEqual((self.target / "config/team.config.md").read_bytes(), before)

    def test_apply_requires_preview_digest_and_updates_config_last(self) -> None:
        code, output, error = self.runtime()
        self.assertEqual((code, error), (0, ""), output + error)
        digest = json.loads(output)["planDigest"]
        with mock.patch.object(runtime_kit.sys, "platform", "linux"):
            code, output, error = self.runtime("--apply", "--plan-digest", digest)
        self.assertEqual((code, error), (0, ""), output + error)
        result = json.loads(output)
        self.assertTrue(result["applied"])
        self.assertFalse(result["ready"])
        config = (self.target / "config/team.config.md").read_text()
        self.assertIn("TRACKER_WRITERS=broker # preserved comment", config)
        self.assertIn("TASK_WORKTREE_MODE=standalone-clone", config)
        self.assertIn("AGENT_SANDBOX_ENFORCED=true", config)
        manifest = next(self.runtime_root.glob("assets/*/runtime-manifest.json"))
        self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o600)
        runner = manifest.parent / "runner"
        self.assertEqual(stat.S_IMODE(runner.stat().st_mode), 0o700)
        self.assertNotIn("@@", runner.read_text())

        code, output, error = invoke(
            "doctor", "--project", str(self.project), "--install-dir", str(self.target),
            "--mode", "team", "--json",
        )
        self.assertEqual((code, error), (1, ""), output + error)
        doctor = {check["id"]: check for check in json.loads(output)["checks"]}
        self.assertEqual(doctor["secure-runtime.configured"]["status"], "pass")
        self.assertEqual(doctor["secure-runtime.proved"]["status"], "unknown")

        code, output, error = self.runtime()
        self.assertEqual((code, error), (0, ""), output + error)
        retry = json.loads(output)
        self.assertEqual(retry["changes"], [])
        with mock.patch.object(runtime_kit.sys, "platform", "linux"):
            code, output, error = self.runtime("--apply", "--plan-digest", retry["planDigest"])
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertEqual(json.loads(output)["changes"], [])

    def test_wrong_digest_macos_rootful_and_unpinned_fail_without_mutation(self) -> None:
        code, _, error = self.runtime("--apply", "--plan-digest", "sha256:" + "0" * 64)
        self.assertEqual(code, 1)
        self.assertIn("plan-digest", error)
        self.assertFalse(self.runtime_root.exists())

        code, _, error = invoke(
            "runtime-kit", "--project", str(self.project), "--install-dir", str(self.target),
            "--runtime-root", str(self.runtime_root), "--engine", str(self.engine),
            "--image", IMAGE, "--host-platform", "darwin", "--json",
        )
        self.assertEqual(code, 1)
        self.assertIn("Linux guest", error)
        self.assertFalse(self.runtime_root.exists())

        code, _, error = invoke(
            "runtime-kit", "--project", str(self.project), "--install-dir", str(self.target),
            "--runtime-root", str(self.runtime_root), "--engine", str(self.engine),
            "--image", "registry.example.invalid/image:latest", "--host-platform", "linux", "--json",
        )
        self.assertEqual(code, 1)
        self.assertIn("pinned", error)

        text = self.engine.read_text().replace('"rootless":true', '"rootless":false')
        self.engine.write_text(text)
        self.engine.chmod(0o700)
        code, _, error = self.runtime()
        self.assertEqual(code, 1)
        self.assertIn("rootless Podman", error)

    def test_symlink_and_stale_asset_are_refused(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        self.runtime_root.symlink_to(outside, target_is_directory=True)
        code, _, error = self.runtime()
        self.assertEqual(code, 1)
        self.assertIn("symlink", error)
        self.assertEqual(list(outside.iterdir()), [])

    def test_failed_post_config_step_compensates_without_erasing_prestate(self) -> None:
        before = (self.target / "config/team.config.md").read_bytes()
        code, output, error = self.runtime()
        self.assertEqual((code, error), (0, ""), output + error)
        digest = json.loads(output)["planDigest"]
        original = runtime_kit._replace_config

        def replace_then_fail(plan: runtime_kit.RuntimePlan) -> None:
            original(plan)
            raise OSError("injected post-config failure")

        with (
            mock.patch.object(runtime_kit.sys, "platform", "linux"),
            mock.patch.object(runtime_kit, "_replace_config", side_effect=replace_then_fail),
        ):
            code, _, error = self.runtime("--apply", "--plan-digest", digest)
        self.assertEqual(code, 1)
        self.assertIn("transaction failed", error)
        self.assertEqual((self.target / "config/team.config.md").read_bytes(), before)
        self.assertFalse(self.runtime_root.exists())

    def test_probe_is_digest_bound_and_never_promotes_readiness(self) -> None:
        code, output, error = self.runtime("--probe")
        self.assertEqual((code, error), (0, ""), output + error)
        result = json.loads(output)
        self.assertFalse(result["ready"])
        self.assertEqual(result["probe"]["readinessEffect"], "none")
        self.assertEqual(result["probe"]["result"], "definitions-verified-not-executed")
        self.assertIn("shared-git-common-unmounted", result["probe"]["controls"]["negative"])


if __name__ == "__main__":
    unittest.main()
