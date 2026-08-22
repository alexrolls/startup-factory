from __future__ import annotations

import contextlib
import io
import json
import os
import signal
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
        subprocess.run(["git", "-C", str(self.project), "init", "-q", "-b", "main"], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.email", "fixture@example.invalid"], check=True)
        (self.project / "base.txt").write_text("base\n")
        subprocess.run(["git", "-C", str(self.project), "add", "base.txt"], check=True)
        subprocess.run(["git", "-C", str(self.project), "commit", "-qm", "base"], check=True)
        self.project_head = subprocess.check_output(
            ["git", "-C", str(self.project), "rev-parse", "HEAD"], text=True
        ).strip()
        self.engine_log = self.root / "engine-run.log"
        self.runtime_root = self.root / "runtime"
        self.engine = self.root / "podman"
        self.engine.write_text(
            """#!/bin/sh
if [ "$1" = info ]; then
  printf '%s\\n' '{"version":{"Version":"5.4.2"},"host":{"security":{"rootless":true},"idMappings":{"uidmap":[{"container_id":0,"host_id":1000,"size":1}],"gidmap":[{"container_id":0,"host_id":1000,"size":1}]}}}'
elif [ "$1" = image ]; then
  printf '%s\\n' '[{"RepoDigests":["__IMAGE__"],"Id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]'
elif [ "$1" = run ]; then
  printf '%s\\n' "$@" > '__LOG__'
  printf '%s\\n' '{"schemaVersion":1,"worktreeWrite":true,"standaloneGitCommit":"__HEAD__","uid":1000,"gid":1000,"denials":{"hostSentinel":true,"canonicalRepo":true,"brokerState":true,"lifecycleState":true,"siblingWorkspace":true,"loopbackNetwork":true,"metadataNetwork":true}}'
else
  exit 64
fi
""".replace("__IMAGE__", IMAGE).replace("__LOG__", str(self.engine_log)).replace("__HEAD__", self.project_head),
            encoding="utf-8",
        )
        self.engine.chmod(0o700)
        payload = base_payload()
        payload["config/team.config.md"] = (TEAM_CONFIG, 0o640)
        for relative in (
            "bin/standalone_workspace.py",
            "bin/runtime-probe-agent.py",
            "bin/runtime-static-verify.py",
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

    def preview_digest(self) -> str:
        code, output, error = self.runtime()
        self.assertEqual((code, error), (0, ""), output + error)
        return json.loads(output)["planDigest"]

    def apply_on_linux(self, digest: str) -> tuple[int, str, str]:
        with mock.patch.object(runtime_kit.sys, "platform", "linux"):
            return self.runtime("--apply", "--plan-digest", digest)

    def crash_apply_after_phase(self, phase: str) -> str:
        digest = self.preview_digest()
        script = r'''
import json, os, signal, sys
from pathlib import Path
from startup_factory_cli import runtime_kit

target, project, runtime_root, engine, image, expected, phase = sys.argv[1:]
runtime_kit.sys.platform = "linux"
plan = runtime_kit.plan_runtime_kit(
    target=Path(target), project=Path(project), runtime_root=Path(runtime_root),
    engine=Path(engine), image=image, host_platform="linux",
)
if phase in {"locked", "prepared"}:
    original = runtime_kit._write_exclusive
    def write(path, content, mode):
        original(path, content, mode)
        if (phase == "locked" and path.name == ".runtime-kit.lock") or (
            phase == "prepared" and path.name == ".runtime-kit-journal.json"
        ):
            os.kill(os.getpid(), signal.SIGKILL)
    runtime_kit._write_exclusive = write
else:
    original = runtime_kit._replace_owned_transaction_file
    def replace(path, before, after):
        original(path, before, after)
        if json.loads(after)["phase"] == phase:
            os.kill(os.getpid(), signal.SIGKILL)
    runtime_kit._replace_owned_transaction_file = replace
runtime_kit.apply_runtime_kit(plan, expected_plan_digest=expected)
'''
        environment = {
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(ROOT / "src"),
        }
        crashed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(self.target),
                str(self.project),
                str(self.runtime_root),
                str(self.engine),
                IMAGE,
                digest,
                phase,
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stdout + crashed.stderr)
        self.assertTrue((self.runtime_root / ".runtime-kit.lock").exists())
        return digest

    def crash_after_transaction_created_assets_namespace(self) -> str:
        digest = self.preview_digest()
        script = r'''
import json, os, signal, sys
from pathlib import Path
from startup_factory_cli import runtime_kit

target, project, runtime_root, engine, image, expected = sys.argv[1:]
runtime_kit.sys.platform = "linux"
plan = runtime_kit.plan_runtime_kit(
    target=Path(target), project=Path(project), runtime_root=Path(runtime_root),
    engine=Path(engine), image=image, host_platform="linux",
)
original = runtime_kit._replace_owned_transaction_file
def replace(path, before, after):
    original(path, before, after)
    value = json.loads(after)
    assets = str(Path(runtime_root) / "assets")
    if (
        value["phase"] == "prepared"
        and any(record["path"] == assets for record in value["createdDirectories"])
    ):
        os.kill(os.getpid(), signal.SIGKILL)
runtime_kit._replace_owned_transaction_file = replace
runtime_kit.apply_runtime_kit(plan, expected_plan_digest=expected)
'''
        crashed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(self.target),
                str(self.project),
                str(self.runtime_root),
                str(self.engine),
                IMAGE,
                digest,
            ],
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stdout + crashed.stderr)
        journal = json.loads((self.runtime_root / ".runtime-kit-journal.json").read_text())
        assets = self.runtime_root / "assets"
        self.assertEqual(journal["phase"], "prepared")
        self.assertTrue(any(record["path"] == str(assets) for record in journal["createdDirectories"]))
        self.assertTrue(assets.is_dir())
        return digest

    def assert_recovery_round_trip(self, phase: str, expected_action: str) -> None:
        original_digest = self.crash_apply_after_phase(phase)
        code, _, error = self.runtime()
        self.assertEqual(code, 1)
        self.assertIn("--recover", error)
        code, output, error = self.runtime("--recover")
        self.assertEqual((code, error), (0, ""), output + error)
        recovery = json.loads(output)
        self.assertEqual(recovery["transactionPhase"], phase)
        self.assertEqual(recovery["recoveryAction"], expected_action)
        self.assertRegex(recovery["recoveryDigest"], r"^sha256:[0-9a-f]{64}$")
        code, _, error = self.runtime(
            "--recover", "--apply", "--plan-digest", "sha256:" + "0" * 64
        )
        self.assertEqual(code, 1)
        self.assertIn("immutable recovery preview", error)
        self.assertTrue((self.runtime_root / ".runtime-kit.lock").exists())
        code, output, error = self.runtime(
            "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
        )
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertFalse((self.runtime_root / ".runtime-kit.lock").exists())
        self.assertFalse((self.runtime_root / ".runtime-kit-journal.json").exists())
        if expected_action == "finalize-commit":
            code, output, error = self.runtime()
            self.assertEqual((code, error), (0, ""), output + error)
            self.assertEqual(json.loads(output)["changes"], [])
            verified = subprocess.run(
                ["python3", str(self.target / "bin/runtime-static-verify.py"), "--target", str(self.target)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
        else:
            self.assertEqual((self.target / "config/team.config.md").read_bytes(), TEAM_CONFIG)
            code, output, error = self.apply_on_linux(self.preview_digest())
            self.assertEqual((code, error), (0, ""), output + error)
        self.assertRegex(original_digest, r"^sha256:[0-9a-f]{64}$")

    def test_process_death_after_locked_phase_recovers_by_exact_preview(self) -> None:
        self.assert_recovery_round_trip("locked", "clear-lock")

    def test_recovery_preserves_a_lock_while_its_exact_owner_is_alive(self) -> None:
        digest = self.preview_digest()
        sentinel = self.root / "lock-owner-active"
        script = r'''
import os, signal, sys
from pathlib import Path
from startup_factory_cli import runtime_kit

target, project, runtime_root, engine, image, expected, sentinel = sys.argv[1:]
runtime_kit.sys.platform = "linux"
plan = runtime_kit.plan_runtime_kit(
    target=Path(target), project=Path(project), runtime_root=Path(runtime_root),
    engine=Path(engine), image=image, host_platform="linux",
)
original = runtime_kit._write_exclusive
def write(path, content, mode):
    original(path, content, mode)
    if path.name == ".runtime-kit.lock":
        Path(sentinel).touch()
        signal.pause()
runtime_kit._write_exclusive = write
runtime_kit.apply_runtime_kit(plan, expected_plan_digest=expected)
'''
        owner = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(self.target),
                str(self.project),
                str(self.runtime_root),
                str(self.engine),
                IMAGE,
                digest,
                str(sentinel),
            ],
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(200):
                if sentinel.exists():
                    break
                time.sleep(0.01)
            self.assertTrue(sentinel.exists(), "lock owner never reached its durable lock phase")
            lock = self.runtime_root / ".runtime-kit.lock"
            before = lock.read_bytes()
            code, _, error = self.runtime("--recover")
            self.assertEqual(code, 1)
            self.assertIn("owner is still active", error)
            self.assertEqual(lock.read_bytes(), before)
        finally:
            owner.kill()
            owner.communicate(timeout=10)
        code, output, error = self.runtime("--recover")
        self.assertEqual((code, error), (0, ""), output + error)
        recovery = json.loads(output)
        self.assertEqual(recovery["recoveryAction"], "clear-lock")
        code, output, error = self.runtime(
            "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
        )
        self.assertEqual((code, error), (0, ""), output + error)

    def test_process_death_after_prepared_phase_recovers_by_exact_preview(self) -> None:
        self.assert_recovery_round_trip("prepared", "rollback")

    def test_real_death_pre_asset_phases_preserve_substituted_ancestor_and_evidence(self) -> None:
        for phase in ("locked", "prepared"):
            with self.subTest(phase=phase):
                digest = self.crash_apply_after_phase(phase)
                outside = self.root / f"outside-after-{phase}"
                outside.mkdir(mode=0o700)
                substituted = self.runtime_root / "assets"
                self.assertFalse(os.path.lexists(substituted))
                substituted.symlink_to(outside, target_is_directory=True)
                lock = self.runtime_root / ".runtime-kit.lock"
                journal = self.runtime_root / ".runtime-kit-journal.json"
                lock_before = lock.read_bytes()
                journal_before = journal.read_bytes() if journal.exists() else None

                code, _, error = self.runtime("--recover")
                self.assertEqual(code, 1)
                self.assertIn("substituted path", error)
                self.assertIn("--recover", error)
                self.assertEqual(lock.read_bytes(), lock_before)
                if journal_before is not None:
                    self.assertEqual(journal.read_bytes(), journal_before)
                self.assertTrue(substituted.is_symlink())
                self.assertEqual(list(outside.iterdir()), [])

                # Ordinary preview/apply must validate the same absent-leaf
                # ancestry and cannot clear recovery evidence.
                code, _, error = self.apply_on_linux(digest)
                self.assertEqual(code, 1)
                self.assertIn("substituted path", error)
                self.assertEqual(lock.read_bytes(), lock_before)
                self.assertEqual(list(outside.iterdir()), [])

                substituted.unlink()
                recovery_code, recovery_output, recovery_error = self.runtime("--recover")
                self.assertEqual((recovery_code, recovery_error), (0, ""), recovery_output + recovery_error)
                recovery = json.loads(recovery_output)
                code, output, error = self.runtime(
                    "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
                )
                self.assertEqual((code, error), (0, ""), output + error)
                if phase == "locked":
                    self.runtime_root.mkdir(mode=0o700, exist_ok=True)

                # A substitution after a successful recovery preview must be
                # caught by apply's mandatory re-preview. The stale digest can
                # never authorize cleanup of the lock or journal.
                self.crash_apply_after_phase(phase)
                code, output, error = self.runtime("--recover")
                self.assertEqual((code, error), (0, ""), output + error)
                recovery = json.loads(output)
                outside_apply = self.root / f"outside-apply-{phase}"
                outside_apply.mkdir(mode=0o700)
                substituted.symlink_to(outside_apply, target_is_directory=True)
                lock_before = lock.read_bytes()
                journal_before = journal.read_bytes() if journal.exists() else None
                code, _, error = self.runtime(
                    "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
                )
                self.assertEqual(code, 1)
                self.assertIn("substituted path", error)
                self.assertEqual(lock.read_bytes(), lock_before)
                if journal_before is not None:
                    self.assertEqual(journal.read_bytes(), journal_before)
                self.assertTrue(substituted.is_symlink())
                self.assertEqual(list(outside_apply.iterdir()), [])
                substituted.unlink()
                code, output, error = self.runtime("--recover")
                self.assertEqual((code, error), (0, ""), output + error)
                recovery = json.loads(output)
                code, output, error = self.runtime(
                    "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
                )
                self.assertEqual((code, error), (0, ""), output + error)
                if phase == "locked":
                    self.runtime_root.mkdir(mode=0o700, exist_ok=True)

    def test_real_death_rejects_unbound_namespace_mode_and_type_matrix(self) -> None:
        cases = ("world-writable", "wrong-private-mode", "unexpected-private", "fifo")
        for phase in ("locked", "prepared"):
            for case in cases:
                with self.subTest(phase=phase, case=case):
                    self.crash_apply_after_phase(phase)
                    namespace = self.runtime_root / "assets"
                    if case == "fifo":
                        os.mkfifo(namespace, 0o600)
                    else:
                        namespace.mkdir(mode=0o700)
                        if case == "world-writable":
                            namespace.chmod(0o777)
                        elif case == "wrong-private-mode":
                            namespace.chmod(0o500)
                    lock = self.runtime_root / ".runtime-kit.lock"
                    journal = self.runtime_root / ".runtime-kit-journal.json"
                    lock_before = lock.read_bytes()
                    journal_before = journal.read_bytes() if journal.exists() else None

                    code, _, error = self.runtime("--recover")
                    self.assertEqual(code, 1)
                    self.assertIn("reserved namespace mismatch", error)
                    self.assertIn("lock, journal, and unexpected namespace were preserved", error)
                    self.assertEqual(lock.read_bytes(), lock_before)
                    if journal_before is not None:
                        self.assertEqual(journal.read_bytes(), journal_before)
                    self.assertTrue(os.path.lexists(namespace))

                    if namespace.is_dir():
                        namespace.chmod(0o700)
                        namespace.rmdir()
                    else:
                        namespace.unlink()
                    code, output, error = self.runtime("--recover")
                    self.assertEqual((code, error), (0, ""), output + error)
                    recovery = json.loads(output)
                    code, output, error = self.runtime(
                        "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
                    )
                    self.assertEqual((code, error), (0, ""), output + error)

    def test_real_death_rejects_replaced_bound_namespace_inode(self) -> None:
        for phase in ("locked", "prepared"):
            with self.subTest(phase=phase):
                self.runtime_root.mkdir(mode=0o700, exist_ok=True)
                namespace = self.runtime_root / "assets"
                namespace.mkdir(mode=0o700)
                self.crash_apply_after_phase(phase)
                original = self.runtime_root / "assets-recorded-identity"
                namespace.rename(original)
                namespace.mkdir(mode=0o700)
                lock = self.runtime_root / ".runtime-kit.lock"
                journal = self.runtime_root / ".runtime-kit-journal.json"
                lock_before = lock.read_bytes()
                journal_before = journal.read_bytes() if journal.exists() else None

                code, _, error = self.runtime("--recover")
                self.assertEqual(code, 1)
                self.assertIn("reserved namespace mismatch", error)
                self.assertEqual(lock.read_bytes(), lock_before)
                if journal_before is not None:
                    self.assertEqual(journal.read_bytes(), journal_before)
                namespace.rmdir()
                original.rename(namespace)
                code, output, error = self.runtime("--recover")
                self.assertEqual((code, error), (0, ""), output + error)
                recovery = json.loads(output)
                code, output, error = self.runtime(
                    "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
                )
                self.assertEqual((code, error), (0, ""), output + error)
                self.assertTrue(namespace.is_dir(), "authorized pre-state must never be removed")
                namespace.rmdir()
                self.runtime_root.rmdir()

    def test_real_death_rejects_bound_namespace_link_count_change(self) -> None:
        for phase in ("locked", "prepared"):
            with self.subTest(phase=phase):
                self.runtime_root.mkdir(mode=0o700, exist_ok=True)
                namespace = self.runtime_root / "assets"
                namespace.mkdir(mode=0o700)
                original_links = namespace.stat().st_nlink
                self.crash_apply_after_phase(phase)
                unexpected_child = namespace / "unbound-child"
                unexpected_child.mkdir(mode=0o700)
                self.assertNotEqual(namespace.stat().st_nlink, original_links)
                lock = self.runtime_root / ".runtime-kit.lock"
                before = lock.read_bytes()
                code, _, error = self.runtime("--recover")
                self.assertEqual(code, 1)
                self.assertIn("reserved namespace mismatch", error)
                self.assertEqual(lock.read_bytes(), before)

                unexpected_child.rmdir()
                code, output, error = self.runtime("--recover")
                self.assertEqual((code, error), (0, ""), output + error)
                recovery = json.loads(output)
                code, output, error = self.runtime(
                    "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
                )
                self.assertEqual((code, error), (0, ""), output + error)
                namespace.rmdir()
                self.runtime_root.rmdir()

    def test_wrong_namespace_owner_is_simulated_without_privileged_chown(self) -> None:
        for phase in ("locked", "prepared"):
            with self.subTest(phase=phase):
                self.runtime_root.mkdir(mode=0o700, exist_ok=True)
                namespace = self.runtime_root / "assets"
                namespace.mkdir(mode=0o700)
                self.crash_apply_after_phase(phase)
                original_state = runtime_kit._directory_recovery_state

                def simulated_wrong_owner(path: Path) -> dict[str, object]:
                    state = original_state(path)
                    if path == namespace and state.get("exists") is True:
                        state = dict(state)
                        state["owner"] = os.geteuid() + 1
                    return state

                lock = self.runtime_root / ".runtime-kit.lock"
                lock_before = lock.read_bytes()
                with mock.patch.object(
                    runtime_kit, "_directory_recovery_state", side_effect=simulated_wrong_owner
                ):
                    code, _, error = self.runtime("--recover")
                self.assertEqual(code, 1)
                self.assertIn("reserved namespace mismatch", error)
                self.assertEqual(lock.read_bytes(), lock_before)

                code, output, error = self.runtime("--recover")
                self.assertEqual((code, error), (0, ""), output + error)
                recovery = json.loads(output)
                code, output, error = self.runtime(
                    "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
                )
                self.assertEqual((code, error), (0, ""), output + error)
                self.assertTrue(namespace.is_dir())
                namespace.rmdir()
                self.runtime_root.rmdir()

    def test_exact_transaction_created_namespace_is_the_only_created_state_removed(self) -> None:
        self.crash_after_transaction_created_assets_namespace()
        namespace = self.runtime_root / "assets"
        journal = json.loads((self.runtime_root / ".runtime-kit-journal.json").read_text())
        bound = next(
            record for record in journal["createdDirectories"] if record["path"] == str(namespace)
        )
        self.assertEqual(bound["state"]["inode"], namespace.stat().st_ino)
        self.assertEqual(bound["state"]["mode"], 0o700)
        code, output, error = self.runtime("--recover")
        self.assertEqual((code, error), (0, ""), output + error)
        recovery = json.loads(output)
        self.assertEqual(recovery["transactionPhase"], "prepared")
        code, output, error = self.runtime(
            "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
        )
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertFalse(namespace.exists())
        self.assertFalse((self.runtime_root / ".runtime-kit.lock").exists())
        self.assertFalse((self.runtime_root / ".runtime-kit-journal.json").exists())

    def test_descriptor_relative_creation_never_follows_raced_assets_symlink(self) -> None:
        digest = self.preview_digest()
        outside = self.root / "outside-race-target"
        outside.mkdir(mode=0o700)
        substituted = self.runtime_root / "assets"
        original_mkdir = runtime_kit.os.mkdir
        injected = False

        def substitute_before_create(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal injected
            if path == "assets" and dir_fd is not None and not injected:
                substituted.symlink_to(outside, target_is_directory=True)
                injected = True
            original_mkdir(path, mode, dir_fd=dir_fd)

        with (
            mock.patch.object(runtime_kit.sys, "platform", "linux"),
            mock.patch.object(runtime_kit.os, "mkdir", side_effect=substitute_before_create),
        ):
            code, _, error = self.runtime("--apply", "--plan-digest", digest)
        self.assertEqual(code, 1)
        self.assertTrue(injected)
        self.assertIn("lock, journal, and substituted path were preserved", error)
        self.assertTrue((self.runtime_root / ".runtime-kit.lock").exists())
        self.assertTrue((self.runtime_root / ".runtime-kit-journal.json").exists())
        self.assertTrue(substituted.is_symlink())
        self.assertEqual(list(outside.iterdir()), [])

        code, _, recovery_error = self.runtime("--recover")
        self.assertEqual(code, 1)
        self.assertIn("substituted path", recovery_error)
        self.assertEqual(list(outside.iterdir()), [])

    def test_process_death_after_assets_written_phase_recovers_by_exact_preview(self) -> None:
        self.assert_recovery_round_trip("assets-written", "rollback")

    def test_process_death_after_config_replaced_phase_recovers_by_exact_preview(self) -> None:
        self.assert_recovery_round_trip("config-replaced", "rollback")

    def test_process_death_after_commit_marked_phase_blocks_authority_until_finalized(self) -> None:
        self.crash_apply_after_phase("commit-marked")
        static = subprocess.run(
            ["python3", str(self.target / "bin/runtime-static-verify.py"), "--target", str(self.target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(static.returncode, 0)
        self.assertIn("--recover", static.stderr)
        code, output, _ = invoke(
            "doctor", "--project", str(self.project), "--install-dir", str(self.target),
            "--mode", "team", "--json",
        )
        self.assertEqual(code, 1)
        configured = next(
            item for item in json.loads(output)["checks"] if item["id"] == "secure-runtime.configured"
        )
        self.assertEqual(configured["status"], "fail")
        code, output, error = self.runtime("--recover")
        self.assertEqual((code, error), (0, ""), output + error)
        recovery = json.loads(output)
        self.assertEqual(recovery["recoveryAction"], "finalize-commit")
        code, output, error = self.runtime(
            "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
        )
        self.assertEqual((code, error), (0, ""), output + error)
        static = subprocess.run(
            ["python3", str(self.target / "bin/runtime-static-verify.py"), "--target", str(self.target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(static.returncode, 0, static.stderr)

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
        code, output, error = self.apply_on_linux(digest)
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
        code, output, error = self.apply_on_linux(retry["planDigest"])
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertEqual(json.loads(output)["changes"], [])

    def test_wrong_digest_macos_rootful_and_unpinned_fail_without_mutation(self) -> None:
        code, _, error = self.runtime("--apply", "--plan-digest", "sha256:" + "0" * 64)
        self.assertEqual(code, 1)
        self.assertIn("plan-digest", error)
        self.assertFalse(self.runtime_root.exists())

        digest = self.preview_digest()
        with mock.patch.object(runtime_kit.sys, "platform", "darwin"):
            code, _, error = self.runtime("--apply", "--plan-digest", digest)
        self.assertEqual(code, 1)
        self.assertIn("refused on Darwin", error)
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

        self.runtime_root.unlink()
        digest = self.preview_digest()
        code, output, error = self.apply_on_linux(digest)
        self.assertEqual((code, error), (0, ""), output + error)
        runner = next(self.runtime_root.glob("assets/*/runner"))
        runner.write_bytes(runner.read_bytes() + b"\n# operator tamper\n")
        code, _, error = self.runtime()
        self.assertEqual(code, 1)
        self.assertIn("refuses overwrite", error)
        self.assertIn(b"operator tamper", runner.read_bytes())

    def test_missing_runtime_leaf_below_substituted_ancestor_fails_static_and_readiness(self) -> None:
        code, output, error = self.apply_on_linux(self.preview_digest())
        self.assertEqual((code, error), (0, ""), output + error)
        asset_root = next((self.runtime_root / "assets").iterdir())
        preserved = asset_root.with_name(asset_root.name + ".preserved")
        asset_root.rename(preserved)
        outside = self.root / "outside-static"
        outside.mkdir(mode=0o700)
        asset_root.symlink_to(outside, target_is_directory=True)

        static = subprocess.run(
            ["python3", str(self.target / "bin/runtime-static-verify.py"), "--target", str(self.target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(static.returncode, 0)
        self.assertIn("symlink", static.stderr)
        code, output, error = invoke(
            "doctor", "--project", str(self.project), "--install-dir", str(self.target),
            "--mode", "team", "--json",
        )
        self.assertEqual((code, error), (1, ""), output + error)
        configured = next(
            item for item in json.loads(output)["checks"] if item["id"] == "secure-runtime.configured"
        )
        self.assertEqual(configured["status"], "fail")
        code, _, error = self.runtime()
        self.assertEqual(code, 1)
        self.assertIn("substituted path", error)
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

    def test_foreign_lock_and_recovery_evidence_are_never_deleted(self) -> None:
        digest = self.preview_digest()
        self.runtime_root.mkdir(mode=0o700)
        lock = self.runtime_root / ".runtime-kit.lock"
        lock.write_bytes(b"foreign-lock\n")
        lock.chmod(0o600)
        code, _, error = self.apply_on_linux(digest)
        self.assertEqual(code, 1)
        self.assertIn("recovery state", error)
        self.assertEqual(lock.read_bytes(), b"foreign-lock\n")
        code, _, error = self.runtime("--recover")
        self.assertEqual(code, 1)
        self.assertIn("malformed or foreign", error)
        self.assertEqual(lock.read_bytes(), b"foreign-lock\n")

        lock.unlink()
        journal = self.runtime_root / ".runtime-kit-journal.json"
        journal.write_text('{"schemaVersion":2,"phase":"prepared"}\n')
        journal.chmod(0o600)
        code, _, error = self.apply_on_linux(digest)
        self.assertEqual(code, 1)
        self.assertIn("recovery state", error)
        self.assertTrue(journal.exists())

        journal.unlink()
        lock.write_text(
            '{"schemaVersion":2,"phase":"locked","transactionToken":"'
            + "a" * 64
            + '"}\n'
        )
        lock.chmod(0o600)
        alias = self.root / "hard-linked-lock"
        os.link(lock, alias)
        code, _, error = self.apply_on_linux(digest)
        self.assertEqual(code, 1)
        self.assertIn("single-link", error)
        self.assertTrue(lock.exists())
        self.assertTrue(alias.exists())

    def test_recovery_preview_and_apply_preserve_changed_assets_and_evidence(self) -> None:
        self.crash_apply_after_phase("assets-written")
        code, output, error = self.runtime("--recover")
        self.assertEqual((code, error), (0, ""), output + error)
        recovery = json.loads(output)
        journal = self.runtime_root / ".runtime-kit-journal.json"
        journal_before = journal.read_bytes()
        asset = next(self.runtime_root.glob("assets/*/runner"))
        asset.write_bytes(asset.read_bytes() + b"tamper\n")
        code, _, error = self.runtime(
            "--recover", "--apply", "--plan-digest", recovery["recoveryDigest"]
        )
        self.assertEqual(code, 1)
        self.assertIn("neither recorded pre-state nor post-image", error)
        self.assertEqual(journal.read_bytes(), journal_before)
        self.assertTrue((self.runtime_root / ".runtime-kit.lock").exists())
        self.assertIn(b"tamper", asset.read_bytes())

    def test_idempotent_retry_requires_commit_marker_and_clean_recovery_state(self) -> None:
        digest = self.preview_digest()
        code, output, error = self.apply_on_linux(digest)
        self.assertEqual((code, error), (0, ""), output + error)
        retry = self.preview_digest()
        marker = next(self.runtime_root.glob(".runtime-kit-committed-*"))
        marker.unlink()
        code, _, error = self.apply_on_linux(retry)
        self.assertEqual(code, 1)
        self.assertIn("commit marker", error)

    def test_tampered_owned_journal_is_preserved_for_recovery(self) -> None:
        before = (self.target / "config/team.config.md").read_bytes()
        digest = self.preview_digest()
        original = runtime_kit._replace_config

        def replace_tamper_and_fail(plan: runtime_kit.RuntimePlan) -> None:
            original(plan)
            journal = plan.runtime_root / ".runtime-kit-journal.json"
            journal.write_bytes(b"tampered recovery evidence\n")
            journal.chmod(0o600)
            raise OSError("injected durable crash window")

        with mock.patch.object(runtime_kit, "_replace_config", side_effect=replace_tamper_and_fail):
            code, _, error = self.apply_on_linux(digest)
        self.assertEqual(code, 1)
        self.assertIn("rollback requires operator recovery", error)
        journal = self.runtime_root / ".runtime-kit-journal.json"
        self.assertEqual(journal.read_bytes(), b"tampered recovery evidence\n")
        self.assertEqual((self.target / "config/team.config.md").read_bytes(), before)

    def test_concurrent_config_change_and_asset_phase_crash_preserve_boundaries(self) -> None:
        digest = self.preview_digest()
        config = self.target / "config/team.config.md"
        config.write_bytes(config.read_bytes() + b"# concurrent operator edit\n")
        code, _, error = self.apply_on_linux(digest)
        self.assertEqual(code, 1)
        self.assertIn("plan-digest", error)
        self.assertIn(b"concurrent operator edit", config.read_bytes())
        self.assertFalse(self.runtime_root.exists())

        config.write_bytes(config.read_bytes().replace(b"# concurrent operator edit\n", b""))
        digest = self.preview_digest()

        def crash_before_config(plan: runtime_kit.RuntimePlan) -> None:
            journal = plan.runtime_root / ".runtime-kit-journal.json"
            self.assertEqual(json.loads(journal.read_text())["phase"], "assets-written")
            raise OSError("injected crash after durable asset phase")

        with mock.patch.object(runtime_kit, "_replace_config", side_effect=crash_before_config):
            code, _, error = self.apply_on_linux(digest)
        self.assertEqual(code, 1)
        self.assertIn("transaction failed", error)
        self.assertFalse(self.runtime_root.exists())
        self.assertEqual(config.read_bytes(), TEAM_CONFIG)

    def test_engine_json_and_proof_shape_fail_closed(self) -> None:
        cases = {
            "malformed": "printf '%s\\n' '{'",
            "duplicate": "printf '%s\\n' '{\"version\":{},\"version\":{}}'",
            "oversize": "/usr/bin/python3 -c 'print(\"x\" * 300000)'",
            "mapping": "printf '%s\\n' '{\"version\":{\"Version\":\"5.4.2\"},\"host\":{\"security\":{\"rootless\":true},\"idMappings\":{\"uidmap\":[],\"gidmap\":[]}}}'",
        }
        for label, command in cases.items():
            with self.subTest(label=label):
                self.engine.write_text(f"#!/bin/sh\nif [ \"$1\" = info ]; then {command}; else exit 64; fi\n")
                self.engine.chmod(0o700)
                code, _, error = self.runtime()
                self.assertEqual(code, 1)
                self.assertTrue(error)

        self.engine.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = info ]; then printf '%s\\n' '"
            '{"version":{"Version":"5.4.2"},"host":{"security":{"rootless":true},"idMappings":{"uidmap":[{"container_id":0,"host_id":1000,"size":1}],"gidmap":[{"container_id":0,"host_id":1000,"size":1}]}}}'
            "'; else printf '%s\\n' '[{},{}]'; fi\n"
        )
        self.engine.chmod(0o700)
        code, _, error = self.runtime()
        self.assertEqual(code, 1)
        self.assertIn("exactly one", error)

    def test_probe_is_digest_bound_and_never_promotes_readiness(self) -> None:
        digest = self.preview_digest()
        code, output, error = self.apply_on_linux(digest)
        self.assertEqual((code, error), (0, ""), output + error)
        code, output, error = self.runtime("--probe")
        self.assertEqual((code, error), (0, ""), output + error)
        result = json.loads(output)
        self.assertFalse(result["ready"])
        self.assertEqual(result["probe"]["readinessEffect"], "none")
        self.assertEqual(result["probe"]["result"], "fixed-controls-passed-non-promoting")
        self.assertTrue(result["probe"]["observations"]["denials"]["canonicalRepo"])

    def test_rendered_runner_mounts_only_issued_clone_tools_and_scoped_ingress(self) -> None:
        digest = self.preview_digest()
        code, output, error = self.apply_on_linux(digest)
        self.assertEqual((code, error), (0, ""), output + error)
        verified = subprocess.run(
            ["python3", str(self.target / "bin/runtime-static-verify.py"), "--target", str(self.target)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertTrue(json.loads(verified.stdout)["ok"])

        create = subprocess.run(
            [
                "python3", str(ROOT / "bin/standalone_workspace.py"), "create",
                "--repo", str(self.project), "--root", str(self.runtime_root / "attempt-clones"),
                "--team", "feature-runtime", "--role", "backend", "--attempt", "1",
                "--task-key", "gate-backend", "--branch", "agent-runtime/feature-runtime/gate-backend",
                "--base-ref", "main",
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        clone = Path(json.loads(create.stdout)["path"])
        sibling = clone.parent / "sibling#1-denied"
        sibling.mkdir(mode=0o700)
        ingress = self.runtime_root / "outbox-ingress" / ("cap-" + "c" * 32)
        ingress.mkdir(mode=0o700)
        runner = next(self.runtime_root.glob("assets/*/runner"))
        environment = {
            "PATH": "/usr/bin:/bin",
            "STARTUP_FACTORY_AGENT_WORKTREE": str(clone),
            "STARTUP_FACTORY_ROLE": "backend",
            "STARTUP_FACTORY_TEAM": "feature-runtime",
            "STARTUP_FACTORY_FEATURE_ID": "F-1",
            "STARTUP_FACTORY_PRESET": "deep-infra",
            "STARTUP_FACTORY_EXECUTION_KIND": "gate",
            "STARTUP_FACTORY_TASK_ID": "-",
            "STARTUP_FACTORY_ATTEMPT": "0",
            "STARTUP_FACTORY_INSTANCE": "gate:backend",
            "STARTUP_FACTORY_OUTBOX_INGRESS": str(ingress),
            "STARTUP_FACTORY_OUTBOX_CAPABILITY_ID": ingress.name,
            "STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET": "d" * 64,
            "STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT": "2000000000",
            "STARTUP_FACTORY_SKILL_ROOT": str(self.target),
        }
        result = subprocess.run(
            [str(runner), "--workdir", str(clone), "--", "/bin/true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invoked = self.engine_log.read_text()
        self.assertIn(f"type=bind,src={clone},dst={clone},rw", invoked)
        self.assertIn(f"type=bind,src={self.target},dst={self.target},ro", invoked)
        self.assertIn(f"type=bind,src={ingress},dst={ingress},rw", invoked)
        self.assertNotIn(str(self.project), invoked)
        self.assertNotIn(str(self.runtime_root / "lifecycle"), invoked)
        self.assertNotIn(str(sibling), invoked)
        self.assertIn("--pull=never", invoked)
        self.assertIn("--network=none", invoked)

        policy = next(self.runtime_root.glob("assets/*/container-policy.json"))
        before = policy.read_bytes()
        policy.write_bytes(before + b"\n")
        refused = subprocess.run(
            [str(runner), "--workdir", str(clone), "--", "/bin/true"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            check=False,
        )
        self.assertNotEqual(refused.returncode, 0)
        static_refused = subprocess.run(
            ["python3", str(self.target / "bin/runtime-static-verify.py"), "--target", str(self.target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(static_refused.returncode, 0)
        code, output, error = invoke(
            "doctor", "--project", str(self.project), "--install-dir", str(self.target),
            "--mode", "team", "--json",
        )
        self.assertEqual((code, error), (1, ""), output + error)
        doctor = {item["id"]: item for item in json.loads(output)["checks"]}
        self.assertEqual(doctor["secure-runtime.configured"]["status"], "fail")
        policy.write_bytes(before)

    def test_bundle_update_preserves_runtime_assets_operator_files_and_new_config_fields(self) -> None:
        digest = self.preview_digest()
        code, output, error = self.apply_on_linux(digest)
        self.assertEqual((code, error), (0, ""), output + error)
        old_assets = {path.name for path in (self.runtime_root / "assets").iterdir()}
        operator_file = self.runtime_root / "operator-preserved.txt"
        operator_file.write_text("operator state\n")

        payload = base_payload("2")
        payload["config/team.config.md"] = (b"new bundled default that must not replace applied config\n", 0o640)
        for relative in (
            "bin/standalone_workspace.py",
            "bin/runtime-probe-agent.py",
            "bin/runtime-static-verify.py",
            "runtime/runner-linux-container.sh",
            "runtime/container-policy.json",
            "runtime/network-policy-none.json",
        ):
            source = ROOT / relative
            content = source.read_bytes()
            if relative == "runtime/runner-linux-container.sh":
                content += b"\n# compatible runtime source update\n"
            payload[relative] = (content, stat.S_IMODE(source.stat().st_mode))
        bundle = write_bundle(self.root / "bundle-v2.tar.gz", version="2.0.0", payload=payload)
        code, output, error = invoke(
            "update", "--project", str(self.project), "--install-dir", str(self.target),
            "--bundle", str(bundle), "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)
        config = (self.target / "config/team.config.md").read_text()
        self.assertIn("BROKER_AGENT_OUTBOX_ROOT=", config)
        self.assertIn("AGENT_RUNTIME_MANIFEST=", config)
        self.assertNotIn("new bundled default", config)

        digest = self.preview_digest()
        code, output, error = self.apply_on_linux(digest)
        self.assertEqual((code, error), (0, ""), output + error)
        current_assets = {path.name for path in (self.runtime_root / "assets").iterdir()}
        self.assertTrue(old_assets < current_assets)
        self.assertEqual(operator_file.read_text(), "operator state\n")


if __name__ == "__main__":
    unittest.main()
