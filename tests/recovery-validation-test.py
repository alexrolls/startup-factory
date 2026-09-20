#!/usr/bin/env python3
"""Focused tests for the credential-free recovery validation boundary."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOUNDARY = ROOT / "bin" / "recovery_validation.py"
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli.readiness import _sandbox_runner_readiness  # noqa: E402

SPEC = importlib.util.spec_from_file_location("recovery_validation_tested", BOUNDARY)
assert SPEC is not None and SPEC.loader is not None
recovery_validation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = recovery_validation
SPEC.loader.exec_module(recovery_validation)
PM_SPEC = importlib.util.spec_from_file_location(
    "pm_agent_runner_contract_tested", ROOT / "bin" / "pm-agent.py"
)
assert PM_SPEC is not None and PM_SPEC.loader is not None
pm_agent = importlib.util.module_from_spec(PM_SPEC)
sys.modules[PM_SPEC.name] = pm_agent
PM_SPEC.loader.exec_module(pm_agent)
SAFE_ENV_NAMES = ("PATH", "TMPDIR", "LANG", "LC_ALL", "TERM", "NO_COLOR")


class RecoveryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.config = self.repo / "team.config.md"
        self.changed = self.repo / "changed-files.txt"
        self.changed.write_bytes(b"src/example.py\0")

    def write_script(self, relative: str, body: str) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o700)
        return path

    def write_config(
        self,
        *,
        allowlist: str = "PATH TMPDIR LANG LC_ALL TERM NO_COLOR",
        enforced: str = "false",
        runner: str | None = None,
        script: str | None = None,
        build: str | None = None,
        test: str | None = None,
        lint: str | None = None,
        format_command: str | None = None,
        extra: str = "",
    ) -> None:
        values = {
            "AGENT_ENV_ALLOWLIST": allowlist,
            "AGENT_SANDBOX_ENFORCED": enforced,
            "AGENT_SANDBOX_RUNNER": runner,
            "VALIDATE_SCRIPT": script,
            "VALIDATE_BUILD": build,
            "VALIDATE_TEST": test,
            "VALIDATE_LINT": lint,
            "VALIDATE_FORMAT": format_command,
        }
        lines = [
            f"{key}={'null' if value is None else json.dumps(value)}"
            for key, value in values.items()
        ]
        self.config.write_text("\n".join(lines) + "\n" + extra, encoding="utf-8")

    def invoke(
        self,
        *,
        changed_argument: str | None = None,
        input_text: str | None = None,
        **environment: str,
    ) -> subprocess.CompletedProcess[str]:
        child_environment = dict(os.environ)
        child_environment.update(environment)
        bootstrap_values = {
            "PATH": "/usr/bin:/bin",
            "TMPDIR": child_environment.get("TMPDIR", "/tmp"),
            "LANG": child_environment.get("LANG", "C"),
            "LC_ALL": child_environment.get("LC_ALL", "C"),
            "TERM": child_environment.get("TERM", "dumb"),
            "NO_COLOR": child_environment.get("NO_COLOR", ""),
        }
        fixed = [f"{name}={bootstrap_values[name]}" for name in SAFE_ENV_NAMES]
        return subprocess.run(
            [
                "/usr/bin/env",
                "-i",
                *fixed,
                "AWS_EC2_METADATA_DISABLED=true",
                "PYTHONDONTWRITEBYTECODE=1",
                "/usr/bin/python3",
                "-I",
                "-B",
                str(BOUNDARY),
                "--repo",
                str(self.repo),
                "--config",
                str(self.config),
                "--changed-files",
                changed_argument or str(self.changed),
            ],
            cwd=ROOT,
            env=child_environment,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_direct_mode_scrubs_secrets_and_preserves_safe_allowlist(self) -> None:
        self.write_script(
            "scripts/capture-env.sh",
            """{
  printf 'safe=%s\\n' "${NO_COLOR-unset}"
  printf 'secret=%s\\n' "${SECRET_CANARY-unset}"
  printf 'tracker=%s\\n' "${LINEAR_API_KEY-unset}"
  printf 'cloud=%s\\n' "${AWS_SECRET_ACCESS_KEY-unset}"
  printf 'startup=%s\\n' "${STARTUP_FACTORY_TRACKER_TOKEN-unset}"
  printf 'home=%s\\n' "${HOME-unset}"
  printf 'metadata=%s\\n' "${AWS_EC2_METADATA_DISABLED-unset}"
  printf 'bytecode=%s\\n' "${PYTHONDONTWRITEBYTECODE-unset}"
} > recovery-env.txt
""",
        )
        self.write_config(script="scripts/capture-env.sh")

        result = self.invoke(
            NO_COLOR="kept",
            SECRET_CANARY="must-not-leak",
            LINEAR_API_KEY="must-not-leak",
            AWS_SECRET_ACCESS_KEY="must-not-leak",
            STARTUP_FACTORY_TRACKER_TOKEN="must-not-leak",
            HOME="/credentialed/operator/home",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.repo / "recovery-env.txt").read_text(encoding="utf-8").splitlines(),
            [
                "safe=kept",
                "secret=unset",
                "tracker=unset",
                "cloud=unset",
                "startup=unset",
                "home=unset",
                "metadata=true",
                "bytecode=1",
            ],
        )
        self.assertIn("no filesystem or process isolation", result.stderr)

    def test_validate_script_receives_changed_files_as_exact_argv(self) -> None:
        paths = [
            b"src/first.py",
            b"path with spaces/example.txt",
            b"tab\tname.py",
            b"line\nbreak.py",
            b'quote"name.py',
            b"-leading-dash",
            b"back\\slash.py",
            b"non-utf8-\xff.bin",
        ]
        self.changed.write_bytes(b"\0".join(paths) + b"\0")
        self.write_script(
            "scripts/validate-changed.sh",
            "{ printf '%s\\000' \"$#\"; "
            "for item in \"$@\"; do printf '%s\\000' \"$item\"; done; "
            "} > validation-argv.bin\n",
        )
        self.write_config(
            script="scripts/validate-changed.sh",
            build="exit 88",
            test="exit 89",
        )

        result = self.invoke(NO_COLOR="ok")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.repo / "validation-argv.bin").read_bytes().split(b"\0")[:-1],
            [str(len(paths)).encode(), *paths],
        )

    def test_changed_files_can_arrive_as_bounded_nul_stdin(self) -> None:
        paths = ["stdin path.txt", "tab\tfrom-stdin.py", 'quote"from-stdin.py']
        self.write_script(
            "scripts/capture-stdin-paths.sh",
            "{ printf '%s\\000' \"$#\"; "
            "for item in \"$@\"; do printf '%s\\000' \"$item\"; done; "
            "} > stdin-paths.bin\n",
        )
        self.write_config(script="scripts/capture-stdin-paths.sh")

        result = self.invoke(
            changed_argument="-",
            input_text="\0".join(paths) + "\0",
            NO_COLOR="ok",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.repo / "stdin-paths.bin").read_bytes().split(b"\0")[:-1],
            [str(len(paths)).encode(), *(path.encode() for path in paths)],
        )

    def test_ordered_commands_stop_and_propagate_the_first_failure(self) -> None:
        self.write_config(
            build="printf 'build\\n' > validation-order.txt",
            test="printf 'test\\n' >> validation-order.txt; exit 23",
            lint="printf 'lint\\n' >> validation-order.txt",
            format_command="printf 'format\\n' >> validation-order.txt",
        )

        result = self.invoke(NO_COLOR="ok")

        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(
            (self.repo / "validation-order.txt").read_text(encoding="utf-8"),
            "build\ntest\n",
        )
        self.assertIn("VALIDATE_TEST failed with status 23", result.stderr)

    def test_helper_starts_with_fixed_interpreter_and_ignores_startup_hooks(self) -> None:
        hostile = self.base / "hostile-startup"
        hostile.mkdir()
        path_canary = self.base / "path-python-ran"
        site_canary = self.base / "sitecustomize-ran"
        fake_python = hostile / "python3"
        fake_python.write_text(
            "#!/bin/sh\n"
            f"printf compromised > {shlex.quote(str(path_canary))}\n"
            "exit 91\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o700)
        (hostile / "sitecustomize.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(site_canary)!r}).write_text('compromised')\n",
            encoding="utf-8",
        )
        self.write_config(test="true")

        result = self.invoke(
            PATH=f"{hostile}:/usr/bin:/bin",
            PYTHONPATH=str(hostile),
            PYTHONHOME=str(hostile),
            PYTHONSTARTUP=str(hostile / "sitecustomize.py"),
            PYTHONINSPECT="1",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(path_canary.exists())
        self.assertFalse(site_canary.exists())

        isolated_probe = subprocess.run(
            [
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                f"PYTHONPATH={hostile}",
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                "pass",
            ],
            cwd=self.repo,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(isolated_probe.returncode, 0, isolated_probe.stderr)
        self.assertFalse(site_canary.exists())

        non_isolated = subprocess.run(
            [
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "/usr/bin/python3",
                "-B",
                str(BOUNDARY),
                "--repo",
                str(self.repo),
                "--config",
                str(self.config),
                "--changed-files",
                str(self.changed),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(non_isolated.returncode, 2)
        self.assertIn("isolated and no-bytecode modes", non_isolated.stderr)

    def test_changed_file_transport_rejects_ambiguous_or_unsafe_records(self) -> None:
        self.write_config(test="true")
        cases = (
            (b"unterminated", "NUL-terminated"),
            (b"first\0\0", "empty or oversized"),
            (b"/absolute\0", "unsafe path"),
            (b".\0", "unsafe path"),
            (b"nested/./path\0", "unsafe path"),
            (b"../escape\0", "unsafe path"),
            (b"duplicate\0duplicate\0", "duplicate path"),
            (b"x" * (recovery_validation.MAX_CHANGED_PATH_BYTES + 1) + b"\0", "oversized"),
        )
        for content, expected in cases:
            with self.subTest(content=content):
                self.changed.write_bytes(content)
                result = self.invoke()
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)

    def test_runner_policy_rejects_writable_ancestors_and_rechecks_identity(self) -> None:
        writable_root_metadata = type(
            "Metadata",
            (),
            {"st_mode": stat.S_IFDIR | 0o777, "st_uid": 0},
        )()
        with self.assertRaisesRegex(
            recovery_validation.RecoveryValidationError,
            "ancestor must not be group- or world-writable",
        ):
            recovery_validation._validate_protected_metadata(
                Path("/unsafe"), writable_root_metadata, directory=True
            )

        identity = (1, 2, stat.S_IFREG | 0o555, 0, 0, 10, 11, 12)
        directory_identity = (1, 3, stat.S_IFDIR | 0o555, 0, 0)
        original = recovery_validation.RunnerBinding(
            Path("/protected/runner"),
            identity,
            (("/protected", directory_identity),),
        )
        replacement = recovery_validation.RunnerBinding(
            Path("/protected/runner"),
            (1, 99, stat.S_IFREG | 0o555, 0, 0, 10, 11, 12),
            (("/protected", directory_identity),),
        )
        with mock.patch.object(
            recovery_validation,
            "_validated_runner_binding",
            return_value=replacement,
        ), self.assertRaisesRegex(
            recovery_validation.RecoveryValidationError, "identity changed"
        ):
            original.revalidate(self.repo)

        protected = recovery_validation.validate_runner("/usr/bin/env", self.repo)
        protected.revalidate(self.repo)

    def test_runner_trust_contract_matches_doctor_autonomous_and_recovery(self) -> None:
        target = self.base / "installed"
        (target / "config").mkdir(parents=True)
        team_config = target / "config" / "team.config.md"
        team_config.write_text(
            "AGENT_SANDBOX_ENFORCED=true\n"
            'AGENT_SANDBOX_RUNNER="/usr/bin/env"\n',
            encoding="utf-8",
        )

        ready, message, remediation = _sandbox_runner_readiness(
            target, self.repo
        )
        self.assertTrue(ready, message)
        self.assertIsNone(remediation)
        pm_agent.validate_agent_sandbox_runner(
            self.repo, {"AGENT_SANDBOX_RUNNER": "/usr/bin/env"}
        )
        binding = recovery_validation.validate_runner("/usr/bin/env", self.repo)
        binding.revalidate(self.repo)

        operator_runner = self.base / "operator-owned-runner"
        operator_runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        operator_runner.chmod(0o700)
        team_config.write_text(
            "AGENT_SANDBOX_ENFORCED=true\n"
            f'AGENT_SANDBOX_RUNNER="{operator_runner}"\n',
            encoding="utf-8",
        )
        ready, message, _ = _sandbox_runner_readiness(target, self.repo)
        self.assertFalse(ready)
        self.assertIn("not root-owned", message)
        with self.assertRaisesRegex(pm_agent.MonitorError, "must be root-owned"):
            pm_agent.validate_agent_sandbox_runner(
                self.repo, {"AGENT_SANDBOX_RUNNER": str(operator_runner)}
            )
        with self.assertRaisesRegex(
            recovery_validation.RecoveryValidationError, "must be root-owned"
        ):
            recovery_validation.validate_runner(str(operator_runner), self.repo)

    def test_validation_output_and_process_group_are_bounded(self) -> None:
        for stream, redirect in (("stdout", ""), ("stderr", " >&2")):
            with self.subTest(stream=stream):
                flood = self.write_script(
                    f"scripts/flood-{stream}.sh",
                    f"while :; do printf '0123456789abcdef'{redirect}; done\n",
                )
                with mock.patch.object(
                    recovery_validation, "TERMINATION_GRACE_SECONDS", 0.2
                ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ), self.assertRaisesRegex(
                    recovery_validation.RecoveryValidationError, "output exceeds"
                ):
                    recovery_validation._run_bounded(
                        [str(flood)], cwd=self.repo, timeout_seconds=5, output_limit=1024
                    )

        marker = self.repo / "orphan-wrote-after-timeout"
        sleeper = self.write_script(
            "scripts/ignore-term.sh",
            "trap '' TERM\n"
            "/usr/bin/python3 -c "
            + shlex.quote(
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "time.sleep(1); "
                f"pathlib.Path({str(marker)!r}).write_text('escaped'); "
                "time.sleep(30)"
            )
            + " &\n"
            "wait\n",
        )
        started = time.monotonic()
        with mock.patch.object(
            recovery_validation, "TERMINATION_GRACE_SECONDS", 0.2
        ), self.assertRaisesRegex(
            recovery_validation.RecoveryValidationError, "deadline"
        ):
            recovery_validation._run_bounded(
                [str(sleeper)], cwd=self.repo, timeout_seconds=0.2, output_limit=1024
            )
        self.assertLess(time.monotonic() - started, 5)
        time.sleep(1)
        self.assertFalse(marker.exists())

        orphan_marker = self.repo / "orphan-wrote-after-parent-exit"
        orphan = self.write_script(
            "scripts/exit-with-orphan.sh",
            "/usr/bin/python3 -c "
            + shlex.quote(
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "time.sleep(1); "
                f"pathlib.Path({str(orphan_marker)!r}).write_text('escaped'); "
                "time.sleep(30)"
            )
            + " </dev/null >/dev/null 2>&1 &\n"
            "exit 0\n",
        )
        with mock.patch.object(
            recovery_validation, "TERMINATION_GRACE_SECONDS", 0.2
        ), self.assertRaisesRegex(
            recovery_validation.RecoveryValidationError, "background process"
        ):
            recovery_validation._run_bounded(
                [str(orphan)], cwd=self.repo, timeout_seconds=2, output_limit=1024
            )
        time.sleep(1)
        self.assertFalse(orphan_marker.exists())

    def test_enforced_mode_uses_protected_runner_argv(self) -> None:
        log = self.base / "runner-argv.bin"
        runner = self.base / "protected-runner"
        runner.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            f": > {shlex.quote(str(log))}\n"
            f"for item in \"$@\"; do printf '%s\\0' \"$item\" >> {shlex.quote(str(log))}; done\n"
            "[ \"$1\" = --workdir ]\n"
            "workdir=$2\n"
            "[ \"$3\" = -- ]\n"
            "shift 3\n"
            "cd \"$workdir\"\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        runner.chmod(0o700)
        self.write_script(
            "scripts/runner-validation.sh",
            "printf 'runner-ok\\n' > runner-result.txt\n",
        )
        self.write_config(
            enforced="true",
            runner=str(runner),
            script="scripts/runner-validation.sh",
        )

        binding = mock.Mock()
        binding.path = runner
        config = recovery_validation.parse_config(self.config.read_bytes())
        changed = recovery_validation.changed_files(self.changed)
        with mock.patch.dict(
            os.environ,
            {"NO_COLOR": "through-runner", "SECRET_CANARY": "hidden"},
            clear=False,
        ), mock.patch.object(
            recovery_validation, "validate_runner", return_value=binding
        ):
            result = recovery_validation.run_validation(self.repo, config, changed)

        self.assertEqual(result, 0)
        binding.revalidate.assert_called_once_with(self.repo)
        argv = log.read_bytes().split(b"\0")[:-1]
        decoded = [item.decode() for item in argv]
        self.assertEqual(decoded[:5], ["--workdir", str(self.repo), "--", "/usr/bin/env", "-i"])
        self.assertIn("NO_COLOR=through-runner", decoded)
        self.assertIn("AWS_EC2_METADATA_DISABLED=true", decoded)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", decoded)
        self.assertNotIn("SECRET_CANARY=hidden", decoded)
        self.assertFalse(any(item.startswith("HOME=") for item in decoded))
        self.assertEqual(
            (self.repo / "runner-result.txt").read_text(encoding="utf-8"),
            "runner-ok\n",
        )

    def test_enforced_mode_rejects_missing_and_malformed_runners(self) -> None:
        local_runner = self.write_script("scripts/local-runner.sh", "exec \"$@\"\n")
        protected_runner = self.base / "protected-runner"
        protected_runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        protected_runner.chmod(0o500)
        symlink_runner = self.base / "symlink-runner"
        symlink_runner.symlink_to(protected_runner)
        non_executable_runner = self.base / "non-executable-runner"
        non_executable_runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        non_executable_runner.chmod(0o600)
        writable_runner = self.base / "writable-runner"
        writable_runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        writable_runner.chmod(0o722)
        cases = (
            (None, "is required"),
            ("relative-runner", "absolute path"),
            (str(local_runner), "external to the repository"),
            (str(self.base), "regular file"),
            (str(symlink_runner), "canonical absolute path"),
            (str(non_executable_runner), "must be executable"),
            (str(writable_runner), "group- or world-writable"),
            (str(protected_runner), "must be root-owned"),
        )
        for runner, expected in cases:
            with self.subTest(runner=runner):
                self.write_config(enforced="true", runner=runner, test="true")
                result = self.invoke(NO_COLOR="ok")
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)

    def test_duplicate_and_malformed_config_fail_closed(self) -> None:
        self.write_config(test="true", extra="VALIDATE_TEST=null\n")
        duplicate = self.invoke(NO_COLOR="ok")
        self.assertEqual(duplicate.returncode, 2)
        self.assertIn("duplicate configuration key VALIDATE_TEST", duplicate.stderr)

        self.config.write_text(
            "AGENT_ENV_ALLOWLIST = \"PATH NO_COLOR\"\n"
            "AGENT_SANDBOX_ENFORCED=false\n"
            "VALIDATE_TEST=true\n",
            encoding="utf-8",
        )
        malformed = self.invoke(NO_COLOR="ok")
        self.assertEqual(malformed.returncode, 2)
        self.assertIn("malformed configuration assignment", malformed.stderr)

    def test_secret_like_allowlist_names_and_empty_values_are_rejected(self) -> None:
        for name in (
            "DEPLOY_TOKEN",
            "BASH_ENV",
            "DATABASE_URL",
            "REDIS_URL",
            "SENTRY_DSN",
            "PGPASSWORD",
        ):
            with self.subTest(name=name):
                self.write_config(allowlist=f"PATH {name}", test="true")
                secret = self.invoke(**{name: "must-not-leak"})
                self.assertEqual(secret.returncode, 2)
                self.assertIn("only the recovery-safe names", secret.stderr)

        self.config.write_text(
            "AGENT_ENV_ALLOWLIST=\"PATH\"\n"
            "AGENT_SANDBOX_ENFORCED=\n"
            "VALIDATE_TEST=true\n",
            encoding="utf-8",
        )
        empty = self.invoke()
        self.assertEqual(empty.returncode, 2)
        self.assertIn("empty value", empty.stderr)


if __name__ == "__main__":
    unittest.main()
