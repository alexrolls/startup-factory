from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pwd
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import sandbox_exec_probe as probe  # noqa: E402


SANDBOX = "sf-probe-fixture"
IDENTITY = "d9f44bce-019d-43c3-b8c2-dcf7ac05258b"
CREATED = "2026-11-16T23:52:57+01:00"


def metadata(**overrides: object) -> bytes:
    value = {
        "id": IDENTITY, "name": SANDBOX, "created_at": CREATED,
        "created_version": "v0.54.0", "daemon_version": "v0.54.0",
        "host_mounts": [], "runtime_mounts": [], "mcp_mode": "static",
        "mcp_servers": [], "state": "stopped", "cpus": 2, "memory": 4096,
        "image_digest": "sha256:" + "1" * 64,
    }
    value.update(overrides)
    return json.dumps(value, separators=(",", ":")).encode()


def encode_frame(value: dict) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return struct.pack("!I", len(raw)) + raw


def decode_frames(raw: bytes) -> list[dict]:
    frames = []
    while raw:
        size = struct.unpack("!I", raw[:4])[0]
        frames.append(json.loads(raw[4:4 + size]))
        raw = raw[4 + size:]
    return frames


class FakeRunner:
    """Returns fixture protocol bytes without importing or executing the fixture."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.inspect_outputs: list[bytes] = []
        self.copy_status = 0
        self.transform_exec = lambda value: value

    def __call__(self, argv: list[str], **kwargs: object) -> probe.CommandResult:
        self.calls.append((list(argv), dict(kwargs)))
        operation = argv[4]
        if operation == "inspect":
            output = self.inspect_outputs.pop(0) if self.inspect_outputs else metadata()
            return probe.CommandResult(0, output)
        if operation == "cp":
            return probe.CommandResult(self.copy_status)
        if operation == "exec":
            frames = decode_frames(kwargs["input_data"])
            response = b"".join(encode_frame({**frame, "fixtureVersion": 1}) for frame in frames)
            return self.transform_exec(probe.CommandResult(7, response, b"SF_QUALIFICATION_STDERR\n"))
        raise AssertionError("unexpected command operation")


class SandboxExecProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-exec-probe-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.runtime = Path(self.temporary.name).resolve() / "sbx"
        # This is only a hash/permission fixture. All command execution is fake.
        self.runtime.write_bytes(b"not an executable program; never execute this fixture\n")
        self.runtime.chmod(0o755)
        self.digest = hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        self.runner = FakeRunner()

    def run_probe(self, **overrides: object) -> probe.ExecProbeReport:
        arguments = {
            "sbx_path": self.runtime, "expected_sha256": self.digest,
            "sandbox": SANDBOX, "expected_id": IDENTITY,
            "expected_created_at": CREATED, "runner": self.runner,
        }
        arguments.update(overrides)
        return probe.run_probe(**arguments)

    def test_fixed_command_order_scope_protocol_and_bounds(self) -> None:
        with (
            mock.patch("subprocess.Popen", side_effect=AssertionError("real process")),
            mock.patch("subprocess.run", side_effect=AssertionError("real process")),
        ):
            report = self.run_probe().as_dict()
        self.assertTrue(report["passed"])
        self.assertEqual(report["scope"], "exec-channel-only")
        for field in (
            "qualified", "autonomousReady", "productionBackendAllowed", "identityAtomic",
            "containmentVerified", "cleanupPerformed",
        ):
            self.assertIs(report[field], False, field)
        self.assertIs(report["operatorOnly"], True)
        self.assertEqual(report["observations"]["binaryEchoBytes"], 16384)
        self.assertEqual(report["observations"]["exitStatus"], 7)
        self.assertIn("not atomically bound", " ".join(report["limitations"]))
        self.assertEqual([args[4] for args, _ in self.runner.calls], ["inspect", "cp", "inspect", "exec", "inspect"])
        for args, options in self.runner.calls:
            self.assertEqual(args[:4], [str(self.runtime), "--app-name", "sf-qualification", "--no-input"])
            self.assertGreater(options["timeout_seconds"], 0)
            self.assertLessEqual(options["timeout_seconds"], 15)
            self.assertGreater(options["max_stdout_bytes"], 0)
            self.assertEqual(options["max_stderr_bytes"], 16384)
            self.assertNotIn("shell", options)
        self.assertEqual(self.runner.calls[0][0][4:], ["inspect", SANDBOX, "--format", "json"])
        self.assertEqual(
            self.runner.calls[1][0][4:],
            ["cp", str(ROOT / "bin/sandbox_qualification_fixture.py"), f"{SANDBOX}:/tmp/sf_qualification_fixture.py"],
        )
        exec_args, exec_options = self.runner.calls[3]
        self.assertEqual(
            exec_args[4:],
            ["exec", "-i", "--user", "root", SANDBOX, "/usr/bin/python3", "-I", "-B",
             "/tmp/sf_qualification_fixture.py", "--frame-timeout", "3"],
        )
        self.assertNotIn("-t", exec_args)
        self.assertNotIn("--tty", exec_args)
        requests = decode_frames(exec_options["input_data"])
        self.assertEqual([frame["operation"] for frame in requests], ["ping", "echo", "stderr", "exit"])
        self.assertEqual(bytes.fromhex(requests[1]["payloadHex"]), bytes(range(256)) * 64)
        self.assertEqual(requests[3]["payloadHex"], "07")
        self.assertTrue(all(set(frame) == {"schemaVersion", "id", "operation", "payloadHex"} for frame in requests))

    def test_environment_uses_account_home_and_no_ambient_credentials_or_endpoints(self) -> None:
        with mock.patch.dict(os.environ, {
            "HOME": "/wrong-home", "AWS_ACCESS_KEY_ID": "fixture-key",
            "GH_TOKEN": "fixture-token", "DOCKER_HOST": "unix:///wrong.sock",
            "SBX_APP_NAME": "personal", "SSH_AUTH_SOCK": "/wrong-agent.sock",
        }):
            self.run_probe()
        for _args, options in self.runner.calls:
            environment = options["env"]
            self.assertEqual(environment["HOME"], pwd.getpwuid(os.geteuid()).pw_dir)
            self.assertEqual(set(environment), {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "NO_COLOR"})
            self.assertEqual(environment["PATH"], "/usr/bin:/bin")

    def test_expected_digest_is_required_and_checked_before_any_command(self) -> None:
        for digest in ("", "A" * 64, "0" * 64):
            with self.subTest(digest=digest), self.assertRaises(probe.ExecProbeError):
                self.run_probe(expected_sha256=digest)
        self.assertEqual(self.runner.calls, [])

    def test_large_runtime_hash_uses_bounded_reads_without_retaining_binary(self) -> None:
        size = 8 * 1024 * 1024
        with self.runtime.open("wb") as output:
            output.truncate(size)
        expected = hashlib.sha256(b"\0" * size).hexdigest()
        requested_sizes = []
        original_read = os.read

        def observe_read(descriptor: int, maximum: int) -> bytes:
            requested_sizes.append(maximum)
            return original_read(descriptor, maximum)

        tracemalloc.start()
        try:
            with mock.patch.object(probe.os, "read", side_effect=observe_read):
                observed, _identity = probe._runtime_fingerprint(self.runtime)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(observed, expected)
        self.assertGreater(len(requested_sizes), 1)
        self.assertLessEqual(max(requested_sizes), 64 * 1024)
        # Retaining chunks or joining the native binary would exceed this by
        # several MiB. The streaming hash needs only bounded read buffers.
        self.assertLess(peak, 2 * 1024 * 1024)

    def test_relative_symlink_or_nonexecutable_runtime_is_rejected(self) -> None:
        alias = self.runtime.parent / "alias"
        alias.symlink_to(self.runtime)
        for path in (Path("relative/sbx"), alias):
            with self.subTest(path=path), self.assertRaises(probe.ExecProbeError):
                self.run_probe(sbx_path=path)
        self.runtime.chmod(0o600)
        with self.assertRaises(probe.ExecProbeError):
            self.run_probe()
        self.assertEqual(self.runner.calls, [])

    def test_invalid_expected_identity_or_timestamp_is_rejected_before_commands(self) -> None:
        for fields in (
            {"expected_id": IDENTITY.upper()}, {"expected_id": "not-a-uuid"},
            {"expected_created_at": "2026-11-16T23:52:57"},
            {"expected_created_at": "2026-02-30T23:52:57Z"},
            {"sandbox": "--all"}, {"sandbox": "name:/tmp/other"},
        ):
            with self.subTest(fields=fields), self.assertRaises(probe.ExecProbeError):
                self.run_probe(**fields)
        self.assertEqual(self.runner.calls, [])

    def test_metadata_identity_and_creation_must_both_match(self) -> None:
        for fields in (
            {"id": "11111111-1111-4111-8111-111111111111"},
            {"created_at": "2026-11-16T22:52:57Z"},
            {"name": "another-sandbox"},
        ):
            with self.subTest(fields=fields):
                self.runner = FakeRunner()
                self.runner.inspect_outputs = [metadata(**fields)]
                with self.assertRaises(probe.ExecProbeError):
                    self.run_probe()
                self.assertEqual(len(self.runner.calls), 1)

    def test_mounts_and_mcp_restrictions_fail_closed(self) -> None:
        for fields in (
            {"host_mounts": [{"source": "/fixture"}]}, {"host_mounts": {}},
            {"runtime_mounts": ["/fixture"]}, {"runtime_mounts": None},
            {"mcp_mode": "dynamic"}, {"mcp_servers": ["fixture-server"]},
            {"mcp_servers": {}},
        ):
            with self.subTest(fields=fields):
                self.runner = FakeRunner()
                self.runner.inspect_outputs = [metadata(**fields)]
                with self.assertRaises(probe.ExecProbeError):
                    self.run_probe()
                self.assertEqual(len(self.runner.calls), 1)

    def test_unknown_versions_schema_and_states_are_rejected(self) -> None:
        missing = json.loads(metadata())
        del missing["id"]
        for raw in (
            metadata(created_version="0.54.0"), metadata(daemon_version="v0.55.0"),
            metadata(state="unknown"), metadata(future_field=True),
            json.dumps(missing).encode(), b"[]",
        ):
            with self.subTest(raw=raw[:80]):
                self.runner = FakeRunner()
                self.runner.inspect_outputs = [raw]
                with self.assertRaises(probe.ExecProbeError):
                    self.run_probe()
                self.assertEqual(len(self.runner.calls), 1)

    def test_observed_running_uptime_is_informational_not_identity(self) -> None:
        self.runner.inspect_outputs = [
            metadata(), metadata(state="running", uptime="1s"), metadata(),
        ]
        report = self.run_probe().as_dict()
        self.assertTrue(report["passed"])
        self.assertEqual(report["observedStates"], ["stopped", "running", "stopped"])
        self.assertNotIn("uptime", report)
        self.assertFalse(report["identityAtomic"])
        self.assertFalse(report["qualified"])

    def test_duplicate_nonfinite_invalid_and_deep_json_are_rejected(self) -> None:
        for raw in (
            metadata()[:-1] + b',"id":"duplicate"}',
            metadata(cpus=float("nan")), metadata(cpus=float("inf")),
            metadata()[:-1] + b',"cpus":1e999}',
            b'\xff', b'{"id":',
            metadata()[:-1] + b',"network":' + b'[' * 17 + b'0' + b']' * 17 + b'}',
        ):
            with self.subTest(raw=raw[:80]):
                self.runner = FakeRunner()
                self.runner.inspect_outputs = [raw]
                with self.assertRaises(probe.ExecProbeError):
                    self.run_probe()

    def test_failed_copy_prevents_exec(self) -> None:
        self.runner.copy_status = 1
        with self.assertRaisesRegex(probe.ExecProbeError, "copy failed"):
            self.run_probe()
        self.assertEqual([args[4] for args, _ in self.runner.calls], ["inspect", "cp"])

    def test_post_copy_identity_change_prevents_exec(self) -> None:
        self.runner.inspect_outputs = [metadata(), metadata(created_at="2026-11-17T00:00:00Z")]
        with self.assertRaises(probe.ExecProbeError):
            self.run_probe()
        self.assertEqual([args[4] for args, _ in self.runner.calls], ["inspect", "cp", "inspect"])

    def test_final_identity_change_cannot_report_success(self) -> None:
        self.runner.inspect_outputs = [metadata(), metadata(), metadata(id="11111111-1111-4111-8111-111111111111")]
        with self.assertRaises(probe.ExecProbeError):
            self.run_probe()
        self.assertEqual(len(self.runner.calls), 5)

    def test_wrong_exit_stderr_echo_frames_or_extra_output_are_rejected(self) -> None:
        def changed_frame(result: probe.CommandResult) -> probe.CommandResult:
            frames = decode_frames(result.stdout)
            frames[1]["payloadHex"] = "00"
            return probe.CommandResult(7, b"".join(encode_frame(frame) for frame in frames), result.stderr)

        for transform in (
            lambda result: probe.CommandResult(0, result.stdout, result.stderr),
            lambda result: probe.CommandResult(7, result.stdout, b""),
            lambda result: probe.CommandResult(7, result.stdout, result.stderr * 2),
            lambda result: probe.CommandResult(7, result.stdout + result.stderr, b""),
            lambda result: probe.CommandResult(7, result.stdout[:-1], result.stderr),
            lambda result: probe.CommandResult(7, result.stdout + b"extra", result.stderr),
            lambda result: probe.CommandResult(7, b"\0\0\0\0" + result.stdout, result.stderr),
            lambda result: probe.CommandResult(7, b"\xff\xff\xff\xff" + result.stdout, result.stderr),
            changed_frame,
        ):
            with self.subTest(transform=transform):
                self.runner = FakeRunner()
                self.runner.transform_exec = transform
                with self.assertRaises(probe.ExecProbeError):
                    self.run_probe()
                self.assertEqual(len(self.runner.calls), 4)

    def test_extra_bounded_cli_stderr_diagnostics_remain_opaque_data(self) -> None:
        diagnostic = b"sandbox fixture started\n\x1b[31mnot-control\x1b[0m\n"
        self.runner.transform_exec = lambda result: probe.CommandResult(
            7, result.stdout, diagnostic + result.stderr
        )
        report = self.run_probe().as_dict()
        self.assertTrue(report["passed"])
        self.assertEqual(report["observations"]["extraDiagnosticBytes"], len(diagnostic))
        self.assertNotIn("not-control", json.dumps(report))

    def test_duplicate_or_nonfinite_response_json_is_rejected(self) -> None:
        for raw in (
            b'{"schemaVersion":1,"schemaVersion":1}',
            b'{"schemaVersion":NaN}', b'{"schemaVersion":1e999}',
        ):
            with self.subTest(raw=raw):
                self.runner = FakeRunner()
                self.runner.transform_exec = lambda _result: probe.CommandResult(
                    7, struct.pack("!I", len(raw)) + raw, b"SF_QUALIFICATION_STDERR\n"
                )
                with self.assertRaises(probe.ExecProbeError):
                    self.run_probe()

    def test_oversized_injected_output_cannot_bypass_runner_bounds(self) -> None:
        for stdout, stderr in (
            (b"x" * (probe.MAX_INSPECT_BYTES + 1), b""),
            (metadata(), b"x" * (probe.MAX_COMMAND_OUTPUT_BYTES + 1)),
        ):
            with self.subTest(stdout=len(stdout), stderr=len(stderr)):
                runner = mock.Mock(return_value=probe.CommandResult(0, stdout, stderr))
                with self.assertRaises(probe.ExecProbeError):
                    self.run_probe(runner=runner)
                self.assertEqual(runner.call_count, 1)

    def test_runner_timeout_prevents_further_commands(self) -> None:
        for error in (TimeoutError(), subprocess.TimeoutExpired("fixture", 5)):
            runner = mock.Mock(side_effect=error)
            with self.subTest(error=error), self.assertRaises(probe.ExecProbeError):
                self.run_probe(runner=runner)
            self.assertEqual(runner.call_count, 1)

    def test_command_and_total_deadlines_are_checked_with_injected_runner(self) -> None:
        for elapsed in (6.0, probe.TOTAL_TIMEOUT_SECONDS + 1):
            clock = [0.0]

            def delayed(argv: list[str], **kwargs: object) -> probe.CommandResult:
                clock[0] += elapsed
                return probe.CommandResult(0, metadata())

            with (
                self.subTest(elapsed=elapsed),
                mock.patch.object(probe.time, "monotonic", side_effect=lambda: clock[0]),
                self.assertRaisesRegex(probe.ExecProbeError, "deadline"),
            ):
                self.run_probe(runner=delayed)

    def test_changed_pinned_runtime_during_inspect_prevents_copy(self) -> None:
        def replacing(argv: list[str], **kwargs: object) -> probe.CommandResult:
            self.runtime.write_bytes(b"changed binary fixture")
            return self.runner(argv, **kwargs)

        with self.assertRaisesRegex(probe.ExecProbeError, "changed"):
            self.run_probe(runner=replacing)
        self.assertEqual(len(self.runner.calls), 1)

    def test_wrapper_requires_explicit_namespace_and_has_no_arbitrary_command_options(self) -> None:
        base = [
            "--sbx", str(self.runtime), "--sbx-sha256", self.digest,
            "--sandbox", SANDBOX, "--expected-id", IDENTITY,
            "--expected-created-at", CREATED,
        ]
        for extra in ([], ["--app-name", "personal"], ["--app-name", "sf-qualification", "--command", "sh"]):
            with self.subTest(extra=extra):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    probe.main([*base, *extra])
                self.assertEqual(raised.exception.code, 2)

    def test_json_failure_report_never_claims_qualification(self) -> None:
        stdout = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            mock.patch.object(probe, "run_probe", side_effect=probe.ExecProbeError("fixture denied")),
        ):
            status = probe.main([
                "--sbx", str(self.runtime), "--sbx-sha256", self.digest,
                "--app-name", "sf-qualification", "--sandbox", SANDBOX,
                "--expected-id", IDENTITY, "--expected-created-at", CREATED, "--json",
            ])
        self.assertEqual(status, 1)
        report = json.loads(stdout.getvalue())
        self.assertFalse(report["ok"])
        self.assertFalse(report["qualified"])
        self.assertFalse(report["autonomousReady"])
        self.assertEqual(report["scope"], "exec-channel-only")


@unittest.skipUnless(hasattr(signal, "setitimer"), "requires bounded POSIX child-process tests")
class BoundedCommandRunnerTest(unittest.TestCase):
    @contextlib.contextmanager
    def captured_children(self, *, pass_fds: tuple[int, ...] = (), after_launch=None):
        """An independent timer also bounds regressions in selector/wait logic."""
        original_popen = subprocess.Popen
        children = []

        def launch(*args: object, **kwargs: object):
            self.assertIs(kwargs.get("start_new_session"), True)
            self.assertIs(kwargs.get("shell"), False)
            if pass_fds:
                kwargs["pass_fds"] = pass_fds
            child = original_popen(*args, **kwargs)
            children.append(child)
            if after_launch is not None:
                after_launch(child)
            return child

        def expired(_signum: int, _frame: object) -> None:
            raise AssertionError("bounded command test exceeded its five-second outer deadline")

        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        started = time.monotonic()
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            with mock.patch.object(probe.subprocess, "Popen", side_effect=launch):
                yield children
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            if previous_timer[0]:
                signal.setitimer(
                    signal.ITIMER_REAL,
                    max(0.001, previous_timer[0] - (time.monotonic() - started)),
                    previous_timer[1],
                )
            # Record state before backup cleanup, so the test cannot pass just
            # because its own cleanup hid a runner reaping/pipe-close defect.
            observations = [
                (child.returncode, all(stream is not None and stream.closed for stream in
                                       (child.stdin, child.stdout, child.stderr)))
                for child in children
            ]
            for child in children:
                if child.returncode is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=1)
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()
            self.assertEqual(len(children), 1)
            for returncode, closed in observations:
                self.assertIsNotNone(returncode, "runner did not reap its own child")
                self.assertTrue(closed, "runner did not close all command pipes")

    def command(self, script: str, *, payload: bytes = b"", stdout_limit: int = 262144,
                stderr_limit: int = 262144) -> probe.CommandResult:
        return probe._run_bounded(
            [sys.executable, "-I", "-c", script], input_data=payload,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout_seconds=0.2, max_stdout_bytes=stdout_limit,
            max_stderr_bytes=stderr_limit,
        )

    def test_simultaneous_input_stdout_stderr_and_exit_seven(self) -> None:
        payload = bytes(range(256)) * 256
        script = (
            "import os,sys\n"
            "while True:\n"
            "    chunk=os.read(0,4096)\n"
            "    if not chunk: break\n"
            "    os.write(1,chunk)\n"
            "    os.write(2,b'!'*len(chunk))\n"
            "sys.exit(7)\n"
        )
        with self.captured_children() as children:
            result = self.command(script, payload=payload)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(result.stderr, b"!" * len(payload))
        self.assertEqual(children[0].returncode, 7)

    def test_stdout_overrun_kills_and_reaps_only_the_command_child(self) -> None:
        with self.captured_children() as children:
            with self.assertRaisesRegex(probe.ExecProbeError, "output byte limit"):
                self.command("import os,time;os.write(1,b'x'*65536);time.sleep(10)", stdout_limit=1024)
        self.assertEqual(children[0].returncode, -signal.SIGKILL)

    def test_stdin_pipe_pressure_still_reaches_deadline_and_reaps_child(self) -> None:
        with self.captured_children() as children:
            with self.assertRaisesRegex(probe.ExecProbeError, "deadline"):
                self.command("import time;time.sleep(10)", payload=b"x" * (2 * 1024 * 1024))
        self.assertEqual(children[0].returncode, -signal.SIGKILL)

    def test_closed_pipes_with_live_child_are_bounded_by_wait_deadline(self) -> None:
        with self.captured_children() as children:
            with self.assertRaisesRegex(probe.ExecProbeError, "deadline"):
                self.command("import os,time;[os.close(fd) for fd in (0,1,2)];time.sleep(10)")
        self.assertEqual(children[0].returncode, -signal.SIGKILL)

    @unittest.skipUnless(
        all(hasattr(os, name) for name in ("fork", "waitid", "WNOWAIT", "pidfd_open"))
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux stable, non-reaping child observation",
    )
    def test_exited_leader_reserves_group_until_descendant_holding_pipes_is_killed(self) -> None:
        read_end, write_end = os.pipe()
        descendant_handles = []
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)
        original_killpg = os.killpg
        observed_leader = []
        script = (
            "import os,time\n"
            "descendant=os.fork()\n"
            "if descendant == 0:\n"
            "    time.sleep(10)\n"
            "    os._exit(0)\n"
            f"os.write({write_end},str(descendant).encode('ascii'))\n"
            "os._exit(0)\n"
        )
        def pin_owned_descendant(_child) -> None:
            readable, _, _ = select.select([read_end], [], [], 0.5)
            self.assertTrue(readable, "fixture did not report its own descendant")
            descendant = int(os.read(read_end, 64))
            descendant_handles.append(os.pidfd_open(descendant, 0))

        try:
            with self.captured_children(pass_fds=(write_end,), after_launch=pin_owned_descendant) as children:
                def kill_owned_group(group: int, signum: int) -> None:
                    self.assertEqual(group, children[0].pid)
                    self.assertEqual(signum, signal.SIGKILL)
                    # WNOWAIT proves the dead leader remains our unreaped child;
                    # calling poll first would consume this PID reservation.
                    leader = os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    self.assertIsNotNone(leader)
                    self.assertEqual(leader.si_pid, group)
                    self.assertEqual(leader.si_status, 0)
                    observed_leader.append(leader.si_pid)
                    original_killpg(group, signum)

                with mock.patch.object(probe.os, "killpg", side_effect=kill_owned_group):
                    with self.assertRaisesRegex(probe.ExecProbeError, "deadline"):
                        self.command(script)
                self.assertEqual(observed_leader, [children[0].pid])
                self.assertEqual(children[0].returncode, 0)
                self.assertEqual(len(descendant_handles), 1)
                readable, _, _ = select.select(descendant_handles, [], [], 0.5)
                self.assertEqual(readable, descendant_handles, "owned descendant survived group cleanup")
        finally:
            for handle in descendant_handles:
                # Even a regression that reaps the leader too early cannot
                # leave this test's known descendant alive. Its pidfd prevents
                # signalling an unrelated process after numeric PID reuse.
                if not select.select([handle], [], [], 0)[0]:
                    try:
                        signal.pidfd_send_signal(handle, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                os.close(handle)

    def test_external_sigchld_reaping_is_rejected_before_launch(self) -> None:
        for handler in (signal.SIG_IGN, lambda _signal, _frame: None):
            with (
                self.subTest(handler=handler),
                mock.patch.object(probe.signal, "getsignal", return_value=handler),
                mock.patch.object(probe.subprocess, "Popen") as launch,
                self.assertRaisesRegex(probe.ExecProbeError, "SIGCHLD"),
            ):
                self.command("import sys;sys.exit(0)")
            launch.assert_not_called()

    def test_multiple_parent_threads_are_rejected_before_launch(self) -> None:
        with (
            mock.patch.object(probe.threading, "active_count", return_value=2),
            mock.patch.object(probe.subprocess, "Popen") as launch,
            self.assertRaisesRegex(probe.ExecProbeError, "single-threaded"),
        ):
            self.command("import sys;sys.exit(0)")
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
