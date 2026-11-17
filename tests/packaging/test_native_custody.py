"""Persistent-service native transport fixtures; isolated offline runner only."""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import os
from pathlib import Path
import signal
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/packaging")]

import test_native_clients as fixtures  # noqa: E402
from startup_factory_cli import docker_backend as adapter  # noqa: E402
from startup_factory_cli import native_custody as custody  # noqa: E402


class NativeCustodyTest(unittest.TestCase):
    setUp = fixtures.NativeClientsTest.setUp
    cleanup_clients = fixtures.NativeClientsTest.cleanup_clients
    journal = fixtures.NativeClientsTest.journal
    intent = fixtures.NativeClientsTest.intent
    argv = fixtures.NativeClientsTest.argv
    state = staticmethod(fixtures.NativeClientsTest.state)
    assert_closed = fixtures.NativeClientsTest.assert_closed

    def manager(self):
        result = custody.JournalCustody(self.journal())
        result.bind_reconciler(object())
        self.addCleanup(self.close_manager, result)
        return result

    @staticmethod
    def close_manager(manager):
        with contextlib.suppress(custody.CustodyError):
            manager.close()

    @staticmethod
    def permit():
        return adapter.OperationPermit(fixtures.DIGEST, fixtures.NAME, fixtures.GENERATION, 1, fixtures.DIGEST)

    def test_normal_control_is_gated_acknowledged_and_never_qualification(self):
        manager = self.manager()
        result = manager.run_control(self.profile, self.permit(), self.argv(), timeout_seconds=2,
                                     max_stdout_bytes=4096, max_stderr_bytes=4096)
        self.assertEqual((result.returncode, result.stdout), (0, b"executed\n"))
        record = manager.journal.records()[0]
        self.assertEqual(record["state"], "completed-acknowledged")
        self.assertEqual(record["intent"]["generation"], fixtures.GENERATION)
        self.assertEqual(record["intent"]["requestDigest"], fixtures.DIGEST)
        diagnostic = manager.diagnostics()
        self.assertEqual(diagnostic["activeClients"], 0)
        for name in ("poolBlocked", "lateCommandsQuiescent", "qualified", "autonomousReady"):
            self.assertFalse(diagnostic[name])

    def test_cancelled_generation_is_durable_uncertain_and_blocks_new_exec(self):
        manager = self.manager()
        process = manager.open_process(self.profile, self.permit(), self.argv("stop"), timeout_seconds=2)
        self.assertEqual(process.stdout.readline(), b"started\n")
        manager.cancel_generation(fixtures.NAME, fixtures.GENERATION, 1)
        self.assert_closed(process._handle)
        self.assertTrue(manager.pool_blocked)
        record = manager.journal.records()[0]
        self.assertEqual(record["state"], "delivery-uncertain")
        with self.assertRaises(custody.CustodyError):
            manager.open_process(self.profile, self.permit(), self.argv("open-session"), timeout_seconds=2)
        reopened = custody.JournalCustody(self.journal())
        self.addCleanup(self.close_manager, reopened)
        self.assertTrue(reopened.pool_blocked)

    def test_service_wall_timer_reaps_without_launcher_activity(self):
        manager = self.manager()
        process = manager.open_process(self.profile, self.permit(), self.argv("stop"), timeout_seconds=.3)
        deadline = time.monotonic() + 2
        while process.returncode is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertIsNotNone(process.returncode)
        self.assertTrue(manager.pool_blocked)
        self.assertEqual(manager.journal.records()[0]["state"], "delivery-uncertain")

    def test_generation_cancel_does_not_touch_other_epoch_and_survives_profile_failure(self):
        manager = self.manager()
        process = manager.open_process(self.profile, self.permit(), self.argv("stop"), timeout_seconds=2)
        manager.cancel_generation(fixtures.NAME, fixtures.GENERATION, 2)
        self.assertIsNone(process.returncode)
        manager.journal._poisoned = True
        with self.assertRaises(custody.CustodyError):
            manager.cancel_generation(fixtures.NAME, fixtures.GENERATION, 1)
        self.assert_closed(process._handle)
        self.assertTrue(manager.pool_blocked)

    def test_missing_authority_wrong_namespace_and_profile_never_spawn(self):
        manager = custody.JournalCustody(self.journal())
        self.addCleanup(self.close_manager, manager)
        with mock.patch.object(manager.journal, "spawn") as spawn:
            with self.assertRaises(custody.CustodyError):
                manager.open_process(self.profile, self.permit(), self.argv(), timeout_seconds=2)
            manager.bind_reconciler(object())
            wrong = self.argv()[:2] + ("sf-other",) + self.argv()[3:]
            with self.assertRaises(custody.CustodyError):
                manager.open_process(self.profile, self.permit(), wrong, timeout_seconds=2)
            altered = dataclasses.replace(self.profile, namespace="sf-other")
            with self.assertRaises(custody.CustodyError):
                manager.open_process(altered, self.permit(), self.argv(), timeout_seconds=2)
            spawn.assert_not_called()

    def test_native_session_finish_and_cancel_are_distinct(self):
        manager = self.manager()
        process = manager.open_process(self.profile, self.permit(), self.argv(), timeout_seconds=2)
        session = adapter.NativeSession(process, timeout=2, output_limit=4096, lease=contextlib.ExitStack())
        self.addCleanup(session.close)
        self.assertEqual(session.stdout.read(), b"executed\n")
        self.assertEqual(session.stderr.read(), b"")
        self.assertEqual(session.finish(), 0)
        self.assertEqual(manager.journal.records()[0]["state"], "completed-acknowledged")
        self.assertFalse(manager.pool_blocked)
        self.assertEqual(session.finish(), 0)

    def test_session_input_budget_is_separate_and_finish_requires_real_eof(self):
        manager = self.manager()
        process = manager.open_process(self.profile, self.permit(), self.argv("open-session"), timeout_seconds=2)
        session = adapter.NativeSession(process, timeout=2, output_limit=64, input_limit=5,
                                        lease=contextlib.ExitStack())
        self.addCleanup(session.close)
        with self.assertRaisesRegex(adapter.DockerBackendError, "drain both"):
            session.finish()
        session.stdin.write(b"a\0\xffb\n")
        session.stdin.close()
        self.assertEqual(session.stdout.read(), b"a\0\xffb\n")
        self.assertEqual(session.stderr.read(), b"fixture-stderr")
        self.assertEqual(session.finish(), 7)
        self.assertFalse(manager.pool_blocked)

    def test_custody_process_never_allows_external_poll_wait_or_forked_cleanup(self):
        manager = self.manager()
        process = manager.open_process(self.profile, self.permit(), self.argv("stop"), timeout_seconds=2)
        for action in (process.poll, process.wait):
            with self.assertRaises(custody.CustodyError):
                action()
        with mock.patch.object(custody.os, "getpid", return_value=os.getpid() + 1), mock.patch.object(custody.os, "killpg") as kill:
            with self.assertRaises(custody.CustodyError):
                process._cancel_owned()
            kill.assert_not_called()
        process._cancel_owned()

    def test_real_transport_without_custody_is_refused_after_external_permit(self):
        @contextlib.contextmanager
        def permit(profile, request):
            yield adapter.OperationPermit(request.digest, None, fixtures.GENERATION, 1, fixtures.DIGEST)
        backend = adapter.DockerBackend(self.profile_path, permit=permit)
        with mock.patch.object(backend, "_profile", return_value=self.profile), mock.patch.object(adapter, "_spawn") as spawn:
            with self.assertRaisesRegex(adapter.DockerBackendError, "persistent service"):
                backend.probe(self.profile)
            spawn.assert_not_called()

    def test_current_authority_is_rechecked_after_prepare_before_any_exec(self):
        manager = custody.JournalCustody(self.journal())
        self.addCleanup(self.close_manager, manager)
        authority = SimpleNamespace(authorize_native=mock.Mock(side_effect=(True, False)))
        manager.bind_reconciler(authority)
        with self.assertRaisesRegex(custody.CustodyError, "before gated release"):
            manager.open_process(self.profile, self.permit(), self.argv(), timeout_seconds=2)
        self.assertEqual(authority.authorize_native.call_count, 2)
        self.assertFalse(self.execution_marker.exists())
        self.assertEqual(manager.journal.records()[0]["state"], "aborted-before-release")

    def test_scoped_credential_stdin_and_echo_never_enter_journal_or_hashes(self):
        secret = bytearray(b"dummy-only-openai-fixture-credential")
        self.sbx.write_text("#!" + str(Path(sys.executable).resolve()) + "\nimport sys\nraw=sys.stdin.buffer.read(16385)\nsys.stdout.buffer.write(raw)\nsys.stderr.buffer.write(raw)\n")
        self.profile = dataclasses.replace(self.profile, sbx_sha256=fixtures.pin(self.sbx).sha256)
        with mock.patch.object(fixtures.native, "load_profile", return_value=self.profile):
            manager = self.manager()
            result = manager.run_credential(self.profile, self.permit(), operation="credential-set", secret=secret)
            self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")
            record = manager.journal.records()[0]
            self.assertEqual(record["intent"]["operation"], "credential-set")
            self.assertEqual(record["responseDigest"], fixtures.native.canonical_digest({
                "returncode": 0, "operation": "credential-set", "requestDigest": fixtures.DIGEST}))
            for path in self.path.iterdir():
                raw = path.read_bytes()
                self.assertNotIn(bytes(secret), raw)
                self.assertNotIn(hashlib.sha256(secret).hexdigest().encode(), raw)
            manager.run_credential(self.profile, self.permit(), operation="credential-remove")
            self.assertFalse(manager.pool_blocked)

    def test_credential_services_and_input_shape_are_closed_before_launch(self):
        manager = self.manager()
        with mock.patch.object(manager, "open_process") as launch:
            for kwargs in ({"service": "github", "secret": b"dummy"}, {"service": "anthropic", "secret": b"dummy"},
                           {"secret": b"x" * 16385}, {"secret": b""}, {"secret": {"token": "dummy"}}):
                with self.subTest(kwargs=str(kwargs)[:80]), self.assertRaises(custody.CustodyError):
                    manager.run_credential(self.profile, self.permit(), operation="credential-set", **kwargs)
            with self.assertRaises(custody.CustodyError):
                manager.run_credential(self.profile, self.permit(), operation="credential-remove", secret=b"dummy")
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
