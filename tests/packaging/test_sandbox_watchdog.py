"""Real private ledger/RPC fixtures, only in the bounded offline runner."""
from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/packaging")]
import test_native_clients as fixtures
from startup_factory_cli import sandbox_watchdog as watchdog
from startup_factory_cli.execution_backend import BackendIdentity
from startup_factory_cli.sandbox_controller import GenerationHandle


class WatchdogTest(unittest.TestCase):
    setUp = fixtures.NativeClientsTest.setUp
    cleanup_clients = fixtures.NativeClientsTest.cleanup_clients

    def prepare(self):
        root = self.scratch / "watchdog"
        root.mkdir(mode=0o700)
        self.identity = "linux:fixture-boot:1234"
        self.deployment = SimpleNamespace(
            watchdog_root=str(root), namespace=self.profile.namespace, digest="sha256:" + "d" * 64,
            profile_path=str(self.profile_path), controller_uid=os.geteuid(), source_path=self.scratch / "deployment.json",
            watchdog_socket_path=str(root / "w.sock"),
            programs={"lifecycleHelper": self.tools.lifecycle_helper.as_dict()},
        )
        for target, value in (("load_deployment", self.deployment), ("load_profile", self.profile),
                              ("_identity_helper", SimpleNamespace(process_identity=lambda pid: self.identity if pid == 424242 else None))):
            patch = mock.patch.object(watchdog, target, return_value=value)
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(watchdog.os, "getpid", return_value=424242)
        patch.start(); self.addCleanup(patch.stop)
        self.ledger = watchdog.WatchdogLedger(self.deployment, self.profile, self.identity)
        self.addCleanup(self.ledger.close)
        self.daemon = object.__new__(watchdog.WatchdogDaemon)
        self.daemon.deployment, self.daemon.profile, self.daemon.ledger = self.deployment, self.profile, self.ledger
        self.daemon.enrollment = SimpleNamespace(expires_at=int(time.time()) + 60)
        self.daemon._stop = threading.Event()
        self.daemon._sessions = {}
        self.daemon._session_lock = threading.RLock()
        self.daemon._active_connections = 0
        self.daemon._cleanup_started = set()
        self.daemon._cleanup_lock = threading.RLock()
        self.daemon._cleanup_inflight = 0
        self.daemon._fence_registry = mock.Mock()
        self.handle = GenerationHandle(fixtures.NAME, fixtures.GENERATION, 1)
        self.service = "a" * 32

    def arm(self):
        self.deadline = int(time.time()) + 10
        result = self.daemon._dispatch(self.service, "arm", {"handle": self.handle.as_dict(), "deadline": self.deadline})
        self.lease = result["leaseId"]
        self.daemon._dispatch(self.service, "bind", {"handle": self.handle.as_dict(), "identity": BackendIdentity(
            self.handle.name, "d9f44bce-019d-43c3-b8c2-dcf7ac05258b", "2026-11-17T01:00:00Z").as_dict()})

    def verify(self, **changes):
        values = dict(name=self.handle.name, generation=self.handle.generation, epoch=self.handle.epoch,
                      lease_id=self.lease, deadline=self.deadline)
        values.update(changes)
        return watchdog.verify_watchdog_lease(self.deployment.source_path, **values)

    def test_fresh_binding_verification_is_read_only_without_namespace_flock(self):
        self.prepare(); self.arm()
        before = sorted((path.name, path.stat().st_ino, path.read_bytes()) for path in Path(self.deployment.watchdog_root).iterdir())
        with mock.patch.object(watchdog.SandboxRegistry, "locked", side_effect=AssertionError("verifier must not acquire a namespace lock")), mock.patch.object(watchdog.os, "killpg") as kill:
            self.assertTrue(self.verify())
            kill.assert_not_called()
        after = sorted((path.name, path.stat().st_ino, path.read_bytes()) for path in Path(self.deployment.watchdog_root).iterdir())
        self.assertEqual(before, after)

    def test_revocation_is_durable_before_any_registry_fence(self):
        self.prepare(); self.arm()
        self.daemon._dispatch(self.service, "fence", {"handle": self.handle.as_dict()})
        self.daemon._fence_registry.assert_not_called()
        self.assertFalse(self.verify())
        self.assertEqual(self.ledger.snapshot()["records"][self.handle.name]["state"], "revoked")

    def test_owner_cleanup_grace_does_not_take_over_epoch_and_disarm_stays_clean(self):
        self.prepare(); self.arm()
        self.daemon._dispatch(self.service, "fence", {"handle": self.handle.as_dict()})
        with self.assertRaises(watchdog.WatchdogError):
            self.daemon._dispatch(self.service, "check", {"handle": self.handle.as_dict()})
        self.daemon._revocations()
        self.daemon._fence_registry.assert_not_called()
        self.daemon._dispatch(self.service, "disarm", {"handle": self.handle.as_dict(), "proofDigest": fixtures.DIGEST})
        self.daemon._revocations()
        self.daemon._fence_registry.assert_not_called()
        self.assertEqual(self.ledger.snapshot()["records"][self.handle.name]["state"], "disarmed")

    def test_emergency_cleanup_worker_count_is_bounded(self):
        self.prepare()
        release = threading.Event()
        self.addCleanup(release.set)
        self.daemon._fence_registry.side_effect = lambda _record: release.wait(2)
        for index in range(5):
            handle = GenerationHandle("sf-" + f"{index:032x}", fixtures.GENERATION, 1)
            self.daemon._dispatch(self.service, "arm", {"handle": handle.as_dict(), "deadline": int(time.time()) + 10})
        self.daemon._revocations({self.service})
        self.assertEqual(self.daemon._cleanup_inflight, 4)
        self.assertEqual(len(self.daemon._cleanup_started), 4)
        release.set()
        deadline = time.monotonic() + 1
        while self.daemon._cleanup_inflight and time.monotonic() < deadline:
            time.sleep(.01)
        self.daemon._revocations({self.service})
        self.assertEqual(len(self.daemon._cleanup_started), 5)

    def test_emergency_worker_really_takes_epoch_and_keeps_uncertain_tombstone(self):
        self.prepare()
        path = self.scratch / "vm-registry"
        path.mkdir(mode=0o700)
        self.deployment.registry_root = str(path)
        registry = watchdog.SandboxRegistry(path, self.profile.namespace)
        self.addCleanup(registry.close)
        with registry.locked() as tx:
            original_epoch = tx.takeover()
            record = tx.reserve({"projectId": fixtures.DIGEST, "team": "team", "featureId": "F1",
                                 "role": "backend", "taskId": "T1", "attempt": 1}, epoch=original_epoch)
            tx.bind(record["name"], record["generation"], original_epoch,
                    sandbox_id="d9f44bce-019d-43c3-b8c2-dcf7ac05258b", created_at="2026-11-17T01:00:00Z")
        self.handle = GenerationHandle(record["name"], record["generation"], original_epoch)
        self.arm()
        events = []
        self.daemon._cleanup = threading.local()
        self.daemon._native = SimpleNamespace(run_credential=mock.Mock(side_effect=lambda *_args, **_kwargs: events.append("remove-credential")))
        self.daemon._cleanup_backend = SimpleNamespace(stop=mock.Mock(side_effect=lambda _identity: events.append("stop")),
                                                       destroy=mock.Mock(side_effect=lambda _identity: events.append("destroy")))
        lease = self.ledger.snapshot()["records"][self.handle.name]
        with mock.patch.object(watchdog.os, "killpg") as kill:
            watchdog.WatchdogDaemon._fence_registry(self.daemon, lease)
            kill.assert_not_called()
        with registry.locked() as tx:
            self.assertGreater(tx.epoch, original_epoch)
            after = tx.records()[0]
        self.assertEqual(after["state"], "cleanup-pending")
        for name in ("name", "generation", "sandboxId", "createdAt", "scope"):
            expected = record[name] if name in record else None
            if name == "sandboxId": expected = "d9f44bce-019d-43c3-b8c2-dcf7ac05258b"
            if name == "createdAt": expected = "2026-11-17T01:00:00Z"
            self.assertEqual(after[name], expected)
        self.assertEqual(events, ["remove-credential", "stop", "destroy"])
        self.assertFalse(self.verify())

    def test_stalled_owner_cleanup_becomes_emergency_without_extending_deadline(self):
        self.prepare(); self.arm()
        self.daemon._dispatch(self.service, "fence", {"handle": self.handle.as_dict()})
        before = self.ledger.snapshot()["records"][self.handle.name]
        self.ledger.change(lambda value: value["records"][self.handle.name].update(emergencyAtNs=time.monotonic_ns() - 1))
        self.daemon._revocations()
        deadline = time.monotonic() + 1
        while not self.daemon._fence_registry.called and time.monotonic() < deadline:
            time.sleep(.01)
        self.daemon._fence_registry.assert_called_once()
        after = self.ledger.snapshot()["records"][self.handle.name]
        self.assertEqual((before["deadline"], before["deadlineNs"]), (after["deadline"], after["deadlineNs"]))

    def test_wrong_generation_epoch_lease_deadline_and_liveness_deny(self):
        self.prepare(); self.arm()
        for changes in ({"generation": "gen-" + "c" * 32}, {"epoch": 2}, {"lease_id": "b" * 32}, {"deadline": self.deadline + 1}):
            with self.subTest(changes=changes):
                self.assertFalse(self.verify(**changes))
        with mock.patch.object(watchdog, "_identity_helper", return_value=SimpleNamespace(process_identity=lambda _pid: None)):
            self.assertFalse(self.verify())

    def test_monotonic_and_wall_deadlines_each_fail_closed(self):
        self.prepare(); self.arm()
        path = Path(self.deployment.watchdog_root) / watchdog.LEDGER_FILE
        original = json.loads(path.read_bytes())
        for kind in ("wall", "monotonic", "heartbeat"):
            value = json.loads(json.dumps(original))
            record = value["records"][self.handle.name]
            if kind == "wall":
                record["deadline"] = int(time.time()) - 1
            elif kind == "monotonic":
                record["deadlineNs"] = time.monotonic_ns() - 1
            else:
                value["freshUntilNs"] = time.monotonic_ns() - 1
            path.write_text(json.dumps(value))
            self.assertFalse(self.verify(deadline=record["deadline"]))

    def test_service_disconnect_revokes_before_async_fencing(self):
        self.prepare(); self.arm()
        self.daemon._revocations({self.service})
        self.assertFalse(self.verify())
        deadline = time.monotonic() + 1
        while not self.daemon._fence_registry.called and time.monotonic() < deadline:
            time.sleep(.01)
        self.daemon._fence_registry.assert_called_once()

    def test_restart_revokes_old_leases_and_history_cannot_reset(self):
        self.prepare(); self.arm()
        replacement = watchdog.WatchdogLedger(self.deployment, self.profile, self.identity)
        self.addCleanup(replacement.close)
        self.assertFalse(self.verify())
        (Path(self.deployment.watchdog_root) / watchdog.LEDGER_FILE).unlink()
        with self.assertRaises(watchdog.WatchdogError):
            watchdog.WatchdogLedger(self.deployment, self.profile, self.identity)

    def test_receipt_renewal_keeps_watchdog_basis_and_revokes_old_lease(self):
        self.prepare(); self.arm()
        renewed = dataclasses.replace(self.profile, qualification_digest="sha256:" + "f" * 64)
        replacement = watchdog.WatchdogLedger(self.deployment, renewed, self.identity)
        self.addCleanup(replacement.close)
        value = replacement.snapshot()
        self.assertEqual(value["schemaVersion"], 2)
        self.assertEqual(value["profileBasisDigest"], watchdog.profile_basis_digest(renewed))
        self.assertEqual(value["records"][self.handle.name]["state"], "revoked")

    def test_closed_rpc_schema_and_same_name_reuse_deny(self):
        self.prepare(); self.arm()
        for operation, payload in (("shell", {}), ("heartbeat", {"extra": True}),
            ("arm", {"handle": self.handle.as_dict(), "deadline": self.deadline}),
            ("fence", {"handle": self.handle.as_dict(), "force": True})):
            with self.subTest(operation=operation), self.assertRaises(watchdog.WatchdogError):
                self.daemon._dispatch(self.service, operation, payload)

    def test_private_native_rpc_eof_revokes_real_connection_lease(self):
        self.prepare()
        server, client = socket.socketpair()
        thread = threading.Thread(target=self.daemon._connection, args=(server,), daemon=True)
        thread.start()
        self.addCleanup(client.close)
        def rpc(operation, payload):
            watchdog._send(client, {"schemaVersion": 1, "deploymentDigest": self.deployment.digest,
                                   "operation": operation, "payload": payload})
            return watchdog._receive(client)
        self.assertTrue(rpc("register", {})["ok"])
        deadline = int(time.time()) + 10
        self.assertTrue(rpc("arm", {"handle": self.handle.as_dict(), "deadline": deadline})["ok"])
        client.close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.ledger.snapshot()["records"][self.handle.name]["state"], "revoked")

    def test_native_peer_uid_linux_socket_and_darwin_audit_token(self):
        left, right = socket.socketpair()
        try:
            self.assertEqual(watchdog._peer_uid(left), os.geteuid())
        finally:
            left.close(); right.close()
        class Function:
            def __call__(self, value):
                if type(value) is not watchdog._DarwinAuditToken:
                    raise AssertionError("libbsm requires audit_token_t by value")
                self.value = list(value.val)
                return 1234
        function = Function()
        bsm = SimpleNamespace(audit_token_to_euid=function)
        connection = SimpleNamespace(getsockopt=mock.Mock(return_value=bytes(range(32))))
        with mock.patch.object(watchdog.sys, "platform", "darwin"), mock.patch.object(watchdog.ctypes, "CDLL", return_value=bsm) as library:
            self.assertEqual(watchdog._peer_uid(connection), 1234)
            library.assert_called_once_with("/usr/lib/libbsm.dylib")
            connection.getsockopt.assert_called_once_with(0, 0x006, 32)
            self.assertEqual(len(function.value), 8)
            self.assertEqual(function.argtypes, [watchdog._DarwinAuditToken])
            self.assertIs(function.restype, watchdog.ctypes.c_uint32)
            self.assertEqual(watchdog.ctypes.sizeof(watchdog._DarwinAuditToken), 32)
        for token in (b"", b"x" * 31):
            connection = SimpleNamespace(getsockopt=lambda *_args: token)
            with mock.patch.object(watchdog.sys, "platform", "darwin"), self.assertRaises(watchdog.WatchdogError):
                watchdog._peer_uid(connection)
        connection = SimpleNamespace(getsockopt=lambda *_args: b"x" * 32)
        with mock.patch.object(watchdog.sys, "platform", "darwin"), mock.patch.object(watchdog.ctypes, "CDLL", side_effect=OSError("unavailable")), self.assertRaises(watchdog.WatchdogError):
            watchdog._peer_uid(connection)


if __name__ == "__main__":
    unittest.main()
