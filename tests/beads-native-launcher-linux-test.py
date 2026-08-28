#!/usr/bin/env python3
"""Genuine Linux test for the V27 raw-launcher fixed-FD custody boundary."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import beads_native_boundary_v27 as boundary


PLAN_DOMAIN = b"startup-factory/beads/v27/plan\0"
EVIDENCE_DOMAIN = b"startup-factory/beads/v27/evidence\0"
RESULT_DOMAIN = b"startup-factory/beads/v27/result\0"
SOURCES = tuple(range(64, 76))


def plan_bytes(key: bytes, payload: bytes, *, tamper: bool = False) -> bytes:
    key_id = hashlib.sha256(key).digest()
    commitment = hmac.new(key, PLAN_DOMAIN + payload, hashlib.sha256).digest()
    if tamper:
        commitment = bytes([commitment[0] ^ 1]) + commitment[1:]
    return b"SFV27A1\0" + key_id + commitment + struct.pack("!I", len(payload)) + payload


class NativeLauncherLinuxTest(unittest.TestCase):
    def setUp(self) -> None:
        if not __import__("sys").platform.startswith("linux"):
            self.skipTest("the genuine launcher custody test requires Linux")
        self.launcher = Path(os.environ["STARTUP_FACTORY_V27_TEST_LAUNCHER"])
        self.child = Path(os.environ["STARTUP_FACTORY_V27_TEST_CHILD"])
        self.liveness = Path(os.environ["STARTUP_FACTORY_V27_TEST_LIVENESS"])

    def _run(
        self,
        *,
        tamper_plan: bool = False,
        same_socket: bool = False,
        wrong_proof: bool = False,
        terminal_pidfd: bool = False,
        key_bytes: bytes | None = None,
        leave_key_unsealed: bool = False,
        exec_directory: bool = False,
        parent_extra_fd: bool = False,
    ):
        key = bytes(range(32))
        payload = b'{"operationId":"fixture","schemaVersion":27}'
        opened: list[int] = []
        sockets: list[socket.socket] = []
        temporary = tempfile.TemporaryDirectory()
        try:
            plan = os.memfd_create("sf-v27-test-plan", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            opened.append(plan)
            os.write(plan, plan_bytes(key, payload, tamper=tamper_plan))
            os.lseek(plan, 0, os.SEEK_SET)
            fcntl.fcntl(plan, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            key_fd = os.memfd_create("sf-v27-test-key", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            opened.append(key_fd)
            os.write(key_fd, key if key_bytes is None else key_bytes)
            os.lseek(key_fd, 0, os.SEEK_SET)
            if not leave_key_unsealed:
                fcntl.fcntl(key_fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            lock_fd = os.open(Path(temporary.name) / "operation.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            opened.append(lock_fd)
            lock = struct.pack("hhqqi", fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
            fcntl.fcntl(lock_fd, fcntl.F_OFD_SETLK, lock)
            if terminal_pidfd:
                child_pid = os.fork()
                if child_pid == 0:
                    os._exit(0)
                pidfd = os.pidfd_open(child_pid, 0)
                os.waitpid(child_pid, 0)
            else:
                pidfd = os.pidfd_open(os.getpid(), 0)
            opened.append(pidfd)
            supervisor = os.open(temporary.name, os.O_RDONLY | os.O_DIRECTORY)
            opened.append(supervisor)
            payload_dir = Path(temporary.name) / "payload"
            payload_dir.mkdir()
            payload_fd = os.open(payload_dir, os.O_RDONLY | os.O_DIRECTORY)
            opened.append(payload_fd)
            controller_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            sockets.extend((controller_socket, child_socket))
            controller_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            child_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            result_fd = os.open(temporary.name, os.O_RDONLY | os.O_DIRECTORY)
            opened.append(result_fd)
            proof_path = "/dev/null" if wrong_proof else f"/proc/self/task/{threading.get_native_id()}/stat"
            proof_fd = os.open(proof_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            opened.append(proof_fd)
            evidence_path = Path(temporary.name) / "evidence"
            evidence_fd = os.open(evidence_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            opened.append(evidence_fd)
            executable_fd = os.open(
                temporary.name if exec_directory else self.child,
                os.O_RDONLY
                | (os.O_DIRECTORY if exec_directory else 0)
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
            )
            opened.append(executable_fd)
            mapping = {
                64: plan, 65: key_fd, 66: lock_fd, 67: pidfd, 68: supervisor,
                69: payload_fd, 70: controller_socket.fileno(),
                71: controller_socket.fileno() if same_socket else child_socket.fileno(),
                72: result_fd, 73: proof_fd, 74: evidence_fd, 75: executable_fd,
            }
            if parent_extra_fd:
                os.dup2(result_fd, 76, inheritable=True)
                opened.append(76)
            completed = boundary._invoke_native_launcher_v27(
                self.launcher,
                mapping,
                timeout=10,
                drain_on_failure=False,
            )
            evidence = os.pread(evidence_fd, 64, 0)
            result_path = Path(temporary.name) / "result.bin"
            durable_result = result_path.read_bytes() if result_path.exists() else b""
            return (
                completed.returncode,
                completed.stdout,
                completed.stderr,
                evidence,
                durable_result,
                key,
                payload,
            )
        finally:
            for target in sorted(set(opened), reverse=True):
                try:
                    os.close(target)
                except OSError:
                    pass
            for item in sockets:
                try:
                    item.close()
                except OSError:
                    pass
            temporary.cleanup()

    def test_real_launcher_child_hmac_fd_custody(self) -> None:
        code, stdout, stderr, evidence, durable_result, key, payload = self._run(
            parent_extra_fd=True
        )
        self.assertEqual((0, b""), (code, stderr))
        commitment = hmac.new(key, PLAN_DOMAIN + payload, hashlib.sha256).digest()
        expected_evidence = hmac.new(key, EVIDENCE_DOMAIN + commitment, hashlib.sha256).digest()
        expected_result = hmac.new(key, RESULT_DOMAIN + expected_evidence, hashlib.sha256).digest()
        self.assertEqual(expected_evidence, evidence)
        self.assertEqual(expected_result, durable_result)
        self.assertEqual(expected_result, stdout)

    def test_rejects_plan_socket_and_launcher_proof_substitution(self) -> None:
        for values in (
            {"tamper_plan": True},
            {"same_socket": True},
            {"wrong_proof": True},
            {"terminal_pidfd": True},
            {"key_bytes": bytes(range(31))},
            {"leave_key_unsealed": True},
            {"exec_directory": True},
        ):
            with self.subTest(values=values):
                code, stdout, stderr, evidence, durable_result, _key, _payload = self._run(**values)
                self.assertEqual(125, code)
                self.assertEqual(b"", stdout)
                self.assertEqual(b"", evidence)
                self.assertEqual(b"", durable_result)
                self.assertTrue(stderr.startswith(b"V27 launcher"))

    def test_production_helper_rejects_incomplete_or_extended_source_table(self) -> None:
        for mapping in (
            {descriptor: descriptor for descriptor in SOURCES[:-1]},
            {descriptor: descriptor for descriptor in (*SOURCES, 76)},
        ):
            with self.subTest(descriptors=tuple(mapping)):
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "source descriptor table changed",
                ):
                    boundary._invoke_native_launcher_v27(
                        self.launcher,
                        mapping,
                        timeout=1,
                        drain_on_failure=False,
                    )

    def test_real_midrun_control_and_parent_loss_drain_payload_cgroup(self) -> None:
        for mode in ("control-loss", "parent-loss"):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    [str(self.liveness), mode],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertEqual((0, b"", b""), (
                    completed.returncode, completed.stdout, completed.stderr
                ))

    def test_each_lifecycle_child_is_placed_before_one_release(self) -> None:
        for mode in ("child-placement", "early-exec-denied"):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    [str(self.liveness), mode],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(
                    (0, b"", b""),
                    (completed.returncode, completed.stdout, completed.stderr),
                )

    def test_real_proc_start_time_parser_handles_comm_spaces_and_malformed_input(self) -> None:
        completed = subprocess.run(
            [str(self.liveness), "proc-stat-parser"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(
            (0, b"", b""),
            (completed.returncode, completed.stdout, completed.stderr),
        )

    def test_private_cgroup_rights_are_exact_one_use_and_closed(self) -> None:
        for mode in (
            "rights-valid",
            "rights-missing",
            "rights-extra",
            "rights-replayed",
        ):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    [str(self.liveness), mode],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)

    def test_native_event_relay_authenticates_event_and_controller_ack(self) -> None:
        for mode in (
            "native-event",
            "native-event-ack-tampered",
            "native-event-revoke",
            "native-event-revoke-at-release",
            "native-failure-results",
            "native-result-offer-ack-tampered",
        ):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    [str(self.liveness), mode],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)

    def test_creator_abi_retains_a_fast_exit_for_exact_join_capture(self) -> None:
        for mode in (
            "creator-abi-fast-exit", "creator-attr-failure-matrix",
            "creator-handshake-failure-matrix",
        ):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    [str(self.liveness), mode],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(
                    (0, b"", b""),
                    (completed.returncode, completed.stdout, completed.stderr),
                )

        with tempfile.TemporaryDirectory() as name:
            artifact_root = Path(name)
            artifact_root.chmod(0o700)
            environment = dict(os.environ)
            environment["STARTUP_FACTORY_V27_TEST_CREATOR_ARTIFACT_DIR"] = name
            completed = subprocess.run(
                [str(self.liveness), "creator-abi-fast-exit"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
                env=environment,
            )
            self.assertEqual(
                (0, b"", b""),
                (completed.returncode, completed.stdout, completed.stderr),
            )
            plan = {
                "operationId": "a" * 64,
                "requestKeyId": boundary.sha256(bytes(range(1, 33))),
                "stageLocation": 5,
                "stagePlanSha256": "sha256:" + "b" * 64,
            }
            directory = os.open(
                artifact_root,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                reopened = boundary._reopen_native_creator_artifacts_v27(
                    directory,
                    bytes(range(1, 33)),
                    plan,
                    set(os.listdir(directory)),
                    return_binding=True,
                )
                self.assertEqual("complete", reopened["status"])
                self.assertEqual(
                    {
                        "capturePreparationRecordSha256": "sha256:" + "0" * 63 + "a",
                        "returnAuthorizationRecordSha256": "sha256:" + "0" * 63 + "b",
                        "creatorReturnCurrentRecordSha256": "sha256:" + "0" * 63 + "c",
                        "creatorHandleConsumed": True,
                        "operationId": "a" * 64,
                        "requestKeyId": boundary.sha256(bytes(range(1, 33))),
                        "returnSentinel": "creator-positive-sentinel",
                        "slotGeneration": 1,
                        "stageLocation": 5,
                        "stagePlanSha256": "sha256:" + "b" * 64,
                    },
                    {
                        field: reopened["binding"][field]
                        for field in (
                            "capturePreparationRecordSha256",
                            "returnAuthorizationRecordSha256",
                            "creatorReturnCurrentRecordSha256",
                            "creatorHandleConsumed", "operationId",
                            "requestKeyId", "returnSentinel",
                            "slotGeneration", "stageLocation",
                            "stagePlanSha256",
                        )
                    },
                )
            finally:
                os.close(directory)

    def test_genuine_creator_handshake_wire_roundtrips_controller_sequencer(self) -> None:
        completed = subprocess.run(
            [str(self.liveness), "creator-handshake-wire-matrix"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        rows = completed.stdout.splitlines()
        self.assertEqual(21, len(rows))
        observed_labels: set[str] = set()
        creation_rows: dict[
            str, tuple[str, str, dict[str, object]]
        ] = {}
        lifetime_labels: set[str] = set()
        for raw_row in rows:
            label_raw, nonce_raw, plan_raw, observation_raw = raw_row.split(
                b"\t", 3
            )
            label = label_raw.decode("ascii")
            expected_nonce = nonce_raw.decode("ascii")
            expected_plan = plan_raw.decode("ascii")
            observation = boundary._strict_probe_json(observation_raw + b"\n")
            if label.startswith("lifetime-"):
                failure_label = label.removeprefix("lifetime-")
                self.assertIn(failure_label, creation_rows)
                stored_nonce, stored_plan, created = creation_rows[failure_label]
                self.assertEqual(
                    (stored_nonce, stored_plan),
                    (expected_nonce, expected_plan),
                )
                validated_lifetime = (
                    boundary._validate_native_event_observation_v27(
                        "abort-failure-lifetime", "after", observation
                    )
                )
                sequencer = object.__new__(
                    boundary._NativeOuterEventSequencerV27
                )
                intent = boundary._reference_native_event_observation_v27(
                    "creator-creation-consumed", "before",
                    supervisor_pid=int(created["joinOwnerTid"]),
                )
                intent.update(
                    {
                        "creationNonceSha256": expected_nonce,
                        "creatorPlanSha256": expected_plan,
                        "joinOwnerStartTicks": created["joinOwnerStartTicks"],
                    }
                )
                sequencer.creator_creation_intent = intent
                sequencer.creator_created_receipt = created
                sequencer.plan = {"planSha256": expected_plan}
                sequencer._validate_creator_continuity_v27(
                    "abort-failure-lifetime", "before", validated_lifetime
                )
                sequencer._validate_creator_continuity_v27(
                    "abort-failure-lifetime", "after", validated_lifetime
                )
                lifetime_labels.add(failure_label)
                continue
            event = (
                "native-creator-created"
                if label == "valid"
                else "creator-status-uncertain"
            )
            validated = boundary._validate_native_event_observation_v27(
                event, "before", observation
            )
            sequencer = object.__new__(boundary._NativeOuterEventSequencerV27)
            intent = boundary._reference_native_event_observation_v27(
                "creator-creation-consumed", "before",
                supervisor_pid=int(observation["joinOwnerTid"]),
            )
            intent.update(
                {
                    "creationNonceSha256": expected_nonce,
                    "creatorPlanSha256": expected_plan,
                    "joinOwnerStartTicks": observation["joinOwnerStartTicks"],
                }
            )
            sequencer.creator_creation_intent = intent
            sequencer.creator_created_receipt = None
            sequencer.plan = {"planSha256": expected_plan}
            sequencer._validate_creator_continuity_v27(
                event, "before", validated
            )
            sequencer._validate_creator_continuity_v27(
                event, "after", validated
            )
            creation_rows[label] = (expected_nonce, expected_plan, validated)
            observed_labels.add(label)
        self.assertEqual(
            {
                "valid", "attr-destroy", "cancellation-disable-failed",
                "signal-mask-failed", "creator-tid-invalid",
                "creator-start-unreadable", "supervisor-start-unreadable",
                "parent-identity-mismatch", "creation-nonce-echo-failed",
                "plan-digest-echo-failed", "handshake-timeout",
            },
            observed_labels,
        )
        self.assertEqual(observed_labels - {"valid"}, lifetime_labels)

    def test_durable_fd5_lock_rejects_substitution_and_contention(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.chmod(0o700)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                descriptor = boundary._open_durable_operation_lock_v27(directory)
                try:
                    metadata = os.fstat(descriptor)
                    self.assertEqual((0o600, 1), (
                        metadata.st_mode & 0o777,
                        metadata.st_nlink,
                    ))
                    with self.assertRaisesRegex(
                        boundary.NativeBoundaryV27Error,
                        "did not acquire",
                    ):
                        boundary._open_durable_operation_lock_v27(directory)
                finally:
                    os.close(descriptor)
            finally:
                os.close(directory)

        for substitution in ("mode", "symlink", "hardlink"):
            with self.subTest(substitution=substitution), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                root.chmod(0o700)
                lock = root / "operation.lock"
                if substitution == "symlink":
                    target = root / "outside"
                    target.write_bytes(b"")
                    lock.symlink_to(target)
                else:
                    lock.write_bytes(b"")
                    lock.chmod(0o644 if substitution == "mode" else 0o600)
                    if substitution == "hardlink":
                        os.link(lock, root / "second-link")
                directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(boundary.NativeBoundaryV27Error):
                        boundary._open_durable_operation_lock_v27(directory)
                finally:
                    os.close(directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
