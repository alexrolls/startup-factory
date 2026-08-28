#!/usr/bin/env python3
"""Offline protocol tests for the fixed Linux Beads boundary controller."""

from __future__ import annotations

import ast
import array
import contextlib
import errno
import fcntl
import hashlib
import io
import importlib
import json
import os
import socket
import stat
import struct
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

controller = importlib.import_module(
    "startup_factory_cli.beads_boundary_controller"
)


def digest(label: str) -> str:
    return controller._sha(label.encode("utf-8"))


def reader_outputs() -> list[bytes]:
    names = (
        "beads-v1.1.2-issue-envelope.json",
        "beads-v1.1.2-labels-envelope.json",
        "beads-v1.1.2-comments-envelope.json",
        "beads-v1.1.2-down-dependencies-envelope.json",
    )
    return [(ROOT / "tests/fixtures" / name).read_bytes() for name in names]


def proved_fake_cgroup2(descriptor: int) -> dict[str, object]:
    metadata = os.fstat(descriptor)
    return {
        "schemaVersion": 27,
        "filesystemMagic": controller._CGROUP2_SUPER_MAGIC_V27,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "type": "directory",
    }


def proved_fake_setgid_mode(descriptor: int) -> int:
    mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
    return mode | stat.S_ISGID if mode == 0o710 else mode


class BoundaryControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        # Resolve macOS' /var -> /private/var compatibility symlink.  The
        # production scanner intentionally refuses every symlinked ancestor.
        self.state_root = Path(self.temporary.name).resolve() / "state"
        self.state_root.mkdir(mode=0o700)
        self.key = b"controller-test-domain-key-material-32-bytes"
        self.config = controller.ControllerConfig(
            beads_enabled=True,
            protected_root=Path("/var/lib/startup-factory/beads-protected-runtime"),
            record_hmac_key_path=Path(
                "/var/lib/startup-factory/beads-protected-runtime/records.hmac"
            ),
            controller_uid=81_001,
            broker_uid=81_002,
            worker_uid=81_003,
            transport_gid=81_004,
            runtime_manifest_path=Path(
                "/usr/lib/startup-factory/beads-runtime-manifest.json"
            ),
            module_path=Path(
                "/usr/lib/startup-factory/beads_boundary_controller.py"
            ),
            schema_path=Path(
                "/usr/lib/startup-factory/beads-protected-runtime-schema.json"
            ),
            runtime_manifest_sha256=digest("runtime"),
            module_sha256=digest("module"),
            schema_sha256=digest("schema"),
            config_epoch=4,
            key_epoch=7,
            native_boundary_manifest_path=Path(
                "/usr/lib/startup-factory/beads-native-boundary-v27.json"
            ),
            native_boundary_manifest_sha256=digest("native-boundary-v27"),
            native_module_path=Path(controller.native_boundary_v27.__file__),
            native_module_sha256=controller._sha(
                Path(controller.native_boundary_v27.__file__).read_bytes()
            ),
        )
        self.state_patch = mock.patch.object(
            controller, "STATE_ROOT", self.state_root
        )
        self.state_patch.start()

    def tearDown(self) -> None:
        self.state_patch.stop()
        self.temporary.cleanup()

    def packet(self, action: str, request: dict) -> bytes:
        return controller._canonical(
            {
                "schemaVersion": 1,
                "protocol": controller.PROTOCOL,
                "action": action,
                "request": request,
            }
        )

    def test_pre_effect_worker_packet_and_two_descriptor_empty_proofs_are_exact(self) -> None:
        manifest = controller.native_boundary_v27.parse_native_boundary_manifest_v27(
            json.loads(
                (ROOT / "runtime/beads-native-boundary-v27.example.json").read_bytes()
            )
        )
        plan = {
            "stagePlanSha256": digest("pre-effect-stage"),
        }
        classification = {
            "classification": "pre-popen-descriptor-preflight-failed",
            "setupStep": "source-descriptor-preflight",
            "failureKind": "policy-rejection",
            "executablePathSha256": controller.native_boundary_v27.sha256(
                str(manifest.launcher_path).encode("utf-8")
            ),
            "errno": None,
            "processCreated": False,
        }
        evidence = controller.native_boundary_v27.sha256(
            b"startup-factory/beads/v27/launch-pre-effect-failed\0"
            + controller.native_boundary_v27.canonical_bytes(classification)
        )
        encoded = controller._worker_pre_effect_failure_packet_v27(
            plan["stagePlanSha256"],
            evidence_sha256=evidence,
            classification=classification,
            request_key=self.key,
        )
        packet = controller._worker_packet_v27(encoded, "pre-effect fixture")
        self.assertEqual(
            evidence,
            controller._validate_worker_pre_effect_failure_v27(
                packet,
                plan=plan,
                manifest=manifest,
                request_key=self.key,
            )["evidenceSha256"],
        )
        for field, replacement in (
            ("packetHmac", "hmac-sha256:" + "0" * 64),
            ("evidenceSha256", digest("forged-pre-effect")),
        ):
            with self.subTest(field=field), self.assertRaises(
                controller.ControllerProtocolError
            ):
                controller._validate_worker_pre_effect_failure_v27(
                    {**packet, field: replacement},
                    plan=plan,
                    manifest=manifest,
                    request_key=self.key,
                )

        root = Path(self.temporary.name) / "pre-effect-cgroup"
        supervisor = root / "S"
        worker = supervisor / "worker"
        payload = supervisor / "payload"
        worker.mkdir(parents=True)
        payload.mkdir()
        (supervisor / "cgroup.procs").write_bytes(b"")
        for name, value in {
            "cgroup.procs": b"",
            "cgroup.threads": b"",
            "cgroup.subtree_control": b"cpu memory pids\n",
            "cgroup.events": b"populated 0\n",
            "cgroup.kill": b"",
            "cgroup.stat": b"nr_descendants 0\nnr_dying_descendants 0\n",
        }.items():
            (payload / name).write_bytes(value)
        descriptors: list[int] = []
        try:
            supervisor_fd = os.open(supervisor, os.O_RDONLY | os.O_DIRECTORY)
            supervisor_procs = os.open(supervisor / "cgroup.procs", os.O_WRONLY)
            worker_fd = os.open(worker, os.O_RDONLY | os.O_DIRECTORY)
            payload_fd = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
            payload_procs = os.open(payload / "cgroup.procs", os.O_RDWR)
            payload_threads = os.open(payload / "cgroup.threads", os.O_RDONLY)
            payload_subtree = os.open(
                payload / "cgroup.subtree_control", os.O_RDONLY
            )
            payload_events = os.open(payload / "cgroup.events", os.O_RDONLY)
            payload_kill = os.open(payload / "cgroup.kill", os.O_WRONLY)
            descriptors.extend(
                (
                    supervisor_fd, supervisor_procs, worker_fd, payload_fd,
                    payload_procs, payload_threads, payload_subtree,
                    payload_events, payload_kill,
                )
            )
            custody = controller._ControllerCgroupCustodyV27(
                supervisor_fd,
                supervisor_procs,
                worker_fd,
                "/fixture/S/worker",
                "payload",
                {
                    "operationId": "a" * 64,
                    "stageLocation": 5,
                    "stagePlanSha256": plan["stagePlanSha256"],
                },
                (
                    payload_fd, payload_procs, payload_threads,
                    payload_subtree, payload_events, payload_kill,
                ),
                os.geteuid(),
                os.geteuid(),
                os.getegid(),
            )
            first = controller._controller_pre_effect_empty_observation_v27(
                custody
            )
            second = controller._controller_pre_effect_empty_observation_v27(
                custody
            )
            self.assertEqual(first, second)
            self.assertEqual((True, 0, 0), (
                first["knownNoChild"],
                first["placementMask"],
                first["cgroupStat"]["nr_descendants"],
            ))
            (payload / "lifecycle-0").mkdir()
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "untracked child"
            ):
                controller._controller_pre_effect_empty_observation_v27(custody)
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def test_worker_channel_consumes_authenticated_pre_effect_failure_without_result(self) -> None:
        manifest = controller.native_boundary_v27.parse_native_boundary_manifest_v27(
            json.loads(
                (ROOT / "runtime/beads-native-boundary-v27.example.json").read_bytes()
            )
        )
        repository = Path(self.temporary.name) / "pre-effect-repository"
        (repository / ".beads").mkdir(parents=True)
        (repository / ".beads/issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
        effect = controller.native_boundary_v27.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="e" * 64,
            operation_class="ordinary",
            argv=["/usr/local/bin/bd", "update", "task-1", "--json"],
            repository_path=str(repository),
        )
        stage = controller.native_boundary_v27.literal_stage_schedule_v27(
            "ordinary"
        )[4]
        plan = controller.native_boundary_v27.derive_native_stage_action_plan_v27(
            manifest, effect, stage
        )
        assert plan is not None
        request_key = b"p" * 32
        plan = {
            **plan,
            "requestKeyId": controller.native_boundary_v27.sha256(request_key),
            "stagePlanSha256": None,
        }
        plan["stagePlanSha256"] = (
            controller.native_boundary_v27._native_stage_plan_digest_v27(plan)
        )
        classification = {
            "classification": "pre-popen-descriptor-preflight-failed",
            "setupStep": "source-descriptor-preflight",
            "failureKind": "policy-rejection",
            "executablePathSha256": controller.native_boundary_v27.sha256(
                str(manifest.launcher_path).encode("utf-8")
            ),
            "errno": None,
            "processCreated": False,
        }
        evidence = controller.native_boundary_v27.sha256(
            b"startup-factory/beads/v27/launch-pre-effect-failed\0"
            + controller.native_boundary_v27.canonical_bytes(classification)
        )
        failure_packet = controller._worker_pre_effect_failure_packet_v27(
            plan["stagePlanSha256"],
            evidence_sha256=evidence,
            classification=classification,
            request_key=request_key,
        )

        class Channel:
            def sendmsg(self, values, _rights):
                return len(values[0])

        retirement = {
            "schemaVersion": 27,
            "visibleDescendants": 0,
            "placementMask": 0,
            "initControllers": [],
            "preRemovalCgroupStat": {
                "nr_descendants": 0,
                "nr_dying_descendants": 0,
            },
            "terminalCgroupStat": {
                "nr_descendants": 0,
                "nr_dying_descendants": 0,
            },
        }

        class Custody:
            binding = {}
            transfer_descriptors = (10, 11, 12, 13)
            lifecycle_leaves = {}
            payload_name = "payload-fixture"
            killed = False
            closed = None

            def drain(self, *, persist_intent):
                persist_intent({"fixture": "intent"})
                return dict(retirement)

            def kill_and_wait(self):
                self.killed = True

            def close(self, *, retire):
                self.closed = retire

        custody = Custody()
        worker = controller._WorkerChannelV27(
            Channel(), 1001, 1002, 1003, 1004, 1005, 1006,
            1007, 1008, 1009, 1010, "/fixture/worker", "1",
            "f" * 64,
        )
        devnull = os.open(os.devnull, os.O_RDONLY)
        token = controller.native_boundary_v27._NATIVE_REQUEST_KEY_V27.set(
            request_key
        )
        try:
            with mock.patch.object(
                controller._WorkerChannelV27, "_assert_peer"
            ), mock.patch.object(
                controller._WorkerChannelV27,
                "_prepare_result_arena",
                return_value=digest("arena"),
            ), mock.patch.object(
                controller._WorkerChannelV27, "_persist_retirement_artifact"
            ) as persisted, mock.patch.object(
                controller,
                "_create_controller_cgroup_custody_v27",
                return_value=custody,
            ), mock.patch.object(
                controller,
                "_recv_credentialed_packet_v27",
                return_value=failure_packet,
            ), mock.patch.object(
                controller.select,
                "select",
                return_value=([worker.channel], [], []),
            ), mock.patch.object(
                controller,
                "_controller_pre_effect_empty_observation_v27",
                return_value={"schemaVersion": 27, "knownNoChild": True},
            ) as observed, mock.patch.object(
                controller.native_boundary_v27,
                "_sealed_request_key_descriptor_v27",
                return_value=(devnull, bytearray(request_key)),
            ):
                with self.assertRaises(
                    controller.native_boundary_v27._NativeLaunchPreEffectFailedV27
                ) as raised:
                    worker.execute(
                        manifest,
                        plan,
                        lifecycle_check=lambda: {
                            "operatorState": "active",
                            "generation": 1,
                        },
                        controller_key=self.key,
                        event_handler=types.SimpleNamespace(
                            current={
                                "kind": "SupervisorLaunchSlotConsumedCurrentV1",
                                "recordSha256": digest("pre-effect-consumed"),
                            }
                        ),
                    )
            self.assertEqual(2, observed.call_count)
            self.assertEqual(3, persisted.call_count)
            self.assertEqual(
                "pre-effect-proof", persisted.call_args_list[-1].args[2]
            )
            self.assertFalse(custody.killed)
            self.assertTrue(custody.closed)
            self.assertNotEqual(evidence, raised.exception.evidence_sha256)
            self.assertIsNotNone(raised.exception.proof)

            unresolved_custody = Custody()
            unresolved_fd = os.open(os.devnull, os.O_RDONLY)
            try:
                with mock.patch.object(
                    controller._WorkerChannelV27, "_assert_peer"
                ), mock.patch.object(
                    controller._WorkerChannelV27,
                    "_prepare_result_arena",
                    return_value=digest("arena-unresolved"),
                ), mock.patch.object(
                    controller._WorkerChannelV27,
                    "_persist_retirement_artifact",
                ), mock.patch.object(
                    controller,
                    "_create_controller_cgroup_custody_v27",
                    return_value=unresolved_custody,
                ), mock.patch.object(
                    controller,
                    "_recv_credentialed_packet_v27",
                    return_value=failure_packet,
                ), mock.patch.object(
                    controller.select,
                    "select",
                    return_value=([worker.channel], [], []),
                ), mock.patch.object(
                    controller,
                    "_controller_pre_effect_empty_observation_v27",
                    side_effect=controller.ControllerProtocolError(
                        "payload child identity appeared"
                    ),
                ), mock.patch.object(
                    controller.native_boundary_v27,
                    "_sealed_request_key_descriptor_v27",
                    return_value=(unresolved_fd, bytearray(request_key)),
                ):
                    with self.assertRaises(
                        controller.native_boundary_v27._NativeLaunchUnresolvedV27
                    ) as unresolved:
                        worker.execute(
                            manifest,
                            plan,
                            lifecycle_check=lambda: {
                                "operatorState": "active",
                                "generation": 1,
                            },
                            controller_key=self.key,
                        )
                self.assertEqual(
                    "dead-holder-without-terminal",
                    unresolved.exception.recovered["nativeSupervisorLoss"][
                        "reason"
                    ],
                )
                self.assertTrue(unresolved_custody.closed)
            finally:
                try:
                    os.close(unresolved_fd)
                except OSError:
                    pass
        finally:
            controller.native_boundary_v27._NATIVE_REQUEST_KEY_V27.reset(token)
            try:
                os.close(devnull)
            except OSError:
                pass

    def exchange(self, action: str, request: dict) -> dict:
        result = controller._serve_packet(
            self.packet(action, request),
            self.config.broker_uid,
            self.config,
            self.key,
        )
        return json.loads(result)

    def open_request(self, *, client_nonce: str = "open-client-nonce-00000001") -> dict:
        operation = controller.ALLOWED_OPERATIONS[0]
        request_sha = digest("outer-request")
        binding = {
            "repositoryLocatorSha256": digest("repository"),
            "requestSha256": request_sha,
        }
        now = int(time.time())
        return {
            "operationId": hashlib.sha256(
                controller._canonical(
                    {"operation": operation, "binding": binding}
                )
            ).hexdigest(),
            "clientNonce": client_nonce,
            "operation": operation,
            **binding,
            "rootSetSha256": self.config.root_set_sha256,
            "runtimeManifestSha256": self.config.runtime_manifest_sha256,
            "moduleSha256": self.config.module_sha256,
            "schemaSha256": self.config.schema_sha256,
            "configEpoch": self.config.config_epoch,
            "keyEpoch": self.config.key_epoch,
            "issuedAtUnix": now,
            "expiresAtUnix": now + 120,
        }

    def step_request(
        self,
        prior: dict,
        target: str,
        ordinal: int,
        *,
        result_sha256: str | None = None,
    ) -> dict:
        return {
            "operationId": prior["operationId"],
            "sessionNonce": prior["sessionNonce"],
            "stepNonce": f"step-nonce-{ordinal:016d}",
            "predecessorReceiptSha256": prior["receiptSha256"],
            "targetState": target,
            "transactionIntentSha256": (
                digest("outer-request")
                if target in {"intent-bound", "effect-authorized"}
                else None
            ),
            "resultSha256": result_sha256,
        }

    def recovery_request(
        self,
        prior: dict,
        phase: str,
        ordinal: int,
        *,
        publication_intent_sha256: str | None = None,
        recovery_result_sha256: str | None = None,
    ) -> dict:
        opened = self.open_request(client_nonce="unused-recovery-open-nonce")
        return {
            "operationId": opened["operationId"],
            "recoveryNonce": f"recovery-nonce-{ordinal:016d}",
            "recoveryPhase": phase,
            "operation": opened["operation"],
            "repositoryLocatorSha256": opened["repositoryLocatorSha256"],
            "rootSetSha256": opened["rootSetSha256"],
            "requestSha256": opened["requestSha256"],
            "transactionIntentSha256": opened["requestSha256"],
            "runtimeManifestSha256": opened["runtimeManifestSha256"],
            "moduleSha256": opened["moduleSha256"],
            "schemaSha256": opened["schemaSha256"],
            "configEpoch": opened["configEpoch"],
            "keyEpoch": opened["keyEpoch"],
            "sessionNonce": prior.get("sessionNonce"),
            "predecessorReceiptSha256": prior.get("receiptSha256"),
            "effectAuthorizationReceiptSha256": prior.get(
                "effectAuthorizationReceiptSha256", prior.get("receiptSha256")
            ),
            "publicationIntentSha256": publication_intent_sha256,
            "recoveryResultSha256": recovery_result_sha256,
        }

    def prepare_authenticated_result_arena(
        self, result_directory: Path, payload_name: str
    ) -> tuple[dict[str, object], str]:
        match = controller.re.fullmatch(
            r"payload-([0-9a-f]{64})-s([0-9]+)-([0-9a-f]{16})",
            payload_name,
        )
        assert match is not None
        stage_plan_sha256 = "sha256:" + result_directory.name.rsplit("-", 1)[1]
        request_key = b"r" * 32
        plan = {
            "operationId": match.group(1),
            "stageLocation": int(match.group(2)),
            "stagePlanSha256": stage_plan_sha256,
            "requestKeyId": controller.native_boundary_v27.sha256(request_key),
        }
        lock = result_directory / "operation.lock"
        lock.write_bytes(b"")
        lock.chmod(0o600)
        result_fd = os.open(result_directory, os.O_RDONLY | os.O_DIRECTORY)
        lock_fd = os.open(lock, os.O_RDWR)
        try:
            arena = controller.native_boundary_v27._result_arena_body_v27(
                plan, os.fstat(result_fd), os.fstat(lock_fd)
            )
        finally:
            os.close(lock_fd)
            os.close(result_fd)
        preparation = {
            "arena": arena,
            "requestKeyHmac": "hmac-sha256:" + controller.hmac.new(
                request_key,
                controller.native_boundary_v27._RESULT_ARENA_REQUEST_DOMAIN_V27
                + controller._canonical(arena),
                controller.hashlib.sha256,
            ).hexdigest(),
        }
        envelope = controller._controller_result_arena_envelope_v27(
            preparation, plan, request_key, self.key
        )
        (result_directory / "arena.json").write_bytes(
            controller._canonical(envelope)
        )
        (result_directory / "arena.json").chmod(0o600)
        return plan, controller._sha(controller._canonical(envelope))

    def authenticated_retirement_chain(
        self,
        result_directory: Path,
        payload_name: str,
        plan: dict[str, object],
    ) -> dict[str, object]:
        arena = json.loads((result_directory / "arena.json").read_bytes())
        arena_sha = controller._sha(controller._canonical(arena))
        payload_identity = {
            "device": 17,
            "gid": 993,
            "inode": 19,
            "mode": "2710",
            "uid": 991,
        }
        removal_plan = [
            {
                "parent": "payload",
                "name": f"lifecycle-{ordinal}",
                "identity": {
                    "device": 17,
                    "gid": 993,
                    "inode": 100 + ordinal,
                    "mode": "0770",
                    "nlink": 2,
                    "uid": 991,
                },
            }
            for ordinal in range(6)
        ]
        intent_body = {
            "schemaVersion": 27,
            "payloadIdentity": payload_identity,
            "placementMask": 63,
            "visibleDescendants": 6,
            "initControllers": [],
            "preRemovalCgroupStat": {
                "nr_descendants": 6,
                "nr_dying_descendants": 0,
            },
            "removalPlan": removal_plan,
        }
        intent = controller._controller_retirement_envelope_v27(
            kind="intent",
            plan=plan,
            payload_name=payload_name,
            payload_identity=payload_identity,
            arena_record_sha256=arena_sha,
            predecessor_artifact_sha256=None,
            body=intent_body,
            controller_key=self.key,
        )
        intent_sha = controller._sha(controller._canonical(intent))
        receipt_body = {
            "schemaVersion": 27,
            "visibleDescendants": 6,
            "placementMask": 63,
            "controllerTrackedPlacementMask": 63,
            "initControllers": [],
            "preRemovalCgroupStat": {
                "nr_descendants": 6,
                "nr_dying_descendants": 0,
            },
            "terminalCgroupStat": {
                "nr_descendants": 0,
                "nr_dying_descendants": 0,
            },
        }
        receipt = controller._controller_retirement_envelope_v27(
            kind="receipt",
            plan=plan,
            payload_name=payload_name,
            payload_identity=payload_identity,
            arena_record_sha256=arena_sha,
            predecessor_artifact_sha256=intent_sha,
            body=receipt_body,
            controller_key=self.key,
        )
        return {"arena": arena, "intent": intent, "receipt": receipt}

    def test_closed_config_pins_paths_roles_operations_and_identity(self) -> None:
        value = {
            "beadsEnabled": True,
            "schemaVersion": 1,
            "protocol": controller.PROTOCOL,
            "endpointPath": str(controller.ENDPOINT_PATH),
            "stateRoot": str(controller.STATE_ROOT),
            "controllerKeyPath": str(controller.CONTROLLER_KEY_PATH),
            "protectedRoot": str(self.config.protected_root),
            "recordHmacKeyPath": str(self.config.record_hmac_key_path),
            "controllerUid": self.config.controller_uid,
            "brokerUid": self.config.broker_uid,
            "workerUid": self.config.worker_uid,
            "transportGid": self.config.transport_gid,
            "runtimeManifestPath": str(self.config.runtime_manifest_path),
            "modulePath": str(self.config.module_path),
            "schemaPath": str(self.config.schema_path),
            "runtimeManifestSha256": self.config.runtime_manifest_sha256,
            "moduleSha256": self.config.module_sha256,
            "schemaSha256": self.config.schema_sha256,
            "configEpoch": self.config.config_epoch,
            "keyEpoch": self.config.key_epoch,
            "nativeBoundaryManifestPath": str(
                self.config.native_boundary_manifest_path
            ),
            "nativeBoundaryManifestSha256": self.config.native_boundary_manifest_sha256,
            "nativeModulePath": str(self.config.native_module_path),
            "nativeModuleSha256": self.config.native_module_sha256,
            "allowedOperations": list(controller.ALLOWED_OPERATIONS),
        }
        self.assertEqual(self.config, controller._parse_config(value))
        for mutation in (
            {"schemaVersion": True},
            {"beadsEnabled": "false"},
            {"endpointPath": "/tmp/caller.sock"},
            {"workerUid": self.config.broker_uid},
            {"transportGid": True},
            {"allowedOperations": list(controller.ALLOWED_OPERATIONS[:-1])},
            {"unexpectedOverride": "/tmp/escape"},
            {"moduleSha256": "sha256:" + "0" * 64},
            {"nativeBoundaryManifestSha256": "sha256:" + "0" * 64},
            {"nativeBoundaryManifestPath": str(self.config.module_path)},
        ):
            invalid = {**value, **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(
                controller.ControllerProtocolError
            ):
                controller._parse_config(invalid)
        example_bytes = (
            ROOT / "runtime/beads-boundary-controller-v1.example.json"
        ).read_bytes()
        example = json.loads(example_bytes)
        self.assertEqual(controller._canonical(example) + b"\n", example_bytes)
        self.assertEqual(
            list(controller.ALLOWED_OPERATIONS), example["allowedOperations"]
        )
        self.assertEqual(str(controller.ENDPOINT_PATH), example["endpointPath"])
        self.assertEqual(66_004, example["transportGid"])
        self.assertEqual(
            "/usr/local/lib/python3.13/site-packages/startup_factory_cli/beads_boundary_controller.py",
            example["modulePath"],
        )
        self.assertEqual(str(controller.CONFIG_PATH), "/etc/startup-factory/beads-boundary-controller-v1.json")

    def test_shipped_config_is_literal_disabled_and_serve_creates_nothing(self) -> None:
        example = json.loads(
            (ROOT / "runtime/beads-boundary-controller-v1.example.json").read_bytes()
        )
        self.assertIs(example["beadsEnabled"], False)
        disabled = controller.dataclasses.replace(self.config, beads_enabled=False)
        with mock.patch.object(
            controller, "load_controller_config", return_value=disabled
        ), mock.patch.object(controller, "_create_listener") as create_listener, mock.patch.object(
            controller, "_verify_installed_artifacts"
        ) as verify_artifacts:
            with self.assertRaisesRegex(controller.ControllerProtocolError, "disabled"):
                controller.serve_forever()
        create_listener.assert_not_called()
        verify_artifacts.assert_not_called()

        service = (
            ROOT / "runtime/startup-factory-beads-controller.service.example"
        ).read_text()
        tmpfiles = (
            ROOT / "runtime/startup-factory-beads-controller.tmpfiles.example"
        ).read_text()
        self.assertIn("Restart=on-failure", service)
        self.assertIn("UMask=0007", service)
        self.assertIn("Requires=systemd-tmpfiles-setup.service", service)
        self.assertIn(
            "ExecCondition=/usr/local/bin/startup-factory-beads-controller require-enabled",
            service,
        )
        self.assertIn(
            "ReadWritePaths=/run/startup-factory /run/user/991/startup-factory-beads-results /run/user/993/startup-factory-beads-results /run/user/993 /var/lib/startup-factory/beads-boundary-controller/v1 /var/lib/startup-factory/beads-worker /var/lib/startup-factory/beads-handoff",
            service,
        )
        self.assertNotIn("ExecStartPre=", service)
        self.assertNotIn("matchpathcon", service)
        self.assertNotIn("ExecStartPre=/usr/sbin/restorecon", service)
        self.assertNotRegex(
            service, r"(?m)^CapabilityBoundingSet=.*CAP_MAC_ADMIN"
        )
        self.assertNotIn(".socket", service)
        self.assertNotIn("User=", service)
        self.assertIn(
            "d /run/startup-factory 0750 root startup-factory-beads-transport -\n",
            tmpfiles,
        )
        self.assertIn(
            "Z /run/user/993/startup-factory-beads-results 0700 "
            "startup-factory-beads-worker startup-factory-beads-worker -",
            tmpfiles,
        )
        self.assertIn(
            "d /var/lib/startup-factory/beads-worker 0700 startup-factory-beads-worker startup-factory-beads-worker -",
            tmpfiles,
        )
        self.assertIn(
            "d /var/lib/startup-factory/beads-handoff 2710 startup-factory-beads-controller startup-factory-beads-worker -",
            tmpfiles,
        )
        self.assertNotIn("A+ /var/lib/startup-factory/beads-handoff", tmpfiles)
        self.assertFalse(
            (ROOT / "runtime/startup-factory-beads-controller.socket.example").exists()
        )
        output = io.StringIO()
        with mock.patch.object(
            controller, "load_controller_config", return_value=disabled
        ), contextlib.redirect_stdout(output):
            self.assertEqual(0, controller.main(["validate-config"]))
        self.assertEqual("disabled", json.loads(output.getvalue())["proofState"])
        with mock.patch.object(
            controller, "load_controller_config", return_value=disabled
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, controller.main(["require-enabled"]))

    def test_local_operator_apply_disable_and_reactivation_are_authenticated_and_independent(self) -> None:
        operator_state = Path(self.temporary.name) / "operator-state.json"
        operator_key = b"independent-local-operator-key-material-v1"
        disabled = controller.dataclasses.replace(self.config, beads_enabled=False)

        disabled_preview = controller.preview_operator_lifecycle_v1(
            disabled, "apply", state_path=operator_state, operator_key=operator_key
        )
        self.assertFalse(disabled_preview["configEnabled"])
        self.assertFalse(operator_state.exists(), "fresh disabled preview is zero-artifact")
        with mock.patch.object(controller.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(controller.ControllerProtocolError, "configuration remains disabled"):
                controller.apply_operator_lifecycle_v1(
                    disabled,
                    "apply",
                    disabled_preview["planDigest"],
                    operator_key=operator_key,
                    state_path=operator_state,
                )
        self.assertFalse(operator_state.exists(), "config true alone is not bypassed")

        with mock.patch.object(controller.os, "geteuid", return_value=0):
            preview = controller.preview_operator_lifecycle_v1(
                self.config, "apply", state_path=operator_state, operator_key=operator_key
            )
            active = controller.apply_operator_lifecycle_v1(
                self.config,
                "apply",
                preview["planDigest"],
                operator_key=operator_key,
                state_path=operator_state,
            )
            self.assertEqual("active", active["operatorState"])
            controller.verify_operator_lifecycle_v1(
                self.config, operator_key, state_path=operator_state, require_active=True
            )

            disable_preview = controller.preview_operator_lifecycle_v1(
                self.config, "disable", state_path=operator_state, operator_key=operator_key
            )
            disabled_state = controller.apply_operator_lifecycle_v1(
                self.config,
                "disable",
                disable_preview["planDigest"],
                operator_key=operator_key,
                state_path=operator_state,
            )
            self.assertEqual("disabled", disabled_state["operatorState"])
            with self.assertRaisesRegex(controller.ControllerProtocolError, "not active"):
                controller.verify_operator_lifecycle_v1(
                    self.config, operator_key, state_path=operator_state, require_active=True
                )

            reactivate_preview = controller.preview_operator_lifecycle_v1(
                self.config, "reactivate", state_path=operator_state, operator_key=operator_key
            )
            reactivated = controller.apply_operator_lifecycle_v1(
                self.config,
                "reactivate",
                reactivate_preview["planDigest"],
                operator_key=operator_key,
                state_path=operator_state,
            )
            self.assertEqual("active", reactivated["operatorState"])
            self.assertGreater(reactivated["generation"], active["generation"])

        tampered = json.loads(operator_state.read_bytes())
        tampered["payload"]["operatorState"] = "disabled"
        operator_state.write_bytes(controller._canonical(tampered))
        with self.assertRaisesRegex(controller.ControllerProtocolError, "authentication"):
            controller.verify_operator_lifecycle_v1(
                self.config, operator_key, state_path=operator_state
            )

    def test_linux_probe_pins_registered_operation_set_and_active_verifier(self) -> None:
        probe_path = ROOT / "tests/beads-boundary-controller-linux-opt-in.py"
        source = probe_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "EXPECTED_OPERATIONS"
                for target in node.targets
            )
        )
        self.assertEqual(controller.ALLOWED_OPERATIONS, ast.literal_eval(assignment.value))
        self.assertIn(
            'controller.open_operation(\n    "verify_active_beads_authority_v1",',
            source,
        )
        self.assertNotIn("verify_current_beads_authority_epoch_v1", source)

    def test_controller_binds_socket_then_drops_to_distinct_identity(self) -> None:
        class FakeListener:
            def __init__(self) -> None:
                self.bound = None
                self.backlog = None
                self.closed = False

            def bind(self, path):
                self.bound = path

            def listen(self, backlog):
                self.backlog = backlog

            def close(self):
                self.closed = True

        listener = FakeListener()
        with mock.patch.object(controller.os, "geteuid", side_effect=[0, self.config.controller_uid]), mock.patch.object(
            controller.os, "getegid", return_value=self.config.transport_gid
        ), mock.patch.object(
            controller.os, "getgroups", return_value=[self.config.transport_gid]
        ), mock.patch.object(
            controller, "_validate_endpoint_parent"
        ), mock.patch.object(
            controller, "_remove_stale_endpoint"
        ) as removed, mock.patch.object(
            controller.socket, "socket", return_value=listener
        ), mock.patch.object(
            controller.os, "chown"
        ) as chown, mock.patch.object(
            controller.os, "chmod"
        ) as chmod, mock.patch.object(
            controller.os, "setgroups"
        ) as setgroups, mock.patch.object(
            controller.os, "setgid"
        ) as setgid, mock.patch.object(
            controller.os, "setuid"
        ) as setuid, mock.patch.object(
            controller, "_endpoint_metadata"
        ) as endpoint_metadata:
            observed = controller._create_listener(self.config)

        self.assertIs(listener, observed)
        self.assertEqual(str(controller.ENDPOINT_PATH), listener.bound)
        self.assertIsNone(listener.backlog)
        removed.assert_called_once_with(self.config)
        chown.assert_called_once_with(
            controller.ENDPOINT_PATH,
            self.config.controller_uid,
            self.config.transport_gid,
            follow_symlinks=False,
        )
        chmod.assert_called_once_with(controller.ENDPOINT_PATH, 0o660)
        setgroups.assert_called_once_with([self.config.transport_gid])
        setgid.assert_called_once_with(self.config.transport_gid)
        setuid.assert_called_once_with(self.config.controller_uid)
        endpoint_metadata.assert_called_once_with(self.config)

    def test_durable_one_operation_lineage_and_fresh_validation(self) -> None:
        opened = self.exchange("OPEN", self.open_request())
        self.assertEqual("accepted", opened["state"])
        intent = self.exchange("STEP", self.step_request(opened, "intent-bound", 1))
        effect = self.exchange(
            "STEP", self.step_request(intent, "effect-authorized", 2)
        )
        result_sha = digest("stored-result")
        stored = self.exchange(
            "STEP",
            self.step_request(
                effect, "result-stored", 3, result_sha256=result_sha
            ),
        )
        completed = self.exchange(
            "STEP",
            self.step_request(
                stored, "completed", 4, result_sha256=result_sha
            ),
        )
        self.assertEqual(("completed", result_sha), (completed["state"], completed["resultSha256"]))

        completed_retry = self.exchange(
            "OPEN",
            self.open_request(client_nonce="open-client-nonce-00000099"),
        )
        self.assertEqual(
            ("completed", result_sha, completed["sessionNonce"]),
            (
                completed_retry["state"],
                completed_retry["resultSha256"],
                completed_retry["sessionNonce"],
            ),
        )

        validation = self.exchange(
            "VALIDATE",
            {
                "operationId": completed["operationId"],
                "validationNonce": "validation-nonce-00000001",
                "storedReceiptSha256": completed_retry["receiptSha256"],
                "expectedState": "completed",
                "expectedResultSha256": result_sha,
            },
        )
        self.assertEqual("validated", validation["status"])
        with self.assertRaisesRegex(
            controller.ControllerProtocolError, "not the current"
        ):
            self.exchange(
                "VALIDATE",
                {
                    "operationId": completed["operationId"],
                    "validationNonce": "validation-nonce-00000002",
                    "storedReceiptSha256": effect["receiptSha256"],
                    "expectedState": "effect-authorized",
                    "expectedResultSha256": None,
                },
            )

    def test_open_retry_is_nonce_bound_and_never_reauthorizes_uncertain_effect(self) -> None:
        opened = self.exchange("OPEN", self.open_request())
        with self.assertRaisesRegex(controller.ControllerProtocolError, "already consumed"):
            self.exchange("OPEN", self.open_request())
        retried_request = self.open_request(
            client_nonce="open-client-nonce-00000002"
        )
        retried = self.exchange("OPEN", retried_request)
        self.assertEqual(opened["sessionNonce"], retried["sessionNonce"])
        intent = self.exchange("STEP", self.step_request(retried, "intent-bound", 1))
        effect = self.exchange(
            "STEP", self.step_request(intent, "effect-authorized", 2)
        )
        self.assertEqual("effect-authorized", effect["state"])
        with self.assertRaisesRegex(controller.ControllerProtocolError, "outcome is uncertain"):
            self.exchange(
                "OPEN",
                self.open_request(client_nonce="open-client-nonce-00000003"),
            )

    def test_effect_authorized_allows_only_exact_publication_recovery(self) -> None:
        opened = self.exchange("OPEN", self.open_request())
        intent = self.exchange("STEP", self.step_request(opened, "intent-bound", 1))
        effect = self.exchange(
            "STEP", self.step_request(intent, "effect-authorized", 2)
        )
        publication = digest("exact-object-publication-intent")
        inspected = self.exchange(
            "RECOVER",
            self.recovery_request(effect, "inspect", 1),
        )
        self.assertEqual("effect-authorized", inspected["state"])
        self.assertEqual(effect["receiptSha256"], inspected["effectAuthorizationReceiptSha256"])

        authorized = self.exchange(
            "RECOVER",
            self.recovery_request(
                inspected,
                "authorize-publication",
                2,
                publication_intent_sha256=publication,
            ),
        )
        self.assertEqual("publication-recovery-authorized", authorized["state"])
        self.assertEqual(publication, authorized["recoveryPublicationIntentSha256"])

        with self.assertRaises(controller.ControllerProtocolError):
            self.exchange(
                "RECOVER",
                self.recovery_request(
                    authorized,
                    "authorize-publication",
                    3,
                    publication_intent_sha256=digest("different-publication"),
                ),
            )
        with self.assertRaises(controller.ControllerProtocolError):
            self.exchange(
                "STEP",
                self.step_request(
                    authorized,
                    "result-stored",
                    4,
                    result_sha256=digest("must-not-repeat-command"),
                ),
            )

        recovery_result = digest("publication-receipt")
        completed = self.exchange(
            "RECOVER",
            self.recovery_request(
                authorized,
                "complete-publication",
                5,
                publication_intent_sha256=publication,
                recovery_result_sha256=recovery_result,
            ),
        )
        self.assertEqual("publication-recovered", completed["state"])
        self.assertEqual(recovery_result, completed["resultSha256"])
        inspected_completed = self.exchange(
            "RECOVER",
            self.recovery_request(completed, "inspect", 6),
        )
        self.assertEqual("publication-recovered", inspected_completed["state"])
        self.assertEqual(recovery_result, inspected_completed["resultSha256"])
        with self.assertRaisesRegex(
            controller.ControllerProtocolError, "cannot authorize another mutation"
        ):
            self.exchange(
                "RECOVER",
                self.recovery_request(
                    inspected_completed,
                    "authorize-publication",
                    7,
                    publication_intent_sha256=publication,
                ),
            )
        with self.assertRaises(controller.ControllerProtocolError):
            self.exchange(
                "OPEN",
                self.open_request(client_nonce="open-client-nonce-00000100"),
            )

    def test_durable_state_rejects_unknown_fields_and_symlink_substitution(self) -> None:
        opened = self.exchange("OPEN", self.open_request())
        path = controller._state_file(opened["operationId"])
        original = path.read_bytes()
        malformed = json.loads(original)
        malformed["verifierOverride"] = "/tmp/escape"
        path.write_bytes(controller._canonical(malformed))
        path.chmod(0o600)
        with self.assertRaisesRegex(
            controller.ControllerProtocolError, "unknown or missing"
        ):
            self.exchange("STEP", self.step_request(opened, "intent-bound", 1))

        path.write_bytes(original)
        path.chmod(0o600)
        saved = path.with_suffix(".saved")
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaisesRegex(
            controller.ControllerProtocolError, "metadata is unsafe"
        ):
            self.exchange("STEP", self.step_request(opened, "intent-bound", 2))

    def test_protocol_rejects_wrong_peer_unknown_fields_and_result_rebinding(self) -> None:
        request = self.open_request()
        with self.assertRaisesRegex(controller.ControllerProtocolError, "broker UID"):
            controller._serve_packet(
                self.packet("OPEN", request),
                self.config.worker_uid,
                self.config,
                self.key,
            )
        with self.assertRaisesRegex(controller.ControllerProtocolError, "unknown or missing"):
            self.exchange("OPEN", {**request, "endpointOverride": "/tmp/escape"})
        opened = self.exchange("OPEN", request)
        intent = self.exchange("STEP", self.step_request(opened, "intent-bound", 1))
        effect = self.exchange(
            "STEP", self.step_request(intent, "effect-authorized", 2)
        )
        stored = self.exchange(
            "STEP",
            self.step_request(
                effect, "result-stored", 3, result_sha256=digest("result-a")
            ),
        )
        with self.assertRaisesRegex(controller.ControllerProtocolError, "changed the stored result"):
            self.exchange(
                "STEP",
                self.step_request(
                    stored, "completed", 4, result_sha256=digest("result-b")
                ),
            )

    def test_every_action_rejects_wrong_scalar_types_as_protocol_errors(self) -> None:
        opened = self.exchange("OPEN", self.open_request())
        intent = self.exchange("STEP", self.step_request(opened, "intent-bound", 1))
        effect = self.exchange(
            "STEP", self.step_request(intent, "effect-authorized", 2)
        )
        cases = []
        for field in self.open_request():
            cases.append(("OPEN", field, {**self.open_request(client_nonce=f"typed-open-nonce-{len(cases):016d}"), field: True}))
        for field in self.step_request(effect, "result-stored", 9, result_sha256=digest("r")):
            cases.append(("STEP", field, {**self.step_request(effect, "result-stored", len(cases) + 10, result_sha256=digest("r")), field: {}}))
        validation = {
            "operationId": effect["operationId"],
            "validationNonce": "validation-nonce-typed-0001",
            "storedReceiptSha256": effect["receiptSha256"],
            "expectedState": "effect-authorized",
            "expectedResultSha256": None,
        }
        for field in validation:
            cases.append(("VALIDATE", field, {**validation, "validationNonce": f"validation-typed-{len(cases):016d}", field: []}))
        recovery = self.recovery_request(effect, "inspect", 500)
        for field in recovery:
            cases.append(
                (
                    "RECOVER",
                    field,
                    {
                        **recovery,
                        "recoveryNonce": f"recovery-typed-{len(cases):016d}",
                        field: [],
                    },
                )
            )
        for action, field, request in cases:
            with self.subTest(action=action, field=field):
                with self.assertRaises(controller.ControllerProtocolError):
                    self.exchange(action, request)

        outer = {
            "schemaVersion": 1,
            "protocol": controller.PROTOCOL,
            "action": "OPEN",
            "request": self.open_request(client_nonce="typed-outer-nonce-00000001"),
        }
        for field, invalid in (
            ("schemaVersion", True),
            ("protocol", []),
            ("action", []),
            ("request", []),
        ):
            packet = controller._canonical({**outer, field: invalid})
            with self.subTest(action="outer", field=field), self.assertRaises(
                controller.ControllerProtocolError
            ):
                controller._serve_packet(
                    packet, self.config.broker_uid, self.config, self.key
                )

    def test_malformed_connection_is_contained_and_never_receives_success(self) -> None:
        class BadConnection:
            def __init__(self) -> None:
                self.sent = []
                self.closed = False
                self.timeout = None

            def settimeout(self, value):
                self.timeout = value

            def recv(self, _size, *_flags):
                return controller._canonical(
                    {
                        "schemaVersion": 1,
                        "protocol": controller.PROTOCOL,
                        "action": [],
                        "request": {},
                    }
                )

            def sendall(self, value):
                self.sent.append(value)

            def close(self):
                self.closed = True

        connection = BadConnection()
        with mock.patch.object(
            controller, "_peer_credentials", return_value=(1, self.config.broker_uid, 1)
        ):
            controller._serve_connection(connection, self.config, self.key)
        self.assertEqual([], connection.sent)
        self.assertTrue(connection.closed)
        self.assertEqual(controller.CONNECTION_DEADLINE_SECONDS, connection.timeout)

        class IdleConnection(BadConnection):
            def recv(self, _size, *_flags):
                raise TimeoutError("idle client")

        idle = IdleConnection()
        with mock.patch.object(
            controller, "_peer_credentials", return_value=(1, self.config.broker_uid, 1)
        ):
            controller._serve_connection(idle, self.config, self.key)
        self.assertEqual([], idle.sent)
        self.assertTrue(idle.closed)
        self.assertEqual(controller.CONNECTION_DEADLINE_SECONDS, idle.timeout)

        packet = controller._canonical(
            {
                "schemaVersion": 1,
                "protocol": controller.PROTOCOL,
                "action": "OPEN",
                "request": self.open_request(client_nonce="post-idle-client-nonce-0001"),
            }
        )

        class GoodConnection(BadConnection):
            def __init__(self) -> None:
                super().__init__()
                self.reads = 0

            def recv(self, _size, *_flags):
                self.reads += 1
                return packet if self.reads == 1 else b""

        good = GoodConnection()
        with mock.patch.object(
            controller, "_peer_credentials", return_value=(1, self.config.broker_uid, 1)
        ):
            controller._serve_connection(good, self.config, self.key)
        self.assertEqual(1, len(good.sent))
        self.assertEqual("accepted", json.loads(good.sent[0])["state"])
        self.assertTrue(good.closed)

    def test_serve_preflight_observes_exact_root_owned_artifacts(self) -> None:
        live_module = Path(controller.__file__)
        live_module_bytes = live_module.read_bytes()
        values = {
            self.config.runtime_manifest_path: b"runtime-manifest-bytes",
            self.config.schema_path: b"schema-bytes",
            self.config.native_boundary_manifest_path: (
                ROOT / "runtime/beads-native-boundary-v27.example.json"
            ).read_bytes(),
            live_module: live_module_bytes,
            self.config.native_module_path: self.config.native_module_path.read_bytes(),
        }
        config = controller.dataclasses.replace(
            self.config,
            module_path=live_module,
            runtime_manifest_sha256=controller._sha(values[self.config.runtime_manifest_path]),
            module_sha256=controller._sha(live_module_bytes),
            schema_sha256=controller._sha(values[self.config.schema_path]),
            native_boundary_manifest_sha256=controller._sha(
                values[self.config.native_boundary_manifest_path]
            ),
            native_module_sha256=controller._sha(
                values[self.config.native_module_path]
            ),
        )
        with mock.patch.object(
            controller,
            "_read_root_owned",
            side_effect=lambda path, _label, **_kwargs: values[path],
        ) as observed:
            controller._verify_installed_artifacts(config)
        self.assertEqual(5, observed.call_count)

        with mock.patch.object(
            controller,
            "_read_root_owned",
            side_effect=lambda path, _label, **_kwargs: values[path] + b"tampered",
        ):
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "installed artifact digest"
            ):
                controller._verify_installed_artifacts(config)

    def test_enabled_preflight_binds_native_assets_and_fixed_platform_gate(self) -> None:
        manifest_value = json.loads(
            (ROOT / "runtime/beads-native-boundary-v27.example.json").read_bytes()
        )
        manifest_value["launcherSha256"] = controller._sha(b"launcher")
        manifest_value["supervisorSha256"] = controller._sha(b"supervisor")
        manifest_value["ociRuntimeSha256"] = controller._sha(b"crun")
        manifest = controller.native_boundary_v27.parse_native_boundary_manifest_v27(
            manifest_value
        )
        assets = {
            manifest.launcher_path: b"launcher",
            manifest.supervisor_path: b"supervisor",
            manifest.podman_path: b"podman",
            manifest.conmon_path: b"conmon",
            manifest.oci_runtime_path: b"crun",
        }
        with mock.patch.object(
            controller,
            "_read_root_owned",
            side_effect=lambda path, _label, **_kwargs: assets[path],
        ) as observed, mock.patch.object(
            controller.native_boundary_v27, "verify_local_platform_gate_v27"
        ) as platform_gate:
            controller._verify_native_platform_gate(manifest)
        self.assertEqual(5, observed.call_count)
        platform_gate.assert_called_once_with(manifest, expected_worker_uid=None)

        assets[manifest.podman_path] = b"tampered"
        with mock.patch.object(
            controller,
            "_read_root_owned",
            side_effect=lambda path, _label, **_kwargs: assets[path],
        ), mock.patch.object(
            controller.native_boundary_v27, "verify_local_platform_gate_v27"
        ) as platform_gate:
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "native Podman"
            ):
                controller._verify_native_platform_gate(manifest)
        platform_gate.assert_not_called()

        assets[manifest.podman_path] = b"podman"
        assets[manifest.oci_runtime_path] = b"tampered"
        with mock.patch.object(
            controller,
            "_read_root_owned",
            side_effect=lambda path, _label, **_kwargs: assets[path],
        ), mock.patch.object(
            controller.native_boundary_v27, "verify_local_platform_gate_v27"
        ) as platform_gate:
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "native OCI runtime"
            ):
                controller._verify_native_platform_gate(manifest)
        platform_gate.assert_not_called()

    def test_execute_uses_only_worker_runner_and_durable_done_result(self) -> None:
        opened = self.exchange("OPEN", self.open_request())
        intent = self.exchange("STEP", self.step_request(opened, "intent-bound", 1))
        effect = self.exchange(
            "STEP", self.step_request(intent, "effect-authorized", 2)
        )
        manifest = controller.native_boundary_v27.parse_native_boundary_manifest_v27(
            json.loads(
                (ROOT / "runtime/beads-native-boundary-v27.example.json").read_bytes()
            )
        )
        repository = Path(self.temporary.name).resolve() / "repository-1"
        beads = repository / ".beads"
        beads.mkdir(parents=True)
        (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
        plan = controller.native_boundary_v27.reference_supervised_effect_plan_v27(
            manifest,
            operation_id=effect["operationId"],
            operation_class="ordinary",
            argv=["/usr/local/bin/bd", "update", "task-1", "--json"],
            repository_path=str(repository),
        )
        calls = []
        reads = reader_outputs()

        def worker_runner(_manifest, observed):
            calls.append(observed["stagePlanSha256"])
            stage_key = observed["stageKey"]
            stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
            if stage_key.startswith("reader-"):
                stdout = reads[int(stage_key.split("-")[1])]
            result = {
                "exitCode": 0,
                "placementMask": 63,
                "stdout": stdout,
                "stderr": b"",
                "lifecycle": [
                    "create",
                    "init",
                    "start-attach",
                    "terminal",
                    "cleanup",
                    "rm",
                ],
                "resultKind": "success",
                "resultPredecessorKind": "creator-lifetime-closed-positive",
                "failureEvidenceSha256": None,
            }
            handler = (
                controller.native_boundary_v27._NATIVE_OUTER_EVENT_HANDLER_V27.get()
            )
            for sequence, event in enumerate(
                controller.native_boundary_v27._SUCCESS_NATIVE_EVENTS_V27, 1
            ):
                evidence = digest(
                    f"{observed['stagePlanSha256']}:{sequence}:{event}"
                )
                handler(
                    event, "before", evidence,
                    controller.native_boundary_v27._reference_native_event_observation_v27(
                        event, "before"
                    ),
                )
                handler(
                    event, "after", evidence,
                    controller.native_boundary_v27._reference_native_event_observation_v27(
                        event, "after"
                    ),
                )
            observation = controller.native_boundary_v27._decode_native_stage_result_v27(
                result, require_discriminants=True
            )
            handler.authorize_result_offer(observation)
            handler.receipt_result_handoff(observation)
            handler.terminalize_result_handoff(
                {
                    "schemaVersion": 27,
                    "visibleDescendants": 6,
                    "placementMask": 63,
                    "controllerTrackedPlacementMask": 63,
                    "initControllers": [],
                    "preRemovalCgroupStat": {
                        "nr_descendants": 6,
                        "nr_dying_descendants": 0,
                    },
                    "terminalCgroupStat": {
                        "nr_descendants": 0,
                        "nr_dying_descendants": 0,
                    },
                }
            )
            return result

        request = {
            "operationId": effect["operationId"],
            "sessionNonce": effect["sessionNonce"],
            "executionNonce": "execute-native-worker-nonce-0001",
            "predecessorReceiptSha256": effect["receiptSha256"],
            "authorizationRecordSha256": digest("protected-authorization"),
        }
        with mock.patch.object(
            controller, "_verify_installed_artifacts", return_value=manifest
        ), mock.patch.object(
            controller, "_verify_native_platform_gate"
        ) as platform:
            result = json.loads(
                controller._serve_packet(
                    self.packet("EXECUTE", request),
                    self.config.broker_uid,
                    self.config,
                    self.key,
                    supervisor_runner=worker_runner,
                    authority_loader=lambda *_args: plan,
                )
            )
            repeated = json.loads(
                controller._serve_packet(
                    self.packet(
                        "EXECUTE",
                        {
                            **request,
                            "executionNonce": "execute-native-worker-nonce-0002",
                        },
                    ),
                    self.config.broker_uid,
                    self.config,
                    self.key,
                    supervisor_runner=worker_runner,
                    authority_loader=lambda *_args: plan,
                )
            )
        self.assertEqual(result["nativeResult"], repeated["nativeResult"])
        self.assertEqual(5, len(calls))
        self.assertEqual(5, len(set(calls)))
        self.assertEqual(2, platform.call_count)
        for call in platform.call_args_list:
            self.assertEqual(mock.call(manifest, run_probe=False), call)

    def test_execute_request_has_no_caller_plan_and_controller_derives_authority(self) -> None:
        self.assertNotIn("plan", controller._EXECUTE_FIELDS)
        self.assertIn("authorizationRecordSha256", controller._EXECUTE_FIELDS)
        source = Path(controller.__file__).read_text()
        self.assertIn("_derive_protected_effect_authority_v27", source)
        self.assertNotIn('execution["plan"]', source)

    def test_worker_protocol_authenticates_post_drop_packets_and_rechecks_lifecycle(self) -> None:
        source = Path(controller.__file__).read_text()
        self.assertIn("SCM_CREDENTIALS", source)
        self.assertIn("SO_PASSCRED", source)
        self.assertIn("pidfd_open", source)
        worker = source.index("def _worker_main_v27")
        drop = source.index("_drop_to_worker_identity_v27(config)", worker)
        death = source.index("_set_worker_parent_death_v27(parent_pid)", worker)
        label = source.index("_verify_worker_result_root_label_v27(config)", worker)
        ready = source.index('"status": "ready"', worker)
        self.assertLess(drop, death)
        self.assertLess(death, label)
        self.assertLess(label, ready)
        self.assertGreaterEqual(
            source.count("_verify_worker_result_root_label_v27(config)", worker),
            2,
        )
        execute = source.index("def execute(", source.index("class _WorkerChannelV27"))
        publish = source.index("return result", execute)
        final_check = source.rindex("lifecycle_check()", execute, publish)
        receive = source.index("_recv_credentialed_packet_v27(", execute, publish)
        self.assertGreater(final_check, receive)

    def test_operator_disable_cas_precedes_native_revoke_and_late_cutoff_fences(self) -> None:
        plan = {"stagePlanSha256": digest("disable-stage-plan")}
        disabled = {
            "operatorState": "disabled",
            "authenticatedOperatorState": "disabled",
            "configEnabled": True,
            "generation": 9,
        }

        def candidate(event: str, phase: str, sequence: int = 1):
            observation = (
                controller.native_boundary_v27._reference_native_event_observation_v27(
                    event, phase
                )
            )
            return {
                "event": event,
                "phase": phase,
                "sequence": sequence,
                "eventObservation": observation,
                "eventEvidenceSha256": (
                    controller.native_boundary_v27._native_event_evidence_v27(
                        stage_plan_sha256=plan["stagePlanSha256"],
                        sequence=sequence,
                        event=event,
                        phase=phase,
                        observation=observation,
                    )
                ),
            }

        calls: list[tuple[str, str, str, dict]] = []

        def authorize(
            event: str, phase: str, evidence: str, observation: dict
        ) -> str:
            calls.append((event, phase, evidence, observation))
            return digest(f"authority:{len(calls)}:{event}:{phase}")

        authority, action, revoke_authority, delivered = (
            controller._mediate_native_event_authority_v27(
                candidate("native-creator-created", "after"),
                plan,
                authorize,
                revocation_observation=disabled,
                revoke_delivered=False,
            )
        )
        self.assertEqual(
            [("native-creator-created", "after"), ("revoke-decision", "before")],
            [(event, phase) for event, phase, _evidence, _observation in calls],
        )
        self.assertEqual("revoke", action)
        self.assertTrue(delivered)
        self.assertEqual(authority, digest("authority:1:native-creator-created:after"))
        self.assertEqual(
            revoke_authority, digest("authority:2:revoke-decision:before")
        )

        calls.clear()
        authority, action, revoke_authority, delivered = (
            controller._mediate_native_event_authority_v27(
                candidate("release-consumed-current", "before"),
                plan,
                authorize,
                revocation_observation=disabled,
                revoke_delivered=False,
            )
        )
        self.assertEqual(
            [("revoke-decision", "before")],
            [(event, phase) for event, phase, _evidence, _observation in calls],
        )
        self.assertEqual(("revoke", revoke_authority, True), (
            action, authority, delivered
        ))

        with self.assertRaisesRegex(
            controller.ControllerProtocolError, "crossed the no-effect revoke cutoff"
        ):
            controller._mediate_native_event_authority_v27(
                candidate("signal-attempt-consumed", "before"),
                plan,
                authorize,
                revocation_observation=disabled,
                revoke_delivered=False,
            )

    def test_controller_places_paused_worker_in_exact_worker_leaf_below_empty_supervisor(self) -> None:
        cgroup_root = Path(self.temporary.name) / "cgroup"
        proc_root = Path(self.temporary.name) / "proc"
        controller_group = cgroup_root / "system.slice/example.service/controller"
        supervisor_group = controller_group.parent / "supervisor"
        controller_group.mkdir(parents=True)
        supervisor_group.mkdir()
        (supervisor_group / "cgroup.procs").write_bytes(b"")
        (supervisor_group / "cgroup.controllers").write_bytes(b"cpu memory pids\n")
        (supervisor_group / "cgroup.subtree_control").write_bytes(b"")
        worker_group = supervisor_group / "worker"
        worker_group.mkdir(mode=0o700)
        worker_group.chmod(0o700)
        (worker_group / "cgroup.procs").write_bytes(b"")
        (worker_group / "cgroup.stat").write_bytes(
            b"nr_descendants 0\nnr_dying_descendants 0\n"
        )
        (proc_root / "self").mkdir(parents=True)
        (proc_root / "self/cgroup").write_bytes(
            b"0::/system.slice/example.service/controller\n"
        )
        worker_pid = 4242
        controller_uid = os.geteuid()
        worker_uid = controller_uid + 1
        worker_gid = os.getegid()
        (proc_root / str(worker_pid)).mkdir()
        (proc_root / str(worker_pid) / "cgroup").write_bytes(
            b"0::/system.slice/example.service/supervisor/worker\n"
        )

        with mock.patch.object(controller, "_assert_worker_pidfd_identity_v27"), mock.patch.object(
            controller, "_enable_exact_subtree_controllers_v27"
        ) as enable, mock.patch.object(controller.os, "geteuid", return_value=0):
            descriptor, supervisor_procs, worker_descriptor, worker_procs, relative, recovered = (
                controller._move_worker_to_supervisor_cgroup_v27(
                    worker_pid,
                    worker_pidfd=-1,
                    worker_start_time="7",
                    controller_uid=controller_uid,
                    worker_uid=worker_uid,
                    worker_gid=worker_gid,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root,
                    cgroup2_observer=proved_fake_cgroup2,
                    cgroup_mode_observer=proved_fake_setgid_mode,
                )
            )
        os.close(worker_procs)
        os.close(worker_descriptor)
        os.close(supervisor_procs)
        os.close(descriptor)
        self.assertEqual({}, recovered)

        self.assertEqual(b"", (supervisor_group / "cgroup.procs").read_bytes())
        self.assertEqual(b"4242\n", (worker_group / "cgroup.procs").read_bytes())
        enable.assert_called_once()
        self.assertEqual(
            "/system.slice/example.service/supervisor/worker", relative
        )
        supervisor_process = supervisor_group / "cgroup.procs"
        self.assertFalse(stat.S_IMODE(supervisor_process.stat().st_mode) & 0o022)
        self.assertNotEqual(worker_uid, supervisor_process.stat().st_uid)
        self.assertEqual(controller_uid, supervisor_process.stat().st_uid)
        self.assertEqual(worker_gid, supervisor_process.stat().st_gid)
        self.assertEqual(0o600, stat.S_IMODE(supervisor_process.stat().st_mode))
        self.assertTrue(worker_group.is_dir())
        self.assertEqual(
            controller._SUPERVISOR_CGROUP_MODE_V27,
            stat.S_IMODE(supervisor_group.stat().st_mode) | stat.S_ISGID,
        )

    def test_supervisor_process_control_is_retained_and_worker_denied(self) -> None:
        control = Path(self.temporary.name) / "supervisor.procs"
        control.write_bytes(b"")
        control.chmod(0o600)
        descriptor = os.open(control, os.O_WRONLY)
        try:
            controller._validate_supervisor_process_control_v27(
                descriptor, worker_uid=os.geteuid() + 1
            )
            control.chmod(0o620)
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "worker-denied"
            ):
                controller._validate_supervisor_process_control_v27(
                    descriptor, worker_uid=os.geteuid() + 1
                )
            control.chmod(0o600)
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "worker-denied"
            ):
                controller._validate_supervisor_process_control_v27(
                    descriptor, worker_uid=os.geteuid()
                )
        finally:
            os.close(descriptor)

    def test_controller_retirement_receipt_joins_all_masks_and_retains_dying(self) -> None:
        result = {
            "exitCode": 0,
            "placementMask": 63,
            "stdout": b"{}",
            "stderr": b"",
            "lifecycle": [
                "create", "init", "start-attach", "terminal", "cleanup", "rm"
            ],
            "controllerRetirement": {
                "schemaVersion": 27,
                "visibleDescendants": 8,
                "placementMask": 63,
                "controllerTrackedPlacementMask": 63,
                "initControllers": ["cpu", "memory", "pids"],
                "preRemovalCgroupStat": {
                    "nr_descendants": 8,
                    "nr_dying_descendants": 2,
                    "nr_dying_subsys_memory": 1,
                    "nr_subsys_memory": 3,
                },
                "terminalCgroupStat": {
                    "nr_descendants": 0,
                    "nr_dying_descendants": 3,
                    "nr_dying_subsys_memory": 2,
                    "nr_subsys_memory": 1,
                },
            },
        }
        decoded = controller.native_boundary_v27._decode_native_stage_result_v27(
            result
        )
        self.assertEqual(
            2,
            decoded["controllerRetirement"]["preRemovalCgroupStat"][
                "nr_dying_descendants"
            ],
        )
        for field in ("placementMask", "controllerTrackedPlacementMask"):
            hostile = json.loads(json.dumps({
                **result,
                "stdout": None,
                "stderr": None,
            }))
            hostile["stdout"] = b"{}"
            hostile["stderr"] = b""
            hostile["controllerRetirement"][field] = 31
            with self.subTest(field=field), self.assertRaisesRegex(
                controller.native_boundary_v27.NativeBoundaryV27Error,
                "retirement receipt",
            ):
                controller.native_boundary_v27._decode_native_stage_result_v27(
                    hostile
                )

    def test_retirement_intent_admits_every_deterministic_terminal_mask_suffix(self) -> None:
        terminal_masks = sorted(
            controller.native_boundary_v27._LIFECYCLE_TERMINAL_MASKS_V27
        )

        def fixture(mask: int, sequence: int):
            payload = Path(self.temporary.name) / f"retirement-{mask}-{sequence}"
            payload.mkdir(mode=0o710)
            payload.chmod(0o710)
            for ordinal in range(6):
                if not mask & (1 << ordinal):
                    continue
                leaf = payload / f"lifecycle-{ordinal}"
                leaf.mkdir(mode=0o770)
                leaf.chmod(0o770)
                for control in (
                    "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"
                ):
                    value = (
                        b"cpu memory pids\n"
                        if control == "cgroup.subtree_control"
                        and ordinal == 1 and mask == 63
                        else b""
                    )
                    (leaf / control).write_bytes(value)
                    (leaf / control).chmod(0o660)
                if ordinal == 1 and mask == 63:
                    for name, mode in (
                        ("runtime", 0o750),
                        ("libpod-payload-" + "a" * 64, 0o755),
                    ):
                        child = leaf / name
                        child.mkdir(mode=mode)
                        child.chmod(mode)
                        (child / "cgroup.events").write_bytes(b"populated 0\n")
            stat_path = payload / "cgroup.stat"

            def update_stat() -> None:
                visible = sum(
                    item.is_dir() for item in payload.rglob("*")
                )
                stat_path.write_bytes(
                    f"nr_descendants {visible}\nnr_dying_descendants 0\n".encode()
                )

            update_stat()
            return payload, stat_path, update_stat

        sequence = 0
        for mask in terminal_masks:
            probe, _stat, _update = fixture(mask, sequence)
            sequence += 1
            probe_fd = os.open(probe, os.O_RDONLY | os.O_DIRECTORY)
            captured: list[dict[str, object]] = []
            real_rmdir = os.rmdir

            def remove_probe(name: str, *, dir_fd: int) -> None:
                observed = os.fstat(dir_fd)
                parent = probe
                lifecycle_one = probe / "lifecycle-1"
                if lifecycle_one.exists():
                    candidate = lifecycle_one.stat()
                    if (observed.st_dev, observed.st_ino) == (
                        candidate.st_dev, candidate.st_ino
                    ):
                        parent = lifecycle_one
                target = parent / name
                for entry in tuple(target.iterdir()):
                    if entry.is_file():
                        entry.unlink()
                real_rmdir(name, dir_fd=dir_fd)
                _update()

            try:
                with mock.patch.object(controller.os, "rmdir", side_effect=remove_probe):
                    controller._retire_lifecycle_cgroups_v27(
                        probe_fd,
                        controller_uid=os.geteuid(),
                        worker_uid=os.geteuid(),
                        worker_gid=os.getegid(),
                        cgroup2_observer=proved_fake_cgroup2,
                        cgroup_mode_observer=proved_fake_setgid_mode,
                        persist_intent=lambda value: captured.append(dict(value)),
                    )
            finally:
                os.close(probe_fd)
            self.assertEqual(1, len(captured))
            removal_count = len(captured[0]["removalPlan"])
            (probe / "cgroup.stat").unlink()
            probe.rmdir()

            for crash_after in range(removal_count):
                with self.subTest(mask=mask, crash_after=crash_after):
                    payload, _stat_path, update_stat = fixture(mask, sequence)
                    sequence += 1
                    payload_fd = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
                    captured = []
                    removed = 0

                    def remove(name: str, *, dir_fd: int) -> None:
                        nonlocal removed
                        observed = os.fstat(dir_fd)
                        parent = payload
                        lifecycle_one = payload / "lifecycle-1"
                        if lifecycle_one.exists():
                            candidate = lifecycle_one.stat()
                            if (observed.st_dev, observed.st_ino) == (
                                candidate.st_dev, candidate.st_ino
                            ):
                                parent = lifecycle_one
                        target = parent / name
                        for entry in tuple(target.iterdir()):
                            if entry.is_file():
                                entry.unlink()
                        real_rmdir(name, dir_fd=dir_fd)
                        removed += 1
                        update_stat()

                    def crash(phase: str) -> None:
                        if phase.startswith("retirement-remove-") and removed == crash_after + 1:
                            raise SystemExit(phase)

                    try:
                        with self.assertRaises(SystemExit), mock.patch.object(
                            controller.os, "rmdir", side_effect=remove
                        ):
                            controller._retire_lifecycle_cgroups_v27(
                                payload_fd,
                                controller_uid=os.geteuid(),
                                worker_uid=os.geteuid(),
                                worker_gid=os.getegid(),
                                cgroup2_observer=proved_fake_cgroup2,
                                cgroup_mode_observer=proved_fake_setgid_mode,
                                persist_intent=lambda value: captured.append(dict(value)),
                                phase_hook=crash,
                            )
                    finally:
                        os.close(payload_fd)
                    self.assertEqual(1, len(captured))
                    payload_fd = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with mock.patch.object(
                            controller.os, "rmdir", side_effect=remove
                        ):
                            receipt = controller._retire_lifecycle_cgroups_v27(
                                payload_fd,
                                controller_uid=os.geteuid(),
                                worker_uid=os.geteuid(),
                                worker_gid=os.getegid(),
                                cgroup2_observer=proved_fake_cgroup2,
                                cgroup_mode_observer=proved_fake_setgid_mode,
                                retirement_intent=captured[0],
                            )
                    finally:
                        os.close(payload_fd)
                    self.assertEqual(mask, receipt["placementMask"])
                    self.assertEqual(removal_count, receipt["visibleDescendants"])
                    (payload / "cgroup.stat").unlink()
                    payload.rmdir()

    def test_retirement_artifact_atomic_install_recovers_only_exact_temp_prefix(self) -> None:
        root = Path(self.temporary.name) / "retirement-artifact"
        root.mkdir(mode=0o700)
        raw = controller._canonical({"schemaVersion": 27, "value": "x" * 64})
        phases = (
            "controller-retirement.json:temp-created-unnormalized",
            "controller-retirement.json:temp-created",
            "controller-retirement.json:bytes-written",
            "controller-retirement.json:file-fsynced",
            "controller-retirement.json:installed",
            "controller-retirement.json:temporary-unlinked",
            "controller-retirement.json:directory-fsynced",
        )
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                target = root / f"case-{index}"
                target.mkdir(mode=0o700)
                descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(SystemExit):
                        controller.native_boundary_v27._persist_atomic_retirement_artifact_v27(
                            descriptor,
                            "controller-retirement.json",
                            raw,
                            owner_uid=os.geteuid(),
                            owner_gid=os.getegid(),
                            phase_hook=lambda observed: (
                                (_ for _ in ()).throw(SystemExit(observed))
                                if observed == phase else None
                            ),
                        )
                    controller.native_boundary_v27._persist_atomic_retirement_artifact_v27(
                        descriptor,
                        "controller-retirement.json",
                        raw,
                        owner_uid=os.geteuid(),
                        owner_gid=os.getegid(),
                    )
                finally:
                    os.close(descriptor)
                self.assertEqual(raw, (target / "controller-retirement.json").read_bytes())

        hostile = root / "hostile"
        hostile.mkdir(mode=0o700)
        (hostile / ".controller-retirement.json.tmp").write_bytes(b"not-prefix")
        (hostile / ".controller-retirement.json.tmp").chmod(0o600)
        descriptor = os.open(hostile, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(
                controller.native_boundary_v27.NativeBoundaryV27Error,
                "not an exact prefix",
            ):
                controller.native_boundary_v27._persist_atomic_retirement_artifact_v27(
                    descriptor,
                    "controller-retirement.json",
                    raw,
                    owner_uid=os.geteuid(),
                    owner_gid=os.getegid(),
                )
        finally:
            os.close(descriptor)
        self.assertEqual(
            b"not-prefix",
            (hostile / ".controller-retirement.json.tmp").read_bytes(),
        )

    def test_supervisor_common_ancestor_control_repairs_only_exact_bootstrap_states(self) -> None:
        root = Path(self.temporary.name) / "supervisor-process-control"
        root.mkdir()
        control = root / "cgroup.procs"
        control.write_bytes(b"")
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        controller_uid = os.geteuid()
        worker_uid = controller_uid + 1
        worker_gid = os.getegid()
        try:
            control.chmod(0o644)
            with mock.patch.object(controller.os, "geteuid", return_value=0):
                descriptor = controller._prepare_supervisor_process_control_v27(
                    root_fd,
                    controller_uid=controller_uid,
                    worker_uid=worker_uid,
                    worker_gid=worker_gid,
                    cgroup2_observer=proved_fake_cgroup2,
                )
            try:
                self.assertEqual(0o600, stat.S_IMODE(os.fstat(descriptor).st_mode))
                self.assertEqual(controller_uid, os.fstat(descriptor).st_uid)
                self.assertEqual(worker_gid, os.fstat(descriptor).st_gid)
                self.assertEqual(os.O_WRONLY, fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE)
            finally:
                os.close(descriptor)

            for mode in (0o620, 0o660, 0o666):
                with self.subTest(mode=oct(mode)):
                    control.chmod(mode)
                    with self.assertRaisesRegex(
                        controller.ControllerProtocolError, "substituted owner or mode"
                    ):
                        controller._prepare_supervisor_process_control_v27(
                            root_fd,
                            controller_uid=controller_uid,
                            worker_uid=worker_uid,
                            worker_gid=worker_gid,
                            cgroup2_observer=proved_fake_cgroup2,
                        )
            control.chmod(0o600)
        finally:
            os.close(root_fd)

    def test_worker_leaf_root_half_state_is_exact_and_substitutions_are_preserved(self) -> None:
        controller_uid = 991
        worker_gid = 993
        root_half = types.SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o2700,
            st_uid=0,
            st_gid=worker_gid,
        )
        final = types.SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=controller_uid,
            st_gid=worker_gid,
        )
        with mock.patch.object(
            controller, "_observed_cgroup_mode_v27", side_effect=(0o2700, 0o700)
        ), mock.patch.object(
            controller.os, "geteuid", return_value=0
        ), mock.patch.object(
            controller.os, "fchown"
        ) as fchown, mock.patch.object(
            controller.os, "fchmod"
        ) as fchmod, mock.patch.object(
            controller.os, "fstat", return_value=final
        ):
            observed = controller._normalize_worker_cgroup_owner_v27(
                17,
                root_half,
                controller_uid=controller_uid,
                worker_gid=worker_gid,
            )
        self.assertIs(final, observed)
        fchown.assert_called_once_with(17, controller_uid, worker_gid)
        fchmod.assert_called_once_with(17, 0o700)

        for metadata, observed_mode, error in (
            (
                types.SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o2700, st_uid=0, st_gid=81_004
                ),
                0o2700,
                "substituted worker state",
            ),
            (
                types.SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o777, st_uid=0, st_gid=worker_gid
                ),
                0o777,
                "half-state is unsafe",
            ),
        ):
            with self.subTest(error=error), mock.patch.object(
                controller, "_observed_cgroup_mode_v27", return_value=observed_mode
            ), mock.patch.object(
                controller.os, "geteuid", return_value=0
            ), mock.patch.object(
                controller.os, "fchown"
            ) as hostile_chown, self.assertRaisesRegex(
                controller.ControllerProtocolError, error
            ):
                controller._normalize_worker_cgroup_owner_v27(
                    17,
                    metadata,
                    controller_uid=controller_uid,
                    worker_gid=worker_gid,
                )
            hostile_chown.assert_not_called()

    def test_native_disposition_and_fd10_are_durable_before_terminal_channel_send(self) -> None:
        source = (
            ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c"
        ).read_text()
        execute = source[source.index("static int execute_plan(void)") :]
        self.assertIn("persist_loss_disposition(&plan);", execute)
        publish = source[
            source.index("static int publish_authenticated_stage_result(") :
            source.index("static int native_event_pair(")
        ]
        result = publish.index("persist_authenticated_result(")
        terminal = publish.index('"CONTROL-DONE %u\\n"')
        self.assertLess(result, terminal)
        controller_source = Path(controller.__file__).read_text()
        self.assertIn("class _WorkerStageRunnerV27", controller_source)
        self.assertIn("def recover(", controller_source)
        self.assertIn("recover_durable_native_stage_result_v27", controller_source)
        native_source = Path(controller.native_boundary_v27.__file__).read_text()
        self.assertNotIn(
            "_reopen_controller_retirement_receipt_v27", native_source
        )
        worker_recover = controller_source[
            controller_source.index(
                "    def recover(", controller_source.index("class _WorkerChannelV27")
            ) : controller_source.index(
                "    def terminate(", controller_source.index("class _WorkerChannelV27")
            )
        ]
        runner_recover = controller_source[
            controller_source.index(
                "    def recover(", controller_source.index("class _WorkerStageRunnerV27")
            ) : controller_source.index(
                "def _move_worker_to_supervisor_cgroup_v27"
            )
        ]
        self.assertNotIn("_decode_controller_retirement_v27", worker_recover)
        self.assertIn("_verify_controller_retirement_chain_v27", runner_recover)

    def test_result_offer_is_digest_only_and_worker_blocks_before_final_packet(self) -> None:
        request_key = b"offer-request-key-material-32-byt"
        plan_sha256 = digest("result-offer-stage")
        result = {
            "exitCode": 0,
            "placementMask": 63,
            "stdout": b"credentialed-result-bytes",
            "stderr": b"",
            "lifecycle": list(controller.native_boundary_v27._EFFECT_LIFECYCLE),
            "resultKind": "success",
            "resultPredecessorKind": "creator-lifetime-closed-positive",
            "failureEvidenceSha256": None,
        }
        offer = json.loads(
            controller._worker_result_offer_packet_v27(
                plan_sha256, result, request_key
            )
        )
        self.assertNotIn("nativeStageObservation", offer)
        self.assertNotIn("stdoutBase64", offer)
        self.assertEqual(
            {
                "schemaVersion", "protocol", "status", "stagePlanSha256",
                "nativeResultSha256", "resultKind", "resultPredecessorKind",
                "failureEvidenceSha256", "placementMask", "offerHmac",
            },
            set(offer),
        )
        acknowledgement = json.loads(
            controller._worker_result_offer_ack_v27(
                plan_sha256=plan_sha256,
                native_result_sha256=offer["nativeResultSha256"],
                authorization_record_sha256=digest("offer-authorization"),
                request_key=request_key,
            )
        )
        self.assertEqual("ACK-RESULT-OFFER", acknowledgement["action"])
        source = Path(controller.__file__).read_text()
        worker = source[
            source.index("def _worker_main_v27(") :
            source.index("class _WorkerChannelV27")
        ]
        mediator = worker[
            worker.index("def result_offer_mediator(") :
            worker.index("def event_mediator(")
        ]
        offer_send = mediator.index("channel.send(encoded)")
        ack_receive = mediator.index(
            'label="native result-offer authorization"', offer_send
        )
        self.assertLess(offer_send, ack_receive)
        run_native = worker.index("run_native_stage_action_v27(")
        final_send = worker.index("_worker_result_packet_v27(", run_native)
        self.assertLess(run_native, final_send)
        supervisor = (
            ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c"
        ).read_text()
        result_function = supervisor[
            supervisor.index("static int publish_authenticated_stage_result(") :
            supervisor.index("static int native_event_pair(")
        ]
        native_offer = result_function.index("V27 result offer send failed")
        durable_fd10 = result_function.index("persist_authenticated_result(")
        control_done = result_function.index('"CONTROL-DONE %u\\n"')
        final_stdout = result_function.index("write_all_fd(STDOUT_FILENO")
        self.assertLess(native_offer, durable_fd10)
        self.assertLess(durable_fd10, control_done)
        self.assertLess(control_done, final_stdout)

    def test_subtree_controller_enablement_is_empty_exact_and_read_back(self) -> None:
        root = Path(self.temporary.name) / "controller-enable"
        root.mkdir()
        (root / "cgroup.procs").write_bytes(b"")
        (root / "cgroup.controllers").write_bytes(b"cpu memory pids\n")
        (root / "cgroup.subtree_control").write_bytes(b"")
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch.object(
                controller,
                "_read_cgroup_tokens_v27",
                side_effect=[("cpu", "memory", "pids"), (), ("cpu", "memory", "pids")],
            ):
                controller._enable_exact_subtree_controllers_v27(descriptor)
            self.assertEqual(
                b"+cpu +memory +pids\n",
                (root / "cgroup.subtree_control").read_bytes(),
            )
            with mock.patch.object(
                controller,
                "_read_cgroup_tokens_v27",
                side_effect=[("cpu", "memory", "pids"), ("io",)],
            ), self.assertRaisesRegex(
                controller.ControllerProtocolError, "extra enabled controller"
            ):
                controller._enable_exact_subtree_controllers_v27(descriptor)
            (root / "cgroup.procs").write_bytes(b"991\n")
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "internal process"
            ):
                controller._enable_exact_subtree_controllers_v27(descriptor)
        finally:
            os.close(descriptor)

    def test_lifecycle_recovery_accepts_only_l1_split_siblings_and_retains_dying(self) -> None:
        payload = Path(self.temporary.name) / "payload-lifecycle"
        payload.mkdir(mode=0o2710)
        payload.chmod(0o2710)
        leaves = []
        for ordinal in range(6):
            leaf = payload / f"lifecycle-{ordinal}"
            leaf.mkdir(mode=0o770)
            leaf.chmod(0o770)
            for control in (
                "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"
            ):
                (leaf / control).write_bytes(
                    b"cpu memory pids\n"
                    if control == "cgroup.subtree_control" and ordinal == 1
                    else b""
                )
                (leaf / control).chmod(0o660)
            leaves.append(leaf)
        runtime = leaves[1] / "runtime"
        runtime.mkdir(mode=0o750)
        runtime.chmod(0o750)
        nested = leaves[1] / ("libpod-payload-" + "a" * 64)
        nested.mkdir(mode=0o755)
        nested.chmod(0o755)
        (payload / "cgroup.stat").write_bytes(
            b"nr_descendants 8\nnr_dying_descendants 0\n"
        )
        descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
        real_rmdir = os.rmdir

        def retire_fake_cgroup(name: str, *, dir_fd: int) -> None:
            identity = (os.fstat(dir_fd).st_dev, os.fstat(dir_fd).st_ino)
            candidates = [payload, *leaves, runtime, nested]
            parent = next(
                item for item in candidates
                if item.exists() and (item.stat().st_dev, item.stat().st_ino) == identity
            )
            target = parent / name
            for entry in tuple(target.iterdir()):
                if entry.is_file():
                    entry.unlink()
            real_rmdir(name, dir_fd=dir_fd)
        try:
            with mock.patch.object(
                controller,
                "_read_cgroup_stat_v27",
                side_effect=[
                    {"nr_descendants": 8, "nr_dying_descendants": 0},
                    {"nr_descendants": 0, "nr_dying_descendants": 3},
                ],
            ), mock.patch.object(
                controller.os, "rmdir", side_effect=retire_fake_cgroup
            ):
                receipt = controller._retire_lifecycle_cgroups_v27(
                    descriptor,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                    cgroup_mode_observer=proved_fake_setgid_mode,
                )
            self.assertEqual(8, receipt["visibleDescendants"])
            self.assertEqual(63, receipt["placementMask"])
            self.assertEqual(
                ["cpu", "memory", "pids"], receipt["initControllers"]
            )
            self.assertEqual(0, receipt["preRemovalCgroupStat"]["nr_dying_descendants"])
            self.assertEqual(3, receipt["terminalCgroupStat"]["nr_dying_descendants"])
            self.assertEqual([], [item.name for item in payload.iterdir() if item.is_dir()])
        finally:
            os.close(descriptor)

    def test_lifecycle_recovery_rejects_split_descendant_outside_l1(self) -> None:
        payload = Path(self.temporary.name) / "payload-hostile-lifecycle"
        payload.mkdir(mode=0o2710)
        payload.chmod(0o2710)
        leaf = payload / "lifecycle-0"
        leaf.mkdir(mode=0o770)
        leaf.chmod(0o770)
        for control in (
            "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"
        ):
            (leaf / control).write_bytes(b"")
            (leaf / control).chmod(0o660)
        hostile = leaf / "runtime"
        hostile.mkdir(mode=0o750)
        hostile.chmod(0o750)
        (payload / "cgroup.stat").write_bytes(
            b"nr_descendants 2\nnr_dying_descendants 0\n"
        )
        descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "non-init lifecycle"
            ):
                controller._retire_lifecycle_cgroups_v27(
                    descriptor,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                    cgroup_mode_observer=proved_fake_setgid_mode,
                )
        finally:
            os.close(descriptor)

    def test_lifecycle_recovery_retries_busy_and_rejects_inode_substitution(self) -> None:
        for substitution in (False, True):
            with self.subTest(substitution=substitution):
                payload = Path(self.temporary.name) / f"payload-retry-{substitution}"
                payload.mkdir(mode=0o2710)
                payload.chmod(0o2710)
                leaf = payload / "lifecycle-0"
                leaf.mkdir(mode=0o770)
                leaf.chmod(0o770)
                for control in (
                    "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"
                ):
                    (leaf / control).write_bytes(b"")
                    (leaf / control).chmod(0o660)
                (payload / "cgroup.stat").write_bytes(
                    b"nr_descendants 1\nnr_dying_descendants 0\n"
                )
                descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
                real_rmdir = os.rmdir
                attempts = [0]

                def retire(name: str, *, dir_fd: int) -> None:
                    attempts[0] += 1
                    if attempts[0] == 1:
                        if substitution:
                            for item in leaf.iterdir():
                                item.unlink()
                            real_rmdir(name, dir_fd=dir_fd)
                            leaf.mkdir(mode=0o770)
                            leaf.chmod(0o770)
                            for control in (
                                "cgroup.procs", "cgroup.threads",
                                "cgroup.subtree_control",
                            ):
                                (leaf / control).write_bytes(b"")
                                (leaf / control).chmod(0o660)
                        raise OSError(errno.EBUSY, "busy")
                    for item in leaf.iterdir():
                        item.unlink()
                    real_rmdir(name, dir_fd=dir_fd)

                context = (
                    self.assertRaisesRegex(
                        controller.ControllerProtocolError, "replaced during retirement"
                    )
                    if substitution
                    else contextlib.nullcontext()
                )
                try:
                    with mock.patch.object(
                        controller,
                        "_read_cgroup_stat_v27",
                        side_effect=[
                            {"nr_descendants": 1, "nr_dying_descendants": 0},
                            {"nr_descendants": 0, "nr_dying_descendants": 0},
                        ],
                    ), mock.patch.object(
                        controller.os, "rmdir", side_effect=retire
                    ), context:
                        controller._retire_lifecycle_cgroups_v27(
                            descriptor,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=proved_fake_cgroup2,
                            cgroup_mode_observer=proved_fake_setgid_mode,
                        )
                    self.assertEqual(2 if not substitution else 1, attempts[0])
                finally:
                    os.close(descriptor)

    def test_lifecycle_recovery_repairs_exact_empty_chmod_crash_lattice_only(self) -> None:
        crash_modes = (
            (True, (0o644, 0o644, 0o644)),
            (False, (0o644, 0o644, 0o644)),
            (False, (0o660, 0o644, 0o644)),
            (False, (0o660, 0o660, 0o644)),
        )
        for index, (setgid_half, modes) in enumerate(crash_modes):
            with self.subTest(index=index, setgid_half=setgid_half, modes=modes):
                payload = Path(self.temporary.name) / f"payload-li-half-{index}"
                payload.mkdir(mode=0o710)
                payload.chmod(0o710)
                leaf = payload / "lifecycle-0"
                leaf.mkdir(mode=0o770)
                leaf.chmod(0o770)
                controls = (
                    "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"
                )
                for name, mode in zip(controls, modes):
                    (leaf / name).write_bytes(b"")
                    (leaf / name).chmod(mode)
                (leaf / "cgroup.stat").write_bytes(
                    b"nr_descendants 0\nnr_dying_descendants 0\n"
                )
                (payload / "cgroup.stat").write_bytes(
                    b"nr_descendants 1\nnr_dying_descendants 0\n"
                )
                payload_fd = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
                leaf_identity = (leaf.stat().st_dev, leaf.stat().st_ino)
                leaf_mode_reads = [0]
                real_rmdir = os.rmdir

                def mode_observer(descriptor: int) -> int:
                    metadata = os.fstat(descriptor)
                    if (metadata.st_dev, metadata.st_ino) == leaf_identity:
                        leaf_mode_reads[0] += 1
                        if setgid_half and leaf_mode_reads[0] == 1:
                            return 0o2770
                    return proved_fake_setgid_mode(descriptor)

                def retire(name: str, *, dir_fd: int) -> None:
                    for entry in tuple(leaf.iterdir()):
                        entry.unlink()
                    real_rmdir(name, dir_fd=dir_fd)
                    (payload / "cgroup.stat").write_bytes(
                        b"nr_descendants 0\nnr_dying_descendants 0\n"
                    )

                try:
                    with mock.patch.object(
                        controller.os, "rmdir", side_effect=retire
                    ):
                        receipt = controller._retire_lifecycle_cgroups_v27(
                            payload_fd,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=proved_fake_cgroup2,
                            cgroup_mode_observer=mode_observer,
                        )
                    self.assertEqual(1, receipt["placementMask"])
                    self.assertFalse(leaf.exists())
                finally:
                    os.close(payload_fd)

        payload = Path(self.temporary.name) / "payload-li-populated"
        payload.mkdir(mode=0o710)
        payload.chmod(0o710)
        leaf = payload / "lifecycle-0"
        leaf.mkdir(mode=0o770)
        leaf.chmod(0o770)
        for name in ("cgroup.procs", "cgroup.threads", "cgroup.subtree_control"):
            (leaf / name).write_bytes(b"4242\n" if name == "cgroup.procs" else b"")
            (leaf / name).chmod(0o644)
        (leaf / "cgroup.stat").write_bytes(
            b"nr_descendants 0\nnr_dying_descendants 0\n"
        )
        (payload / "cgroup.stat").write_bytes(
            b"nr_descendants 1\nnr_dying_descendants 0\n"
        )
        payload_fd = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "half-state is populated"
            ):
                controller._retire_lifecycle_cgroups_v27(
                    payload_fd,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                    cgroup_mode_observer=proved_fake_setgid_mode,
                )
            self.assertTrue(leaf.exists())
        finally:
            os.close(payload_fd)

    def test_controller_owns_and_authenticates_exact_cgroup_descriptor_transfer(self) -> None:
        supervisor = Path(self.temporary.name) / "supervisor-custody"
        supervisor.mkdir(mode=0o710)
        supervisor.chmod(0o710)
        supervisor_fd = os.open(supervisor, os.O_RDONLY | os.O_DIRECTORY)
        worker = supervisor / "worker"
        worker.mkdir(mode=0o700)
        worker_fd = os.open(worker, os.O_RDONLY | os.O_DIRECTORY)
        supervisor_process = supervisor / "cgroup.procs"
        supervisor_process.write_bytes(b"")
        supervisor_process.chmod(0o600)
        supervisor_process_fd = os.open(supervisor_process, os.O_WRONLY)
        plan = {
            "operationId": "a" * 64,
            "stageLocation": 17,
            "stagePlanSha256": digest("stage-plan"),
        }
        real_mkdir = os.mkdir

        def create_fake_controls(name: str, mode: int, *, dir_fd: int) -> None:
            real_mkdir(name, mode, dir_fd=dir_fd)
            payload = supervisor / name
            (payload / "cgroup.procs").write_bytes(b"")
            (payload / "cgroup.controllers").write_bytes(b"cpu memory pids\n")
            (payload / "cgroup.threads").write_bytes(b"")
            (payload / "cgroup.subtree_control").write_bytes(b"")
            (payload / "cgroup.events").write_bytes(b"populated 0\n")
            (payload / "cgroup.kill").write_bytes(b"")

        custody = None
        try:
            with mock.patch.object(controller.os, "mkdir", side_effect=create_fake_controls), mock.patch.object(
                controller, "_enable_exact_subtree_controllers_v27"
            ):
                custody = controller._create_controller_cgroup_custody_v27(
                    supervisor_fd,
                    supervisor_process_fd,
                    worker_fd,
                    "/service/supervisor/worker",
                    plan,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    worker_pid=os.getpid(),
                    worker_session_nonce="b" * 64,
                    cgroup_mode_observer=proved_fake_setgid_mode,
                )
            self.assertEqual(
                list(controller._WORKER_CGROUP_ROLES_V27),
                [item["role"] for item in custody.binding["descriptors"]],
            )
            self.assertEqual(4, len(custody.transfer_descriptors))
            self.assertEqual(
                ["0700", "0710", "0400", "0200"],
                [item["mode"] for item in custody.binding["descriptors"]],
            )
            self.assertFalse(
                stat.S_IMODE(supervisor.stat().st_mode) & stat.S_IWGRP,
                "worker group must not create a sibling P under S",
            )
            self.assertNotIn(
                "supervisor-procs",
                [item["role"] for item in custody.binding["descriptors"]],
            )
            consumed: set[str] = set()
            validated = controller._validate_worker_cgroup_transfer_v27(
                custody.binding,
                custody.transfer_descriptors,
                plan,
                worker_session_nonce="b" * 64,
                consumed_nonces=consumed,
                process_cgroup_reader=lambda: b"0::/service/supervisor/worker\n",
                process_start_time_reader=lambda: "7",
            )
            duplicates = controller.native_boundary_v27._native_cgroup_descriptors_v27(
                validated,
                plan,
                process_cgroup_reader=lambda: b"0::/service/supervisor/worker\n",
            )
            for descriptor in duplicates:
                os.close(descriptor)
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "identity changed"
            ):
                controller._validate_worker_cgroup_transfer_v27(
                    custody.binding,
                    custody.transfer_descriptors,
                    plan,
                    worker_session_nonce="b" * 64,
                    consumed_nonces=consumed,
                    process_cgroup_reader=lambda: b"0::/service/supervisor/worker\n",
                    process_start_time_reader=lambda: "7",
                )
            with self.assertRaisesRegex(
                controller.native_boundary_v27.NativeBoundaryV27Error,
                "descriptor identity changed",
            ):
                controller.native_boundary_v27._native_cgroup_descriptors_v27(
                    {
                        "binding": custody.binding,
                        "descriptors": (
                            custody.transfer_descriptors[0],
                            custody.transfer_descriptors[1],
                            custody.transfer_descriptors[3],
                            custody.transfer_descriptors[2],
                        ),
                    },
                    plan,
                    process_cgroup_reader=lambda: b"0::/service/supervisor/worker\n",
                )
        finally:
            if custody is not None:
                for name in (
                    "cgroup.procs", "cgroup.controllers", "cgroup.threads", "cgroup.subtree_control",
                    "cgroup.events", "cgroup.kill",
                ):
                    (supervisor / custody.payload_name / name).unlink()
                custody.close(retire=True)
            os.close(supervisor_fd)
            os.close(supervisor_process_fd)
            os.close(worker_fd)

    def test_payload_cgroup_requires_private_controller_owned_supervisor(self) -> None:
        supervisor = Path(self.temporary.name) / "public-supervisor"
        supervisor.mkdir(mode=0o755)
        descriptor = os.open(supervisor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "supervisor cgroup owner/mode/type"
            ):
                controller._create_controller_cgroup_custody_v27(
                    descriptor,
                    descriptor,
                    descriptor,
                    "/service/supervisor/worker",
                    {
                        "operationId": "c" * 64,
                        "stageLocation": 1,
                        "stagePlanSha256": digest("stage"),
                    },
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    worker_pid=os.getpid(),
                    worker_session_nonce="d" * 64,
                )
            self.assertEqual([], list(supervisor.iterdir()))
        finally:
            os.close(descriptor)

    def test_controller_recovery_drains_only_exact_owned_payload_cgroups(self) -> None:
        supervisor = Path(self.temporary.name) / "recovery-supervisor"
        supervisor.mkdir(mode=0o710)
        supervisor.chmod(0o710)
        interface_names = (
            "cgroup.procs",
            "cpu.max",
            "memory.current",
            "pids.current",
            "io.stat",
            "cpuset.cpus",
            "hugetlb.2MB.current",
            "misc.current",
            "rdma.current",
        )
        for interface in interface_names:
            (supervisor / interface).write_bytes(b"")
        payload_name = "payload-" + "e" * 64 + "-s76-" + "f" * 16
        payload = supervisor / payload_name
        payload.mkdir(mode=0o2710)
        payload.chmod(0o2710)
        (payload / "cgroup.events").write_bytes(b"populated 0\n")
        (payload / "cgroup.kill").write_bytes(b"")
        (payload / "cgroup.stat").write_bytes(
            b"nr_descendants 0\nnr_dying_descendants 0\n"
        )
        supervisor_fd = os.open(supervisor, os.O_RDONLY | os.O_DIRECTORY)
        result_root = Path(self.temporary.name) / "recovery-results"
        result_root.mkdir(mode=0o700)
        result_root.chmod(0o700)
        result_directory = result_root / (
            "e" * 64 + "-76-" + "f" * 16 + "0" * 48
        )
        result_directory.mkdir(mode=0o700)
        result_directory.chmod(0o700)
        self.prepare_authenticated_result_arena(result_directory, payload_name)
        real_rmdir = os.rmdir

        def retire(name: str, *, dir_fd: int) -> None:
            self.assertEqual(payload_name, name)
            self.assertEqual(supervisor_fd, dir_fd)
            self.assertEqual(b"1\n", (payload / "cgroup.kill").read_bytes())
            (payload / "cgroup.events").unlink()
            (payload / "cgroup.kill").unlink()
            (payload / "cgroup.stat").unlink()
            real_rmdir(name, dir_fd=dir_fd)

        try:
            with mock.patch.object(controller.os, "rmdir", side_effect=retire):
                controller._recover_controller_payload_cgroups_v27(
                    supervisor_fd,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                    cgroup_mode_observer=proved_fake_setgid_mode,
                    result_runtime_root=result_root,
                    controller_key=self.key,
                )
            self.assertFalse(payload.exists())
            self.assertTrue(
                (result_directory / "controller-retirement.intent.json").is_file()
            )
            self.assertTrue(
                (result_directory / "controller-retirement.json").is_file()
            )
            self.assertFalse(
                (result_directory / ".controller-retirement.intent.json.tmp").exists()
            )
            self.assertFalse(
                (result_directory / ".controller-retirement.json.tmp").exists()
            )
            self.assertEqual(
                list(interface_names),
                [name for name in interface_names if (supervisor / name).exists()],
            )

            substituted = supervisor / ("payload-" + "1" * 64 + "-s1-" + "2" * 16)
            substituted.mkdir(mode=0o755)
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "substituted payload state"
            ):
                controller._recover_controller_payload_cgroups_v27(
                    supervisor_fd,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                    controller_key=self.key,
                )
            self.assertTrue(substituted.exists())
            substituted.rmdir()

            hostile_entries = (
                ("symlink", lambda path: path.symlink_to("cgroup.procs")),
                ("special", lambda path: os.mkfifo(path, 0o600)),
                ("unexpected-dir", lambda path: path.mkdir(mode=0o700)),
            )
            for label, create in hostile_entries:
                with self.subTest(label=label):
                    hostile = supervisor / ("hostile-" + label)
                    create(hostile)
                    expected = (
                        "symlink or special entry"
                        if label != "unexpected-dir"
                        else "substituted payload state"
                    )
                    with self.assertRaisesRegex(
                        controller.ControllerProtocolError, expected
                    ):
                        controller._recover_controller_payload_cgroups_v27(
                            supervisor_fd,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=proved_fake_cgroup2,
                            controller_key=self.key,
                        )
                    if label == "unexpected-dir":
                        hostile.rmdir()
                    else:
                        hostile.unlink()

            hostile_magic = dict(proved_fake_cgroup2(supervisor_fd))
            hostile_magic["filesystemMagic"] = 0x01021994
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "not the exact cgroup2"
            ):
                controller._recover_controller_payload_cgroups_v27(
                    supervisor_fd,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=lambda _descriptor: hostile_magic,
                    controller_key=self.key,
                )
        finally:
            os.close(supervisor_fd)

    def test_recovery_keeps_payload_until_receipt_is_directory_durable(self) -> None:
        phases = (
            "controller-retirement.json:temp-created-unnormalized",
            "controller-retirement.json:temp-created",
            "controller-retirement.json:bytes-written",
            "controller-retirement.json:file-fsynced",
            "controller-retirement.json:installed",
            "controller-retirement.json:temporary-unlinked",
            "controller-retirement.json:directory-fsynced",
            "retirement-receipt-durable",
            "retirement-payload-removed",
        )
        real_rmdir = os.rmdir
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                supervisor = Path(self.temporary.name) / f"receipt-supervisor-{index}"
                supervisor.mkdir(mode=0o710)
                operation = f"{index + 1:064x}"
                prefix = f"{index + 2:016x}"
                payload_name = f"payload-{operation}-s1-{prefix}"
                payload = supervisor / payload_name
                payload.mkdir(mode=0o710)
                payload.chmod(0o710)
                for name, value in (
                    ("cgroup.events", b"populated 0\n"),
                    ("cgroup.kill", b""),
                    ("cgroup.stat", b"nr_descendants 0\nnr_dying_descendants 0\n"),
                ):
                    (payload / name).write_bytes(value)
                result_root = Path(self.temporary.name) / f"receipt-results-{index}"
                result_root.mkdir(mode=0o700)
                result_root.chmod(0o700)
                result_directory = result_root / (
                    operation + "-1-" + prefix + "0" * 48
                )
                result_directory.mkdir(mode=0o700)
                result_directory.chmod(0o700)
                self.prepare_authenticated_result_arena(
                    result_directory, payload_name
                )
                supervisor_fd = os.open(
                    supervisor, os.O_RDONLY | os.O_DIRECTORY
                )

                def retire(name: str, *, dir_fd: int) -> None:
                    self.assertEqual(payload_name, name)
                    for entry in tuple(payload.iterdir()):
                        entry.unlink()
                    real_rmdir(name, dir_fd=dir_fd)

                def crash(observed: str) -> None:
                    if observed == phase:
                        raise SystemExit(observed)

                try:
                    with self.assertRaises(SystemExit), mock.patch.object(
                        controller.os, "rmdir", side_effect=retire
                    ):
                        controller._recover_controller_payload_cgroups_v27(
                            supervisor_fd,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=proved_fake_cgroup2,
                            cgroup_mode_observer=proved_fake_setgid_mode,
                            result_runtime_root=result_root,
                            controller_key=self.key,
                            phase_hook=crash,
                        )
                    if phase != "retirement-payload-removed":
                        self.assertTrue(payload.exists())
                    with mock.patch.object(
                        controller.os, "rmdir", side_effect=retire
                    ):
                        controller._recover_controller_payload_cgroups_v27(
                            supervisor_fd,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=proved_fake_cgroup2,
                            cgroup_mode_observer=proved_fake_setgid_mode,
                            result_runtime_root=result_root,
                            controller_key=self.key,
                        )
                    self.assertFalse(payload.exists())
                    self.assertTrue(
                        (result_directory / "controller-retirement.json").is_file()
                    )
                    self.assertFalse(
                        (result_directory / ".controller-retirement.json.tmp").exists()
                    )
                finally:
                    os.close(supervisor_fd)

    def test_p_only_recovery_is_controller_authenticated_and_not_result_eligible(self) -> None:
        supervisor = Path(self.temporary.name) / "p-only-supervisor"
        supervisor.mkdir(mode=0o710)
        supervisor.chmod(0o710)
        operation = "9" * 64
        payload_name = f"payload-{operation}-s1-{'8' * 16}"
        payload = supervisor / payload_name
        payload.mkdir(mode=0o710)
        payload.chmod(0o710)
        for name, raw in (
            ("cgroup.events", b"populated 0\n"),
            ("cgroup.kill", b""),
            ("cgroup.stat", b"nr_descendants 0\nnr_dying_descendants 0\n"),
        ):
            (payload / name).write_bytes(raw)
        journal_parent = Path(self.temporary.name) / "p-only-journal-parent"
        journal_parent.mkdir(mode=0o700)
        journal_root = journal_parent / "cgroup-recovery-v27"
        supervisor_fd = os.open(supervisor, os.O_RDONLY | os.O_DIRECTORY)
        real_rmdir = os.rmdir

        def retire(name: str, *, dir_fd: int) -> None:
            self.assertEqual(payload_name, name)
            for entry in tuple(payload.iterdir()):
                entry.unlink()
            real_rmdir(name, dir_fd=dir_fd)

        try:
            phases: list[str] = []
            writes: list[str] = []
            real_write_all = controller.native_boundary_v27._write_all_v27

            def observe_write(descriptor: int, raw: bytes) -> None:
                if raw == b"1\n":
                    writes.append("kill")
                    self.assertIn(
                        "controller-custody.json:directory-fsynced", phases
                    )
                real_write_all(descriptor, raw)

            with mock.patch.object(
                controller.os, "rmdir", side_effect=retire
            ), mock.patch.object(
                controller.native_boundary_v27,
                "_write_all_v27",
                side_effect=observe_write,
            ):
                recovered = controller._recover_controller_payload_cgroups_v27(
                    supervisor_fd,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                    cgroup_mode_observer=proved_fake_setgid_mode,
                    result_runtime_root=Path(self.temporary.name) / "missing-results",
                    controller_key=self.key,
                    recovery_journal_root=journal_root,
                    phase_hook=phases.append,
                )
            self.assertEqual({}, recovered)
            self.assertEqual(["kill"], writes)
            self.assertFalse(payload.exists())
            evidence = journal_root / payload_name
            custody_raw = (evidence / "controller-custody.json").read_bytes()
            intent_raw = (evidence / "controller-retirement.intent.json").read_bytes()
            receipt_raw = (evidence / "controller-retirement.json").read_bytes()
            custody = json.loads(custody_raw)
            intent = json.loads(intent_raw)
            receipt = json.loads(receipt_raw)
            self.assertEqual("p-only-custody", custody["artifact"]["kind"])
            self.assertEqual(
                controller._sha(custody_raw),
                intent["artifact"]["predecessorSha256"],
            )
            self.assertEqual(
                controller._sha(intent_raw),
                receipt["artifact"]["predecessorSha256"],
            )
            self.assertIn(b'"kind":"p-only-intent"', intent_raw)
            self.assertIn(b'"kind":"p-only-receipt"', receipt_raw)
            hostile = bytearray(receipt_raw)
            hostile[-2] ^= 1
            (evidence / "controller-retirement.json").write_bytes(hostile)
            # Authentication evidence is immutable audit state; a tamper is
            # not accepted even though no public result can be recovered.
            with self.assertRaises(controller.ControllerProtocolError):
                controller._verify_p_only_recovery_envelope_v27(
                    json.loads(receipt_raw),
                    kind="receipt",
                    payload_name=payload_name,
                    payload_identity=json.loads(receipt_raw)["artifact"][
                        "payloadIdentity"
                    ],
                    predecessor_sha256=controller._sha(intent_raw),
                    controller_key=b"wrong-controller-key-material-32",
                )
        finally:
            os.close(supervisor_fd)

    def test_p_only_custody_atomic_prefixes_recover_before_kill(self) -> None:
        phases = (
            "controller-custody.json:temp-created-unnormalized",
            "controller-custody.json:temp-created",
            "controller-custody.json:bytes-written",
            "controller-custody.json:file-fsynced",
            "controller-custody.json:installed",
            "controller-custody.json:temporary-unlinked",
            "controller-custody.json:directory-fsynced",
        )
        real_rmdir = os.rmdir
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                supervisor = Path(self.temporary.name) / f"p-only-prefix-{index}"
                supervisor.mkdir(mode=0o710)
                operation = f"{index + 17:064x}"
                payload_name = f"payload-{operation}-s1-{'7' * 16}"
                payload = supervisor / payload_name
                payload.mkdir(mode=0o710)
                payload.chmod(0o710)
                for name, raw in (
                    ("cgroup.events", b"populated 0\n"),
                    ("cgroup.kill", b""),
                    ("cgroup.stat", b"nr_descendants 0\nnr_dying_descendants 0\n"),
                ):
                    (payload / name).write_bytes(raw)
                journal_parent = Path(self.temporary.name) / f"p-only-journal-{index}"
                journal_parent.mkdir(mode=0o700)
                journal_root = journal_parent / "cgroup-recovery-v27"
                supervisor_fd = os.open(
                    supervisor, os.O_RDONLY | os.O_DIRECTORY
                )

                def crash(observed: str) -> None:
                    if observed == phase:
                        raise SystemExit(observed)

                def retire(name: str, *, dir_fd: int) -> None:
                    self.assertEqual(payload_name, name)
                    for entry in tuple(payload.iterdir()):
                        entry.unlink()
                    real_rmdir(name, dir_fd=dir_fd)

                try:
                    with self.assertRaises(SystemExit):
                        controller._recover_controller_payload_cgroups_v27(
                            supervisor_fd,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=proved_fake_cgroup2,
                            cgroup_mode_observer=proved_fake_setgid_mode,
                            result_runtime_root=(
                                Path(self.temporary.name) / "missing-prefix-results"
                            ),
                            controller_key=self.key,
                            recovery_journal_root=journal_root,
                            phase_hook=crash,
                        )
                    self.assertTrue(payload.exists())
                    self.assertEqual(b"", (payload / "cgroup.kill").read_bytes())
                    with mock.patch.object(
                        controller.os, "rmdir", side_effect=retire
                    ):
                        recovered = controller._recover_controller_payload_cgroups_v27(
                            supervisor_fd,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=proved_fake_cgroup2,
                            cgroup_mode_observer=proved_fake_setgid_mode,
                            result_runtime_root=(
                                Path(self.temporary.name) / "missing-prefix-results"
                            ),
                            controller_key=self.key,
                            recovery_journal_root=journal_root,
                        )
                    self.assertEqual({}, recovered)
                    self.assertFalse(payload.exists())
                    evidence = journal_root / payload_name
                    self.assertTrue((evidence / "controller-custody.json").is_file())
                    self.assertFalse(
                        (evidence / ".controller-custody.json.tmp").exists()
                    )
                finally:
                    os.close(supervisor_fd)

    def test_prepare_precedes_p_and_retirement_has_independent_controller_auth(self) -> None:
        source = Path(controller.__file__).read_text()
        execute = source[source.index("    def execute(\n", source.index("class _WorkerChannelV27")):]
        execute = execute[:execute.index("    def _persist_retirement_artifact(")]
        self.assertLess(
            execute.index("self._prepare_result_arena("),
            execute.index("_create_controller_cgroup_custody_v27("),
        )
        self.assertLess(
            execute.index("_create_controller_cgroup_custody_v27("),
            execute.index("self.channel.sendmsg("),
        )
        self.assertNotIn("controller_key", source[source.index("def _worker_main_v27("):source.index("class _WorkerChannelV27")])

        plan = {
            "operationId": "a" * 64,
            "stageLocation": 1,
            "stagePlanSha256": digest("stage-plan"),
            "requestKeyId": digest("request-key"),
        }
        payload_name = f"payload-{'a' * 64}-s1-{digest('stage-plan')[7:23]}"
        payload_identity = {
            "device": 1,
            "gid": 993,
            "inode": 2,
            "mode": "2710",
            "uid": 991,
        }
        intent = {
            "schemaVersion": 27,
            "payloadIdentity": payload_identity,
            "placementMask": 0,
            "visibleDescendants": 0,
            "initControllers": [],
            "preRemovalCgroupStat": {
                "nr_descendants": 0,
                "nr_dying_descendants": 0,
            },
            "removalPlan": [],
        }
        arena_sha = digest("controller-arena")
        envelope = controller._controller_retirement_envelope_v27(
            kind="intent",
            plan=plan,
            payload_name=payload_name,
            payload_identity=payload_identity,
            arena_record_sha256=arena_sha,
            predecessor_artifact_sha256=None,
            body=intent,
            controller_key=self.key,
        )
        decoded, record_sha = controller._verify_controller_retirement_envelope_v27(
            envelope,
            kind="intent",
            controller_key=self.key,
            payload_name=payload_name,
            stage_plan_sha256=plan["stagePlanSha256"],
            arena_record_sha256=arena_sha,
            predecessor_artifact_sha256=None,
        )
        self.assertEqual(intent, decoded)
        self.assertEqual(controller._sha(controller._canonical(envelope)), record_sha)
        for field in (
            "operationId", "stageLocation", "stagePlanSha256", "requestKeyId",
            "payloadName", "payloadIdentity", "arenaRecordSha256", "body",
        ):
            hostile = json.loads(json.dumps(envelope))
            hostile["artifact"][field] = (
                "x" if field not in {"stageLocation", "payloadIdentity", "body"}
                else 2 if field == "stageLocation"
                else {} if field == "payloadIdentity"
                else {**intent, "placementMask": 1}
            )
            with self.subTest(field=field), self.assertRaises(
                controller.ControllerProtocolError
            ):
                controller._verify_controller_retirement_envelope_v27(
                    hostile,
                    kind="intent",
                    controller_key=self.key,
                    payload_name=payload_name,
                    stage_plan_sha256=plan["stagePlanSha256"],
                    arena_record_sha256=arena_sha,
                    predecessor_artifact_sha256=None,
                )

    def test_p_absent_restart_requires_full_controller_authenticated_chain(self) -> None:
        operation = "a" * 64
        stage_digest = digest("restart-stage")
        payload_name = (
            f"payload-{operation}-s17-"
            f"{stage_digest.removeprefix('sha256:')[:16]}"
        )
        result_directory = Path(self.temporary.name) / (
            f"{operation}-17-{stage_digest.removeprefix('sha256:')}"
        )
        result_directory.mkdir(mode=0o700)
        plan, _arena_sha = self.prepare_authenticated_result_arena(
            result_directory, payload_name
        )
        chain = self.authenticated_retirement_chain(
            result_directory, payload_name, plan
        )
        recovered = {
            "exitCode": 0,
            "placementMask": 63,
            "stdout": b"{}",
            "stderr": b"",
            "lifecycle": list(controller.native_boundary_v27._EFFECT_LIFECYCLE),
            "resultKind": "success",
            "resultPredecessorKind": "creator-lifetime-closed-positive",
            "failureEvidenceSha256": None,
            "_controllerRetirementChain": chain,
            "_nativeCreatorArtifactBinding": {"test": "signed-root-chain"},
        }
        wire = json.loads(
            controller._worker_recovery_packet_v27(
                plan["stagePlanSha256"], recovered
            )
        )
        self.assertEqual(chain, wire["controllerRetirementChain"])
        self.assertNotIn(
            "controllerRetirement", wire["nativeStageObservation"]
        )
        self.assertEqual(
            {"test": "signed-root-chain"},
            wire["nativeCreatorArtifactBinding"],
        )
        self.assertEqual(
            {
                "schemaVersion", "protocol", "status", "stagePlanSha256",
                "nativeStageObservation", "controllerRetirementChain",
                "nativeCreatorArtifactBinding",
            },
            set(wire),
        )

        class RestartedWorker:
            def __init__(self, value):
                self.value = value
                self.retirement_receipts = {}

            def recover(self, _manifest, _plan, *, lifecycle_check):
                lifecycle_check()
                return json.loads(json.dumps({
                    **self.value,
                    "stdout": None,
                    "stderr": None,
                })) | {
                    "stdout": self.value["stdout"],
                    "stderr": self.value["stderr"],
                }

        worker = RestartedWorker(recovered)
        runner = controller._WorkerStageRunnerV27(worker, lambda: None, self.key)
        request_key = b"r" * 32
        token = controller.native_boundary_v27._NATIVE_REQUEST_KEY_V27.set(
            request_key
        )
        verified: list[tuple[object, str]] = []

        class ArtifactAuthority:
            def bind_native_stage_authority_v27(self, value):
                self.plan = value

            def verify_creator_artifact_binding_v27(self, value, result_kind):
                verified.append((value, result_kind))

        authority_token = (
            controller.native_boundary_v27._NATIVE_OUTER_EVENT_HANDLER_V27.set(
                ArtifactAuthority()
            )
        )
        try:
            with mock.patch.object(
                controller.native_boundary_v27,
                "validate_native_stage_action_plan_v27",
                return_value=plan,
            ):
                result = runner.recover(object(), plan)
            self.assertEqual(63, result["controllerRetirement"]["placementMask"])
            self.assertEqual({}, worker.retirement_receipts)
            self.assertEqual(
                [({"test": "signed-root-chain"}, "success")], verified
            )

            hostile: dict[str, dict[str, object]] = {}
            for name, target in (
                ("arena-hmac", "arena"),
                ("intent-hmac", "intent"),
                ("receipt-hmac", "receipt"),
            ):
                candidate = json.loads(json.dumps(chain))
                candidate[target]["controllerHmac"] = "hmac-sha256:" + "0" * 64
                hostile[name] = candidate
            candidate = json.loads(json.dumps(chain))
            candidate["intent"] = controller._controller_retirement_envelope_v27(
                kind="intent",
                plan=plan,
                payload_name=payload_name,
                payload_identity=chain["intent"]["artifact"]["payloadIdentity"],
                arena_record_sha256=digest("wrong-arena"),
                predecessor_artifact_sha256=None,
                body=chain["intent"]["artifact"]["body"],
                controller_key=self.key,
            )
            hostile["arena-digest"] = candidate
            candidate = json.loads(json.dumps(chain))
            candidate["receipt"] = controller._controller_retirement_envelope_v27(
                kind="receipt",
                plan=plan,
                payload_name=payload_name,
                payload_identity=chain["receipt"]["artifact"]["payloadIdentity"],
                arena_record_sha256=controller._sha(
                    controller._canonical(chain["arena"])
                ),
                predecessor_artifact_sha256=digest("wrong-predecessor"),
                body=chain["receipt"]["artifact"]["body"],
                controller_key=self.key,
            )
            hostile["predecessor-digest"] = candidate
            hostile["swapped-artifacts"] = {
                "arena": chain["arena"],
                "intent": chain["receipt"],
                "receipt": chain["intent"],
            }
            candidate = json.loads(json.dumps(chain))
            candidate["receipt"]["artifact"]["body"]["placementMask"] = 31
            hostile["same-uid-replacement"] = candidate
            candidate = json.loads(json.dumps(chain))
            candidate["intent"]["artifact"]["unexpected"] = True
            hostile["corrupt-intent-shape"] = candidate

            for label, candidate in hostile.items():
                with self.subTest(label=label):
                    worker.value = {
                        **recovered,
                        "_controllerRetirementChain": candidate,
                    }
                    with self.assertRaises(controller.ControllerProtocolError):
                        with mock.patch.object(
                            controller.native_boundary_v27,
                            "validate_native_stage_action_plan_v27",
                            return_value=plan,
                        ):
                            runner.recover(object(), plan)
        finally:
            controller.native_boundary_v27._NATIVE_OUTER_EVENT_HANDLER_V27.reset(
                authority_token
            )
            controller.native_boundary_v27._NATIVE_REQUEST_KEY_V27.reset(token)

    def test_p_absent_pre_effect_requires_controller_proof_chain_or_becomes_loss(self) -> None:
        operation = "c" * 64
        stage_digest = digest("restart-pre-effect-stage")
        payload_name = (
            f"payload-{operation}-s17-"
            f"{stage_digest.removeprefix('sha256:')[:16]}"
        )
        result_directory = Path(self.temporary.name) / (
            f"{operation}-17-{stage_digest.removeprefix('sha256:')}"
        )
        result_directory.mkdir(mode=0o700)
        plan, _arena_sha = self.prepare_authenticated_result_arena(
            result_directory, payload_name
        )
        arena = json.loads((result_directory / "arena.json").read_bytes())
        arena_sha = controller._sha(controller._canonical(arena))
        payload_identity = {
            "device": 17, "gid": 993, "inode": 19,
            "mode": "2710", "uid": 991,
        }
        empty_stat = {"nr_descendants": 0, "nr_dying_descendants": 0}
        intent_body = {
            "schemaVersion": 27,
            "payloadIdentity": payload_identity,
            "placementMask": 0,
            "visibleDescendants": 0,
            "initControllers": [],
            "preRemovalCgroupStat": empty_stat,
            "removalPlan": [],
        }
        intent = controller._controller_retirement_envelope_v27(
            kind="intent", plan=plan, payload_name=payload_name,
            payload_identity=payload_identity,
            arena_record_sha256=arena_sha,
            predecessor_artifact_sha256=None, body=intent_body,
            controller_key=self.key,
        )
        receipt_body = {
            "schemaVersion": 27,
            "visibleDescendants": 0,
            "placementMask": 0,
            "controllerTrackedPlacementMask": 0,
            "initControllers": [],
            "preRemovalCgroupStat": empty_stat,
            "terminalCgroupStat": empty_stat,
        }
        receipt = controller._controller_retirement_envelope_v27(
            kind="receipt", plan=plan, payload_name=payload_name,
            payload_identity=payload_identity,
            arena_record_sha256=arena_sha,
            predecessor_artifact_sha256=controller._sha(
                controller._canonical(intent)
            ),
            body=receipt_body, controller_key=self.key,
        )
        chain = {"arena": arena, "intent": intent, "receipt": receipt}
        empty_observation = {
            "schemaVersion": 27, "knownNoChild": True, "placementMask": 0,
        }
        worker_failure = {
            "evidenceSha256": digest("proved-before-popen"),
            "classification": {
                "classification": "pre-popen-descriptor-preflight-failed",
                "processCreated": False,
            },
        }
        proof = controller._controller_pre_effect_proof_envelope_v27(
            plan=plan, payload_name=payload_name,
            arena_record_sha256=arena_sha,
            consumed_current_record_sha256=digest("consumed-current"),
            worker_failure=worker_failure,
            first_empty_observation=empty_observation,
            second_empty_observation=empty_observation,
            controller_retirement=receipt_body,
            controller_key=self.key,
        )

        class RestartedWorker:
            def __init__(self, value):
                self.value = value

            def recover(self, _manifest, _plan, *, lifecycle_check):
                lifecycle_check()
                return self.value

        worker = RestartedWorker({
            "nativeLaunchPreEffectProof": proof,
            "_controllerRetirementChain": chain,
        })
        runner = controller._WorkerStageRunnerV27(worker, lambda: None, self.key)
        token = controller.native_boundary_v27._NATIVE_REQUEST_KEY_V27.set(b"r" * 32)
        try:
            with mock.patch.object(
                controller.native_boundary_v27,
                "validate_native_stage_action_plan_v27",
                return_value=plan,
            ), self.assertRaises(
                controller.native_boundary_v27._NativeLaunchPreEffectFailedV27
            ):
                runner.recover(object(), plan)

            hostile: dict[str, dict[str, object]] = {}
            candidate = json.loads(json.dumps(proof))
            candidate["controllerHmac"] = "hmac-sha256:" + "0" * 64
            hostile["forged-hmac"] = candidate
            candidate = controller._controller_pre_effect_proof_envelope_v27(
                plan=plan, payload_name=payload_name,
                arena_record_sha256=digest("wrong-arena"),
                consumed_current_record_sha256=digest("consumed-current"),
                worker_failure=worker_failure,
                first_empty_observation=empty_observation,
                second_empty_observation=empty_observation,
                controller_retirement=receipt_body,
                controller_key=self.key,
            )
            hostile["wrong-arena"] = candidate
            candidate = json.loads(json.dumps(proof))
            candidate["proof"]["workerFailure"]["classification"][
                "processCreated"
            ] = True
            hostile["same-uid-replacement"] = candidate
            other_plan = {**plan, "operationId": "d" * 64}
            hostile["swapped-operation"] = (
                controller._controller_pre_effect_proof_envelope_v27(
                    plan=other_plan,
                    payload_name=controller._payload_cgroup_name_v27(other_plan),
                    arena_record_sha256=arena_sha,
                    consumed_current_record_sha256=digest("consumed-current"),
                    worker_failure=worker_failure,
                    first_empty_observation=empty_observation,
                    second_empty_observation=empty_observation,
                    controller_retirement=receipt_body,
                    controller_key=self.key,
                )
            )
            for label, candidate in hostile.items():
                with self.subTest(label=label):
                    worker.value = {
                        "nativeLaunchPreEffectProof": candidate,
                        "_controllerRetirementChain": chain,
                    }
                    with mock.patch.object(
                        controller.native_boundary_v27,
                        "validate_native_stage_action_plan_v27",
                        return_value=plan,
                    ):
                        recovered = runner.recover(object(), plan)
                    self.assertEqual(
                        "dead-holder-without-terminal",
                        recovered["nativeSupervisorLoss"]["reason"],
                    )
                    self.assertEqual(
                        0, recovered["controllerRetirement"]["placementMask"]
                    )
        finally:
            controller.native_boundary_v27._NATIVE_REQUEST_KEY_V27.reset(token)

    def test_p_absent_loss_requires_full_controller_authenticated_chain(self) -> None:
        operation = "b" * 64
        stage_digest = digest("restart-loss-stage")
        payload_name = (
            f"payload-{operation}-s19-"
            f"{stage_digest.removeprefix('sha256:')[:16]}"
        )
        result_directory = Path(self.temporary.name) / (
            f"{operation}-19-{stage_digest.removeprefix('sha256:')}"
        )
        result_directory.mkdir(mode=0o700)
        plan, _arena_sha = self.prepare_authenticated_result_arena(
            result_directory, payload_name
        )
        chain = self.authenticated_retirement_chain(
            result_directory, payload_name, plan
        )
        recovered = {
            "nativeSupervisorLoss": {
                "schemaVersion": 27,
                "reason": "authenticated-controller-loss",
                "evidenceSha256": digest("authenticated-loss-disposition"),
            },
            "_controllerRetirementChain": chain,
        }

        class RestartedWorker:
            def __init__(self, value):
                self.value = value
                self.retirement_receipts = {}

            def recover(self, _manifest, _plan, *, lifecycle_check):
                lifecycle_check()
                return self.value

        worker = RestartedWorker(recovered)
        runner = controller._WorkerStageRunnerV27(worker, lambda: None, self.key)
        token = controller.native_boundary_v27._NATIVE_REQUEST_KEY_V27.set(
            b"r" * 32
        )
        try:
            with mock.patch.object(
                controller.native_boundary_v27,
                "validate_native_stage_action_plan_v27",
                return_value=plan,
            ):
                result = runner.recover(object(), plan)
            self.assertEqual(
                {"nativeSupervisorLoss", "controllerRetirement"}, set(result)
            )
            self.assertEqual(63, result["controllerRetirement"]["placementMask"])

            hostile = json.loads(json.dumps(chain))
            hostile["receipt"]["controllerHmac"] = "hmac-sha256:" + "0" * 64
            worker.value = {
                **recovered,
                "_controllerRetirementChain": hostile,
            }
            with self.assertRaises(controller.ControllerProtocolError), mock.patch.object(
                controller.native_boundary_v27,
                "validate_native_stage_action_plan_v27",
                return_value=plan,
            ):
                runner.recover(object(), plan)
        finally:
            controller.native_boundary_v27._NATIVE_REQUEST_KEY_V27.reset(token)

    def test_split_cgroup_recovery_accepts_only_exact_podman_541_topology(self) -> None:
        payload = Path(self.temporary.name) / "split-positive"
        payload.mkdir(mode=0o770)
        payload.chmod(0o770)
        payload_fd = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
        container_id = "a" * 64
        names = ("runtime", f"libpod-payload-{container_id}")
        for name in names:
            child = payload / name
            mode = 0o750 if name == "runtime" else 0o755
            child.mkdir(mode=mode)
            child.chmod(mode)
            (child / "cgroup.events").write_bytes(b"populated 0\n")
        stat_file = payload / "cgroup.stat"
        stat_file.write_bytes(b"nr_descendants 2\nnr_dying_descendants 0\n")
        real_rmdir = os.rmdir
        attempts: list[str] = []

        def retire(name: str, *, dir_fd: int) -> None:
            self.assertEqual(payload_fd, dir_fd)
            attempts.append(name)
            child = payload / name
            for interface in child.iterdir():
                interface.unlink()
            real_rmdir(name, dir_fd=dir_fd)
            remaining = sum(item.is_dir() for item in payload.iterdir())
            stat_file.write_bytes(
                f"nr_descendants {remaining}\nnr_dying_descendants 0\n".encode()
            )

        try:
            with mock.patch.object(controller.os, "rmdir", side_effect=retire):
                controller._retire_split_cgroup_children_v27(
                    payload_fd,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                )
            self.assertEqual(set(names), set(attempts))
            self.assertEqual([], [item for item in payload.iterdir() if item.is_dir()])
        finally:
            os.close(payload_fd)

    def test_split_retirement_allows_transient_dying_css_between_siblings(self) -> None:
        payload = Path(self.temporary.name) / "split-dying-between"
        payload.mkdir(mode=0o770)
        payload.chmod(0o770)
        names = ("runtime", "libpod-payload-" + "c" * 64)
        for name in names:
            child = payload / name
            mode = 0o750 if name == "runtime" else 0o755
            child.mkdir(mode=mode)
            child.chmod(mode)
            (child / "cgroup.events").write_bytes(b"populated 0\n")
        stat_file = payload / "cgroup.stat"
        stat_file.write_bytes(b"nr_descendants 2\nnr_dying_descendants 0\n")
        descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
        real_rmdir = os.rmdir
        removed = 0

        def retire(name: str, *, dir_fd: int) -> None:
            nonlocal removed
            for interface in (payload / name).iterdir():
                interface.unlink()
            real_rmdir(name, dir_fd=dir_fd)
            removed += 1
            stat_file.write_bytes(
                (
                    "nr_descendants 1\nnr_dying_descendants 1\n"
                    if removed == 1
                    else "nr_descendants 0\nnr_dying_descendants 0\n"
                ).encode()
            )

        try:
            with mock.patch.object(controller.os, "rmdir", side_effect=retire):
                controller._retire_split_cgroup_children_v27(
                    descriptor,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                )
            self.assertEqual(2, removed)
        finally:
            os.close(descriptor)

    def test_recovery_accepts_only_exact_persistent_setgid_payload_state(self) -> None:
        supervisor = Path(self.temporary.name) / "half-supervisor"
        supervisor.mkdir(mode=0o710)
        payload_name = "payload-" + "d" * 64 + "-s1-" + "e" * 16
        payload = supervisor / payload_name
        payload.mkdir(mode=0o2710)
        payload.chmod(0o2710)
        for name, value in (
            ("cgroup.events", b"populated 0\n"),
            ("cgroup.kill", b""),
            ("cgroup.stat", b"nr_descendants 0\nnr_dying_descendants 0\n"),
        ):
            (payload / name).write_bytes(value)
        supervisor_fd = os.open(supervisor, os.O_RDONLY | os.O_DIRECTORY)
        result_root = Path(self.temporary.name) / "half-results"
        result_root.mkdir(mode=0o700)
        result_root.chmod(0o700)
        result_directory = result_root / (
            "d" * 64 + "-1-" + "e" * 16 + "0" * 48
        )
        result_directory.mkdir(mode=0o700)
        result_directory.chmod(0o700)
        self.prepare_authenticated_result_arena(result_directory, payload_name)
        real_rmdir = os.rmdir

        def half_mode(fd: int) -> int:
            return stat.S_IMODE(os.fstat(fd).st_mode) | stat.S_ISGID

        def retire(name: str, *, dir_fd: int) -> None:
            self.assertEqual(0o710, stat.S_IMODE(payload.stat().st_mode))
            for interface in payload.iterdir():
                interface.unlink()
            real_rmdir(name, dir_fd=dir_fd)

        try:
            with mock.patch.object(controller.os, "rmdir", side_effect=retire):
                controller._recover_controller_payload_cgroups_v27(
                    supervisor_fd,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                    cgroup_mode_observer=half_mode,
                    result_runtime_root=result_root,
                    controller_key=self.key,
                )
            self.assertFalse(payload.exists())
        finally:
            os.close(supervisor_fd)

    def test_split_cgroup_recovery_rejects_closed_topology_substitutions(self) -> None:
        cases = (
            "duplicate-payload",
            "unexpected-dir",
            "symlink",
            "fifo",
            "wrong-mode",
            "umask-bypass",
        )
        for label in cases:
            with self.subTest(label=label):
                payload = Path(self.temporary.name) / ("split-hostile-" + label)
                payload.mkdir(mode=0o770)
                payload.chmod(0o770)
                runtime = payload / "runtime"
                if label == "symlink":
                    runtime.symlink_to("cgroup.stat")
                elif label == "fifo":
                    os.mkfifo(runtime, 0o600)
                elif label == "unexpected-dir":
                    runtime = payload / "other"
                    runtime.mkdir(mode=0o750)
                    runtime.chmod(0o750)
                else:
                    child_mode = (
                        0o700
                        if label == "wrong-mode"
                        else 0o755
                        if label == "umask-bypass"
                        else 0o750
                    )
                    runtime.mkdir(mode=child_mode)
                    runtime.chmod(child_mode)
                if label == "duplicate-payload":
                    for identity in ("1" * 64, "2" * 64):
                        child = payload / f"libpod-payload-{identity}"
                        child.mkdir(mode=0o755)
                        child.chmod(0o755)
                descendants = sum(item.is_dir() for item in payload.iterdir())
                (payload / "cgroup.stat").write_bytes(
                    f"nr_descendants {descendants}\nnr_dying_descendants 0\n".encode()
                )
                descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(controller.ControllerProtocolError):
                        controller._retire_split_cgroup_children_v27(
                            descriptor,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=proved_fake_cgroup2,
                        )
                finally:
                    os.close(descriptor)

    def test_split_cgroup_recovery_rejects_nonempty_replacement_and_late_child(self) -> None:
        payload = Path(self.temporary.name) / "split-races"
        payload.mkdir(mode=0o770)
        payload.chmod(0o770)
        runtime = payload / "runtime"
        runtime.mkdir(mode=0o750)
        runtime.chmod(0o750)
        (runtime / "cgroup.events").write_bytes(b"populated 0\n")
        stat_file = payload / "cgroup.stat"
        stat_file.write_bytes(b"nr_descendants 2\nnr_dying_descendants 0\n")
        descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "descendant count"
            ):
                controller._retire_split_cgroup_children_v27(
                    descriptor,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                )

            stat_file.write_bytes(b"nr_descendants 1\nnr_dying_descendants 0\n")
            real_open = os.open
            replaced = False

            def substitute_open(name: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal replaced
                if name == "runtime" and kwargs.get("dir_fd") == descriptor and not replaced:
                    replaced = True
                    runtime.rename(payload / "old-runtime")
                    runtime.mkdir(mode=0o750)
                    runtime.chmod(0o750)
                return real_open(name, flags, *args, **kwargs)

            with mock.patch.object(controller.os, "open", side_effect=substitute_open):
                with self.assertRaisesRegex(
                    controller.ControllerProtocolError, "changed before descriptor open"
                ):
                    controller._retire_split_cgroup_children_v27(
                        descriptor,
                        controller_uid=os.geteuid(),
                        worker_uid=os.geteuid(),
                        worker_gid=os.getegid(),
                        cgroup2_observer=proved_fake_cgroup2,
                    )
        finally:
            os.close(descriptor)

    def test_split_cgroup_recovery_rejects_fake_magic_and_cross_device(self) -> None:
        for label in ("magic", "device"):
            with self.subTest(label=label):
                payload = Path(self.temporary.name) / ("split-proof-" + label)
                payload.mkdir(mode=0o770)
                payload.chmod(0o770)
                runtime = payload / "runtime"
                runtime.mkdir(mode=0o750)
                runtime.chmod(0o750)
                (payload / "cgroup.stat").write_bytes(
                    b"nr_descendants 1\nnr_dying_descendants 0\n"
                )
                descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
                root_inode = os.fstat(descriptor).st_ino

                def hostile_observer(fd: int) -> dict[str, object]:
                    value = dict(proved_fake_cgroup2(fd))
                    if os.fstat(fd).st_ino != root_inode:
                        if label == "magic":
                            value["filesystemMagic"] = 0x01021994
                        else:
                            value["device"] = int(value["device"]) + 1
                    return value

                try:
                    with self.assertRaisesRegex(
                        controller.ControllerProtocolError, "not the exact cgroup2"
                    ):
                        controller._retire_split_cgroup_children_v27(
                            descriptor,
                            controller_uid=os.geteuid(),
                            worker_uid=os.geteuid(),
                            worker_gid=os.getegid(),
                            cgroup2_observer=hostile_observer,
                        )
                finally:
                    os.close(descriptor)

    def test_split_cgroup_recovery_retries_busy_and_rejects_late_or_timeout(self) -> None:
        for label in ("retry", "late", "timeout"):
            with self.subTest(label=label):
                payload = Path(self.temporary.name) / ("split-retire-" + label)
                payload.mkdir(mode=0o770)
                payload.chmod(0o770)
                runtime = payload / "runtime"
                runtime.mkdir(mode=0o750)
                runtime.chmod(0o750)
                (runtime / "cgroup.events").write_bytes(b"populated 0\n")
                stat_file = payload / "cgroup.stat"
                stat_file.write_bytes(b"nr_descendants 1\nnr_dying_descendants 0\n")
                descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
                real_rmdir = os.rmdir
                calls = 0

                def retire(name: str, *, dir_fd: int) -> None:
                    nonlocal calls
                    calls += 1
                    if label == "late" and calls == 1:
                        late = payload / "foreign"
                        late.mkdir(mode=0o750)
                        late.chmod(0o750)
                    if label == "timeout" or calls == 1:
                        raise OSError(errno.EBUSY, "busy")
                    for interface in (payload / name).iterdir():
                        interface.unlink()
                    real_rmdir(name, dir_fd=dir_fd)
                    stat_file.write_bytes(
                        b"nr_descendants 0\nnr_dying_descendants 0\n"
                    )

                try:
                    context = (
                        self.assertRaisesRegex(
                            controller.ControllerProtocolError,
                            "unexpected directory" if label == "late" else "timed out",
                        )
                        if label != "retry"
                        else contextlib.nullcontext()
                    )
                    with mock.patch.object(controller.os, "rmdir", side_effect=retire), \
                         mock.patch.object(controller.time, "sleep"):
                        with context:
                            controller._retire_split_cgroup_children_v27(
                                descriptor,
                                controller_uid=os.geteuid(),
                                worker_uid=os.geteuid(),
                                worker_gid=os.getegid(),
                                cgroup2_observer=proved_fake_cgroup2,
                            )
                    if label == "retry":
                        self.assertEqual(2, calls)
                finally:
                    os.close(descriptor)

    def test_split_cgroup_recovery_admits_nonzero_dying_while_child_is_visible(self) -> None:
        payload = Path(self.temporary.name) / "split-dying-admission"
        payload.mkdir(mode=0o770)
        payload.chmod(0o770)
        runtime = payload / "runtime"
        runtime.mkdir(mode=0o750)
        runtime.chmod(0o750)
        (runtime / "cgroup.events").write_bytes(b"populated 0\n")
        stat_file = payload / "cgroup.stat"
        stat_file.write_bytes(
            b"nr_descendants 1\nnr_dying_descendants 1\n"
            b"nr_subsys_memory 4\nnr_dying_subsys_memory 1\n"
        )
        descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
        real_rmdir = os.rmdir

        def retire(name: str, *, dir_fd: int) -> None:
            for interface in (payload / name).iterdir():
                interface.unlink()
            real_rmdir(name, dir_fd=dir_fd)
            stat_file.write_bytes(
                b"nr_descendants 0\nnr_dying_descendants 0\n"
                b"nr_subsys_memory 4\nnr_dying_subsys_memory 0\n"
            )

        try:
            with mock.patch.object(controller.os, "rmdir", side_effect=retire):
                controller._retire_split_cgroup_children_v27(
                    descriptor,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                )
            self.assertFalse(runtime.exists())
        finally:
            os.close(descriptor)

    def test_split_cgroup_recovery_retains_unbounded_dying_css_as_evidence(self) -> None:
        payload = Path(self.temporary.name) / "split-dying-final"
        payload.mkdir(mode=0o770)
        payload.chmod(0o770)
        runtime = payload / "runtime"
        runtime.mkdir(mode=0o750)
        runtime.chmod(0o750)
        (runtime / "cgroup.events").write_bytes(b"populated 0\n")
        stat_file = payload / "cgroup.stat"
        stat_file.write_bytes(b"nr_descendants 1\nnr_dying_descendants 0\n")
        descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
        real_rmdir = os.rmdir
        now = [10.0]

        def retire(name: str, *, dir_fd: int) -> None:
            for interface in (payload / name).iterdir():
                interface.unlink()
            real_rmdir(name, dir_fd=dir_fd)
            stat_file.write_bytes(
                b"nr_descendants 0\nnr_dying_descendants 1\n"
            )

        def advance(_seconds: float) -> None:
            now[0] += 1.0

        try:
            with mock.patch.object(controller.os, "rmdir", side_effect=retire):
                controller._retire_split_cgroup_children_v27(
                    descriptor,
                    controller_uid=os.geteuid(),
                    worker_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    cgroup2_observer=proved_fake_cgroup2,
                    monotonic_clock=lambda: now[0],
                    sleeper=advance,
                )
            self.assertEqual(10.0, now[0])
        finally:
            os.close(descriptor)

    def test_cgroup_stat_accepts_modern_paired_counters_and_rejects_hostile_scalars(self) -> None:
        valid = (
            b"nr_descendants 0\nnr_dying_descendants 0\n",
            b"nr_dying_subsys_io 0\nnr_subsys_memory 7\n"
            b"nr_descendants 2\nnr_subsys_io 3\n"
            b"nr_dying_descendants 0\nnr_dying_subsys_memory 0\n"
            b"nr_subsys_pids 1\nnr_dying_subsys_pids 0\n",
        )
        for ordinal, raw in enumerate(valid):
            with self.subTest(valid=ordinal):
                root = Path(self.temporary.name) / f"cgroup-stat-valid-{ordinal}"
                root.mkdir()
                (root / "cgroup.stat").write_bytes(raw)
                descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    observed = controller._read_cgroup_stat_v27(descriptor)
                finally:
                    os.close(descriptor)
                self.assertTrue(
                    controller._cgroup_stat_matches_visible_v27(
                        observed, observed["nr_descendants"]
                    )
                )

        invalid = {
            "unknown": b"nr_descendants 0\nnr_dying_descendants 0\nother 0\n",
            "duplicate": b"nr_descendants 0\nnr_descendants 0\nnr_dying_descendants 0\n",
            "unpaired-live": b"nr_descendants 0\nnr_dying_descendants 0\nnr_subsys_cpu 1\n",
            "unpaired-dying": b"nr_descendants 0\nnr_dying_descendants 0\nnr_dying_subsys_cpu 0\n",
            "negative": b"nr_descendants -1\nnr_dying_descendants 0\n",
            "overflow": b"nr_descendants 18446744073709551616\nnr_dying_descendants 0\n",
            "leading-zero": b"nr_descendants 00\nnr_dying_descendants 0\n",
            "bad-controller": b"nr_descendants 0\nnr_dying_descendants 0\nnr_subsys_CPU-X 0\nnr_dying_subsys_CPU-X 0\n",
        }
        for label, raw in invalid.items():
            with self.subTest(invalid=label):
                root = Path(self.temporary.name) / ("cgroup-stat-invalid-" + label)
                root.mkdir()
                (root / "cgroup.stat").write_bytes(raw)
                descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaisesRegex(
                        controller.ControllerProtocolError, "cgroup.stat is malformed"
                    ):
                        controller._read_cgroup_stat_v27(descriptor)
                finally:
                    os.close(descriptor)

        nonzero_dying = {
            "nr_descendants": 1,
            "nr_dying_descendants": 0,
            "nr_subsys_cpu": 9,
            "nr_dying_subsys_cpu": 1,
        }
        self.assertFalse(
            controller._cgroup_stat_matches_visible_v27(nonzero_dying, 1)
        )

    def test_cgroup_protocol_has_one_rights_transfer_and_blocks_children_before_exec(self) -> None:
        controller_source = Path(controller.__file__).read_text()
        native_source = Path(controller.native_boundary_v27.__file__).read_text()
        supervisor_source = (
            ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c"
        ).read_text()
        self.assertIn("len(_WORKER_CGROUP_ROLES_V27)", controller_source)
        self.assertIn("binding[\"transferNonce\"] in consumed_nonces", controller_source)
        self.assertIn("placement_mediator", native_source)
        worker = controller_source[
            controller_source.index("def _worker_main_v27") :
            controller_source.index("class _WorkerChannelV27")
        ]
        self.assertNotIn("os.mkdir", worker)
        self.assertNotIn("os.chown", worker)
        self.assertNotIn("_create_controller_cgroup_custody_v27", worker)
        self.assertIn('credentialed_control("RELEASE\\n",1)', supervisor_source)
        self.assertIn('credentialed_control("ACK\\n",0)', supervisor_source)
        close_inherited = supervisor_source.index("child_close_inherited_fds(")
        release_read = supervisor_source.index("read(3,&release")
        placement_request = supervisor_source.index("request_controller_placement(child")
        release_write = supervisor_source.index(
            'write_all_fd(release_pipe[1],"R",1U)', placement_request
        )
        execve = supervisor_source.index("execve(PODMAN", release_read)
        self.assertLess(close_inherited, release_read)
        self.assertLess(release_read, execve)
        self.assertLess(placement_request, release_write)
        self.assertNotIn("move_to_payload_cgroup(child)", supervisor_source)
        self.assertIn("SYS_close_range", supervisor_source)
        self.assertIn("child_require_stdio_only();", supervisor_source)
        self.assertIn('open("/proc/self/fd"', supervisor_source)
        self.assertIn("close_payload_cgroup_controls();", supervisor_source)
        self.assertEqual(0o2710, controller._SUPERVISOR_CGROUP_MODE_V27)
        self.assertEqual(0o2710, controller._PAYLOAD_CGROUP_MODE_V27)
        self.assertEqual(0o770, controller._LIFECYCLE_CGROUP_MODE_V27)
        self.assertEqual(0o750, controller._SPLIT_RUNTIME_MODE_V27)
        self.assertEqual(0o755, controller._SPLIT_PAYLOAD_MODE_V27)
        self.assertEqual(0, controller._SUPERVISOR_CGROUP_MODE_V27 & 0o007)
        self.assertEqual(0, controller._PAYLOAD_CGROUP_MODE_V27 & 0o007)
        create_custody = controller_source[
            controller_source.index("def _create_controller_cgroup_custody_v27") :
            controller_source.index("def _validate_worker_cgroup_transfer_v27")
        ]
        self.assertNotIn("fchown", create_custody)
        self.assertNotIn("os.chown", create_custody)

        execute_source = controller_source[
            controller_source.index("    def execute(", controller_source.index("class _WorkerChannelV27")) :
            controller_source.index("    def recover(", controller_source.index("class _WorkerChannelV27"))
        ]
        send_execute = execute_source.index("self.channel.sendmsg")
        placement = execute_source.index("custody.place_lifecycle_child", send_execute)
        receive_result = execute_source.index(
            "_recv_credentialed_packet_v27", send_execute
        )
        drain_payload = execute_source.index("custody.drain(")
        self.assertLess(send_execute, receive_result)
        self.assertLess(receive_result, placement)
        self.assertLess(receive_result, drain_payload)
        self.assertNotIn("self._place_worker", execute_source)

    def test_podman_payload_label_matches_the_installed_transition_type(self) -> None:
        supervisor_source = (
            ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c"
        ).read_text()
        policy = (
            ROOT / "runtime/beads-v27/startup_factory_beads_v27.te"
        ).read_text()
        self.assertIn(
            'label=type:startup_factory_beads_payload_t', supervisor_source
        )
        self.assertNotIn('label=type:beads_worker_t', supervisor_source)
        self.assertIn(
            "allow startup_factory_beads_runtime_t startup_factory_beads_payload_t:process transition;",
            policy,
        )

    def test_persistent_worker_move_binds_pidfd_start_time_and_exact_target(self) -> None:
        proc_root = Path(self.temporary.name) / "placement-proc"
        worker_pid = 4242
        worker = proc_root / str(worker_pid)
        worker.mkdir(parents=True)
        # Fields after the closing comm start at field 3; index 19 is starttime.
        (worker / "stat").write_bytes(
            b"4242 (worker) S " + b"1 " * 18 + b"98765 0 0\n"
        )
        target = "/service/supervisor/payload-" + "a" * 64 + "-s1-" + "b" * 16
        (worker / "cgroup").write_bytes(f"0::{target}\n".encode())
        process_path = Path(self.temporary.name) / "placement-procs"
        process_path.write_bytes(b"")
        process_fd = os.open(process_path, os.O_WRONLY)
        pidfd_read, pidfd_write = os.pipe()
        try:
            observed = controller._place_persistent_worker_v27(
                process_fd,
                worker_pid=worker_pid,
                pidfd=pidfd_read,
                start_time="98765",
                expected_relative=target,
                proc_root=proc_root,
            )
            self.assertEqual(target, observed["cgroupRelative"])
            self.assertEqual(b"4242\n", process_path.read_bytes())
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "PID identity changed"
            ):
                controller._place_persistent_worker_v27(
                    process_fd,
                    worker_pid=worker_pid,
                    pidfd=pidfd_read,
                    start_time="98766",
                    expected_relative=target,
                    proc_root=proc_root,
                )
            (worker / "cgroup").write_bytes(b"0::/service/supervisor\n")
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "exact controller-issued cgroup"
            ):
                controller._place_persistent_worker_v27(
                    process_fd,
                    worker_pid=worker_pid,
                    pidfd=pidfd_read,
                    start_time="98765",
                    expected_relative=target,
                    proc_root=proc_root,
                )
        finally:
            os.close(process_fd)
            os.close(pidfd_read)
            os.close(pidfd_write)

    def test_public_claim_and_receipt_do_not_treat_caller_observations_as_authority(self) -> None:
        protected = (ROOT / "src/startup_factory_cli/beads_protected_runtime.py").read_text()
        advance = protected[
            protected.index("def advance_atomic_claim_v1") :
            protected.index("def record_atomic_claim_receipt_v1")
        ]
        receipt_start = protected.index("def record_atomic_claim_receipt_v1")
        receipt = protected[
            receipt_start : protected.index("def _current_authority", receipt_start)
        ]
        for forbidden in (
            'payload["claimSucceeded"]',
            'payload["observedRevision"]',
            'payload["observedStatus"]',
        ):
            self.assertNotIn(forbidden, advance)
        for forbidden in (
            'payload["readBackRevision"]',
            'payload["readBackStatus"]',
            'payload["claimIdentitySha256"]',
        ):
            self.assertNotIn(forbidden, receipt)
        self.assertIn("authorization_record_sha256=prior.record_sha256", advance)
        self.assertIn("authorization_record_sha256=lease.record_sha256", receipt)
        controller_source = Path(controller.__file__).read_text()
        self.assertIn('operation_class = "claim-cas"', controller_source)
        self.assertIn('operation_class = "receipt-comment"', controller_source)

    def test_worker_drop_sanitizes_environment_and_proves_dac_denial(self) -> None:
        account = types.SimpleNamespace(
            pw_uid=self.config.worker_uid,
            pw_gid=82_003,
            pw_dir="/var/lib/startup-factory/beads-worker",
            pw_name="startup-factory-beads-worker",
        )
        with mock.patch.dict(
            controller.os.environ,
            {"AWS_SECRET_ACCESS_KEY": "must-disappear"},
            clear=True,
        ), mock.patch.object(
            controller.pwd, "getpwuid", return_value=account
        ), mock.patch.object(
            controller.os, "setgroups"
        ) as setgroups, mock.patch.object(
            controller.os, "setgid"
        ) as setgid, mock.patch.object(
            controller.os, "setuid"
        ) as setuid, mock.patch.object(
            controller.os, "geteuid", return_value=self.config.worker_uid
        ), mock.patch.object(
            controller.os, "getegid", return_value=account.pw_gid
        ), mock.patch.object(
            controller.os, "getgroups", return_value=[]
        ), mock.patch.object(
            controller.os, "open", side_effect=PermissionError("denied")
        ) as opened:
            controller._drop_to_worker_identity_v27(self.config)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", controller.os.environ)
            self.assertEqual(
                {
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "LOGNAME",
                    "PATH",
                    "USER",
                    "XDG_RUNTIME_DIR",
                },
                set(controller.os.environ),
            )
        setgroups.assert_called_once_with([])
        setgid.assert_called_once_with(account.pw_gid)
        setuid.assert_called_once_with(self.config.worker_uid)
        self.assertEqual(6, opened.call_count)

    def test_worker_result_root_label_is_verified_after_drop_without_capabilities(self) -> None:
        metadata = types.SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=self.config.worker_uid,
            st_gid=82_003,
            st_nlink=2,
        )
        with mock.patch.object(
            controller.os, "open", return_value=37
        ) as opened, mock.patch.object(
            controller.os, "fstat", return_value=metadata
        ), mock.patch.object(
            controller.os,
            "getxattr",
            return_value=(controller._WORKER_RESULT_SELINUX_CONTEXT_V27 + b"\0"),
            create=True,
        ), mock.patch.object(
            controller.os, "getegid", return_value=82_003
        ), mock.patch.object(
            controller.os, "close"
        ) as closed, mock.patch.object(
            controller, "_assert_worker_has_no_linux_capabilities_v27"
        ) as no_caps:
            controller._verify_worker_result_root_label_v27(self.config)
        self.assertEqual(
            Path(f"/run/user/{self.config.worker_uid}/startup-factory-beads-results"),
            opened.call_args.args[0],
        )
        no_caps.assert_called_once_with()
        closed.assert_called_once_with(37)

        with mock.patch.object(
            controller.os, "open", return_value=38
        ), mock.patch.object(
            controller.os, "fstat", return_value=metadata
        ), mock.patch.object(
            controller.os,
            "getxattr",
            return_value=b"unconfined_u:object_r:user_tmp_t:s0",
            create=True,
        ), mock.patch.object(
            controller.os, "getegid", return_value=82_003
        ), mock.patch.object(
            controller.os, "close"
        ), mock.patch.object(
            controller, "_assert_worker_has_no_linux_capabilities_v27"
        ):
            with self.assertRaisesRegex(
                controller.ControllerProtocolError,
                "result root SELinux label",
            ):
                controller._verify_worker_result_root_label_v27(self.config)

    def test_worker_capability_state_must_be_zero_before_readiness(self) -> None:
        zero = (
            b"Name:\tworker\n"
            b"CapInh:\t0000000000000000\n"
            b"CapPrm:\t0000000000000000\n"
            b"CapEff:\t0000000000000000\n"
            b"CapAmb:\t0000000000000000\n"
        )
        controller._validate_zero_worker_capabilities_v27(zero)
        with self.assertRaisesRegex(
            controller.ControllerProtocolError, "retained Linux capabilities"
        ):
            controller._validate_zero_worker_capabilities_v27(
                zero.replace(
                    b"CapEff:\t0000000000000000",
                    b"CapEff:\t0000000000000001",
                )
            )

    def test_serve_preflight_rejects_unrelated_symlinked_or_stale_live_module(self) -> None:
        live_module = Path(controller.__file__)
        live_bytes = live_module.read_bytes()
        config = controller.dataclasses.replace(
            self.config,
            module_path=live_module,
            module_sha256=controller._sha(live_bytes),
        )
        values = {
            config.runtime_manifest_path: b"runtime-manifest-bytes",
            config.module_path: live_bytes,
            config.schema_path: b"schema-bytes",
            config.native_boundary_manifest_path: (
                ROOT / "runtime/beads-native-boundary-v27.example.json"
            ).read_bytes(),
            config.native_module_path: config.native_module_path.read_bytes(),
        }
        config = controller.dataclasses.replace(
            config,
            runtime_manifest_sha256=controller._sha(values[config.runtime_manifest_path]),
            schema_sha256=controller._sha(values[config.schema_path]),
            native_boundary_manifest_sha256=controller._sha(
                values[config.native_boundary_manifest_path]
            ),
            native_module_sha256=controller._sha(values[config.native_module_path]),
        )

        def read_exact(path, _label, **_kwargs):
            return values[path]

        with mock.patch.object(controller, "_read_root_owned", side_effect=read_exact):
            controller._verify_installed_artifacts(config)

        unrelated = controller.dataclasses.replace(
            config, module_path=config.runtime_manifest_path
        )
        with mock.patch.object(controller, "_read_root_owned", side_effect=read_exact):
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "executing controller module"
            ):
                controller._verify_installed_artifacts(unrelated)

        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "controller.py"
            link.symlink_to(live_module)
            symlinked = controller.dataclasses.replace(config, module_path=link)
            with mock.patch.object(
                controller,
                "_read_root_owned",
                return_value=live_bytes,
            ):
                with self.assertRaisesRegex(
                    controller.ControllerProtocolError,
                    "executing controller module|symbolic link",
                ):
                    controller._verify_installed_artifacts(symlinked)

        stale_identity = tuple(
            value + 1 if index == 1 else value
            for index, value in enumerate(controller._EXECUTING_MODULE_IDENTITY)
        )
        with mock.patch.object(controller, "_read_root_owned", side_effect=read_exact), mock.patch.object(
            controller, "_EXECUTING_MODULE_IDENTITY", stale_identity
        ):
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "changed since import"
            ):
                controller._verify_installed_artifacts(config)

        specification = sys.modules[controller.__name__].__spec__
        assert specification is not None
        with mock.patch.object(controller, "_read_root_owned", side_effect=read_exact), mock.patch.object(
            specification, "origin", str(config.runtime_manifest_path)
        ):
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "module specification origin"
            ):
                controller._verify_installed_artifacts(config)

    def test_client_checks_fixed_endpoint_local_broker_and_controller_peer(self) -> None:
        request = self.open_request()

        class FakeConnection:
            def __init__(self, peer_uid: int) -> None:
                self.peer_uid = peer_uid
                self.sent = b""
                self.received = False
                self.connected = None

            def settimeout(self, _value):
                pass

            def connect(self, value):
                self.connected = value

            def getsockopt(self, _level, _option, _size):
                return struct.pack("3i", 44_001, self.peer_uid, 44_002)

            def sendall(self, value):
                self.sent = value

            def recv(self, _size):
                if self.received:
                    return b""
                self.received = True
                packet = json.loads(self.sent)
                return controller._canonical(
                    controller._sign_response(
                        self.key,
                        "OPEN",
                        {
                            "status": "accepted",
                            "state": "accepted",
                            "requestSha256": controller._sha(self.sent),
                            "operationId": packet["request"]["operationId"],
                            "sessionNonce": "server-session-nonce-00000001",
                            "resultSha256": None,
                        },
                    )
                )

            def close(self):
                pass

        accepted = FakeConnection(self.config.controller_uid)
        accepted.key = self.key
        with mock.patch.object(controller.sys, "platform", "linux"), mock.patch.object(controller.socket, "SO_PEERCRED", 17, create=True), mock.patch.object(controller.os, "geteuid", return_value=self.config.broker_uid), mock.patch.object(
            controller, "_endpoint_metadata"
        ), mock.patch.object(
            controller, "_validate_endpoint_parent"
        ), mock.patch.object(
            controller, "_validate_transport_group"
        ), mock.patch.object(controller.socket, "socket", return_value=accepted):
            response = controller._request("OPEN", request, self.config)
        self.assertEqual(str(controller.ENDPOINT_PATH), accepted.connected)
        self.assertEqual("accepted", response["state"])

        wrong_peer = FakeConnection(self.config.worker_uid)
        wrong_peer.key = self.key
        with mock.patch.object(controller.sys, "platform", "linux"), mock.patch.object(controller.socket, "SO_PEERCRED", 17, create=True), mock.patch.object(controller.os, "geteuid", return_value=self.config.broker_uid), mock.patch.object(
            controller, "_endpoint_metadata"
        ), mock.patch.object(
            controller, "_validate_endpoint_parent"
        ), mock.patch.object(
            controller, "_validate_transport_group"
        ), mock.patch.object(controller.socket, "socket", return_value=wrong_peer):
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "controller UID"
            ):
                controller._request("OPEN", request, self.config)

        with mock.patch.object(controller.sys, "platform", "linux"), mock.patch.object(controller.os, "geteuid", return_value=self.config.worker_uid):
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "configured broker UID"
            ):
                controller._request("OPEN", request, self.config)


if __name__ == "__main__":
    unittest.main(verbosity=2)
