#!/usr/bin/env python3
"""Offline protocol tests for the fixed Linux Beads boundary controller."""

from __future__ import annotations

import hashlib
import importlib
import json
import struct
import sys
import tempfile
import time
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


class BoundaryControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state_root = Path(self.temporary.name) / "state"
        self.state_root.mkdir(mode=0o700)
        self.key = b"controller-test-domain-key-material-32-bytes"
        self.config = controller.ControllerConfig(
            protected_root=Path("/var/lib/startup-factory/beads-protected-runtime"),
            record_hmac_key_path=Path(
                "/var/lib/startup-factory/beads-protected-runtime/records.hmac"
            ),
            controller_uid=81_001,
            broker_uid=81_002,
            worker_uid=81_003,
            runtime_manifest_sha256=digest("runtime"),
            module_sha256=digest("module"),
            schema_sha256=digest("schema"),
            config_epoch=4,
            key_epoch=7,
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

    def test_closed_config_pins_paths_roles_operations_and_identity(self) -> None:
        value = {
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
            "runtimeManifestSha256": self.config.runtime_manifest_sha256,
            "moduleSha256": self.config.module_sha256,
            "schemaSha256": self.config.schema_sha256,
            "configEpoch": self.config.config_epoch,
            "keyEpoch": self.config.key_epoch,
            "allowedOperations": list(controller.ALLOWED_OPERATIONS),
        }
        self.assertEqual(self.config, controller._parse_config(value))
        for mutation in (
            {"endpointPath": "/tmp/caller.sock"},
            {"workerUid": self.config.broker_uid},
            {"allowedOperations": list(controller.ALLOWED_OPERATIONS[:-1])},
            {"unexpectedOverride": "/tmp/escape"},
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
        self.assertEqual(str(controller.CONFIG_PATH), "/etc/startup-factory/beads-boundary-controller-v1.json")

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
        ), mock.patch.object(controller.socket, "socket", return_value=accepted):
            response = controller._request("OPEN", request, self.config)
        self.assertEqual(str(controller.ENDPOINT_PATH), accepted.connected)
        self.assertEqual("accepted", response["state"])

        wrong_peer = FakeConnection(self.config.worker_uid)
        wrong_peer.key = self.key
        with mock.patch.object(controller.sys, "platform", "linux"), mock.patch.object(controller.socket, "SO_PEERCRED", 17, create=True), mock.patch.object(controller.os, "geteuid", return_value=self.config.broker_uid), mock.patch.object(
            controller, "_endpoint_metadata"
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
