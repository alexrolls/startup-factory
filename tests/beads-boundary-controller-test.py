#!/usr/bin/env python3
"""Offline protocol tests for the fixed Linux Beads boundary controller."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
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
            "transportGid": self.config.transport_gid,
            "runtimeManifestPath": str(self.config.runtime_manifest_path),
            "modulePath": str(self.config.module_path),
            "schemaPath": str(self.config.schema_path),
            "runtimeManifestSha256": self.config.runtime_manifest_sha256,
            "moduleSha256": self.config.module_sha256,
            "schemaSha256": self.config.schema_sha256,
            "configEpoch": self.config.config_epoch,
            "keyEpoch": self.config.key_epoch,
            "allowedOperations": list(controller.ALLOWED_OPERATIONS),
        }
        self.assertEqual(self.config, controller._parse_config(value))
        for mutation in (
            {"schemaVersion": True},
            {"endpointPath": "/tmp/caller.sock"},
            {"workerUid": self.config.broker_uid},
            {"transportGid": True},
            {"allowedOperations": list(controller.ALLOWED_OPERATIONS[:-1])},
            {"unexpectedOverride": "/tmp/escape"},
            {"moduleSha256": "sha256:" + "0" * 64},
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
        self.assertEqual(str(controller.CONFIG_PATH), "/etc/startup-factory/beads-boundary-controller-v1.json")

        service = (
            ROOT / "runtime/startup-factory-beads-controller.service.example"
        ).read_text()
        socket_unit = (
            ROOT / "runtime/startup-factory-beads-controller.socket.example"
        ).read_text()
        self.assertIn("Restart=on-failure", service)
        self.assertIn("UMask=0007", service)
        self.assertIn("SocketMode=0660", socket_unit)
        self.assertIn("DirectoryMode=0750", socket_unit)
        self.assertIn("SocketGroup=startup-factory-beads-transport", socket_unit)

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

    def test_serve_preflight_observes_exact_root_owned_artifacts(self) -> None:
        values = {
            self.config.runtime_manifest_path: b"runtime-manifest-bytes",
            self.config.module_path: b"module-bytes",
            self.config.schema_path: b"schema-bytes",
        }
        config = controller.dataclasses.replace(
            self.config,
            runtime_manifest_sha256=controller._sha(values[self.config.runtime_manifest_path]),
            module_sha256=controller._sha(values[self.config.module_path]),
            schema_sha256=controller._sha(values[self.config.schema_path]),
        )
        with mock.patch.object(
            controller,
            "_read_root_owned",
            side_effect=lambda path, _label, **_kwargs: values[path],
        ) as observed:
            controller._verify_installed_artifacts(config)
        self.assertEqual(3, observed.call_count)

        with mock.patch.object(
            controller,
            "_read_root_owned",
            side_effect=lambda path, _label, **_kwargs: values[path] + b"tampered",
        ):
            with self.assertRaisesRegex(
                controller.ControllerProtocolError, "installed artifact digest"
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
