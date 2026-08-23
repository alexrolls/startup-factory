"""Fixed Linux controller protocol for protected Beads runtime authority.

The production client deliberately has no configuration, endpoint, key, or
verifier parameter.  It reads one root-owned closed configuration and connects
to one root-owned AF_UNIX SOCK_SEQPACKET endpoint.  Stored controller receipts
are evidence only: callers must validate them through a fresh authenticated
connection before using current authority.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any, Final, Mapping


CONFIG_PATH: Final = Path("/etc/startup-factory/beads-boundary-controller-v1.json")
ENDPOINT_PATH: Final = Path("/run/startup-factory/beads-boundary-controller-v1.sock")
STATE_ROOT: Final = Path("/var/lib/startup-factory/beads-boundary-controller/v1")
CONTROLLER_KEY_PATH: Final = Path("/etc/startup-factory/beads-boundary-controller-v1.key")
PROTOCOL: Final = "startup-factory/beads-boundary-controller/v1"
PRODUCTION_PROVENANCE: Final = "startup-factory/beads-boundary-controller/production/v1"
MAX_MESSAGE_BYTES: Final = 1_048_576
MAX_CLOCK_SKEW_SECONDS: Final = 30
MAX_OPERATION_SECONDS: Final = 300
_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_NONCE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9._:-]{15,255}\Z")
_OPERATION_ID = re.compile(r"\A[0-9a-f]{64}\Z")
_HMAC = re.compile(r"\Ahmac-sha256:[0-9a-f]{64}\Z")

ALLOWED_OPERATIONS: Final = (
    "prepare_atomic_claim_v1",
    "advance_atomic_claim_v1",
    "record_atomic_claim_receipt_v1",
    "authorize_claim_launch_v1",
    "begin_beads_mutation_v1",
    "finish_beads_mutation_v1",
    "verify_beads_installed_database_selector_v1",
    "authorize_beads_preparation_v1",
    "begin_beads_preparation_v1",
    "observe_beads_store_v1",
    "advance_beads_preparation_v1",
    "derive_beads_status_profile_dynamic_bindings_v1",
    "finish_beads_preparation_v1",
    "verify_current_beads_preparation_v1",
    "verify_historical_beads_preparation_v1",
    "record_beads_change_plan_core_v1",
    "verify_beads_change_plan_core_record_v1",
    "authorize_beads_authority_transition_v1",
    "revoke_beads_authority_epoch_v1",
    "stage_beads_authority_epoch_v1",
    "activate_beads_authority_epoch_v1",
    "verify_active_beads_authority_v1",
    "verify_beads_authority_transition_receipt_v1",
    "authorize_beads_runtime_api_manifest_record_v1",
    "record_beads_protected_runtime_api_manifest_v1",
    "verify_current_beads_protected_runtime_api_manifest_v1",
    "verify_historical_beads_protected_runtime_api_manifest_v1",
    "authorize_beads_adapter_release_manifest_record_v1",
    "record_beads_adapter_release_manifest_v1",
    "verify_current_beads_adapter_release_manifest_v1",
)

_CONFIG_FIELDS = {
    "schemaVersion",
    "protocol",
    "endpointPath",
    "stateRoot",
    "controllerKeyPath",
    "protectedRoot",
    "recordHmacKeyPath",
    "controllerUid",
    "brokerUid",
    "workerUid",
    "runtimeManifestSha256",
    "moduleSha256",
    "schemaSha256",
    "configEpoch",
    "keyEpoch",
    "allowedOperations",
}
_REQUEST_FIELDS = {"schemaVersion", "protocol", "action", "request"}
_OPEN_FIELDS = {
    "operationId",
    "clientNonce",
    "operation",
    "repositoryLocatorSha256",
    "rootSetSha256",
    "requestSha256",
    "runtimeManifestSha256",
    "moduleSha256",
    "schemaSha256",
    "configEpoch",
    "keyEpoch",
    "issuedAtUnix",
    "expiresAtUnix",
}
_STEP_FIELDS = {
    "operationId",
    "sessionNonce",
    "stepNonce",
    "predecessorReceiptSha256",
    "targetState",
    "transactionIntentSha256",
    "resultSha256",
}
_VALIDATE_FIELDS = {
    "operationId",
    "validationNonce",
    "storedReceiptSha256",
    "expectedState",
    "expectedResultSha256",
}
_RESPONSE_FIELDS = {
    "schemaVersion",
    "protocol",
    "action",
    "provenanceDomain",
    "status",
    "state",
    "requestSha256",
    "operationId",
    "sessionNonce",
    "resultSha256",
    "controllerHmac",
    "receiptSha256",
}
_STATES = ("accepted", "intent-bound", "effect-authorized", "result-stored", "completed")


class ControllerProtocolError(RuntimeError):
    """A fixed controller/config/protocol invariant failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise ControllerProtocolError(f"controller value is not canonical JSON: {exc}") from exc
    if not encoded or len(encoded) > MAX_MESSAGE_BYTES:
        raise ControllerProtocolError("controller message is empty or oversized")
    return encoded


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _closed_mapping(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ControllerProtocolError(f"{label} has an unknown or missing field")
    return value


def _digest(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ControllerProtocolError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 99_999_999_999_999_999_999:
        raise ControllerProtocolError(f"{label} must be a bounded positive integer")
    return value


@dataclasses.dataclass(frozen=True, slots=True)
class ControllerConfig:
    protected_root: Path
    record_hmac_key_path: Path
    controller_uid: int
    broker_uid: int
    worker_uid: int
    runtime_manifest_sha256: str
    module_sha256: str
    schema_sha256: str
    config_epoch: int
    key_epoch: int

    @property
    def root_set_sha256(self) -> str:
        return _sha(_canonical({
            "protectedRoot": str(self.protected_root),
            "recordHmacKeyPath": str(self.record_hmac_key_path),
        }))


def _parse_config(value: Any) -> ControllerConfig:
    data = _closed_mapping(value, _CONFIG_FIELDS, "controller configuration")
    if data["schemaVersion"] != 1 or data["protocol"] != PROTOCOL:
        raise ControllerProtocolError("controller configuration schema/protocol mismatch")
    if data["endpointPath"] != str(ENDPOINT_PATH) or data["stateRoot"] != str(STATE_ROOT) or data["controllerKeyPath"] != str(CONTROLLER_KEY_PATH):
        raise ControllerProtocolError("controller configuration changed a fixed path")
    protected = Path(str(data["protectedRoot"]))
    record_key = Path(str(data["recordHmacKeyPath"]))
    if (
        not protected.is_absolute()
        or str(protected) != os.path.normpath(str(protected))
        or not record_key.is_absolute()
        or str(record_key) != os.path.normpath(str(record_key))
        or record_key.parent != protected
    ):
        raise ControllerProtocolError("protected root/key must be normalized absolute configured paths")
    identities = tuple(_positive_int(data[name], name) for name in ("controllerUid", "brokerUid", "workerUid"))
    if len(set(identities)) != 3:
        raise ControllerProtocolError("controller, broker, and worker UIDs must be distinct")
    operations = data["allowedOperations"]
    if not isinstance(operations, list) or tuple(operations) != ALLOWED_OPERATIONS:
        raise ControllerProtocolError("controller operation set differs from the closed production set")
    return ControllerConfig(
        protected_root=protected,
        record_hmac_key_path=record_key,
        controller_uid=identities[0],
        broker_uid=identities[1],
        worker_uid=identities[2],
        runtime_manifest_sha256=str(_digest(data["runtimeManifestSha256"], "runtimeManifestSha256")),
        module_sha256=str(_digest(data["moduleSha256"], "moduleSha256")),
        schema_sha256=str(_digest(data["schemaSha256"], "schemaSha256")),
        config_epoch=_positive_int(data["configEpoch"], "configEpoch"),
        key_epoch=_positive_int(data["keyEpoch"], "keyEpoch"),
    )


def _read_root_owned(path: Path, label: str, *, max_bytes: int = MAX_MESSAGE_BYTES, executable: bool = False) -> bytes:
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1:
            raise ControllerProtocolError(f"{label} must be a root-owned single-link regular file")
        # Root-owned public configuration/source may be readable by the
        # dedicated controller UID, but is never group/other writable.  Secret
        # controller material has a separate controller-owned mode-0600 check.
        forbidden = 0o022
        if stat.S_IMODE(before.st_mode) & forbidden:
            raise ControllerProtocolError(f"{label} permissions are unsafe")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_nlink, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink, before.st_size
            ):
                raise ControllerProtocolError(f"{label} changed before open")
            data = bytearray()
            while len(data) <= max_bytes:
                chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(fd)
            if len(data) > max_bytes or (after.st_dev, after.st_ino, after.st_size, after.st_mode) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode
            ):
                raise ControllerProtocolError(f"{label} is oversized or changed while read")
            return bytes(data)
        finally:
            os.close(fd)
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot read {label}: {exc}") from exc


def load_controller_config() -> ControllerConfig:
    """Load only the fixed root-owned production configuration."""

    raw = _read_root_owned(CONFIG_PATH, "Beads boundary controller configuration")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("controller configuration contains malformed JSON") from exc
    if raw not in {_canonical(value), _canonical(value) + b"\n"}:
        raise ControllerProtocolError("controller configuration is not exact canonical JSON")
    return _parse_config(value)


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"):
        raise ControllerProtocolError("SO_PEERCRED controller protocol requires Linux")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _endpoint_metadata(config: ControllerConfig) -> None:
    try:
        info = os.lstat(ENDPOINT_PATH)
    except OSError as exc:
        raise ControllerProtocolError(f"fixed controller endpoint is unavailable: {exc}") from exc
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != config.controller_uid or stat.S_IMODE(info.st_mode) & 0o077:
        raise ControllerProtocolError("fixed controller endpoint owner/mode/type is unsafe")


def _validate_controller_directory(path: Path, config: ControllerConfig, label: str) -> None:
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ControllerProtocolError(f"{label} path is not normalized and absolute")
    descriptor = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != config.controller_uid
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ControllerProtocolError(
                f"{label} must be a controller-owned private directory"
            )
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot open fixed {label}: {exc}") from exc
    finally:
        os.close(descriptor)


def _request(action: str, request: Mapping[str, Any], config: ControllerConfig) -> dict[str, Any]:
    if not sys.platform.startswith("linux"):
        raise ControllerProtocolError("fixed Beads boundary controller requires Linux")
    if os.geteuid() != config.broker_uid:
        raise ControllerProtocolError(
            "client process is not the distinct configured broker UID"
        )
    _endpoint_metadata(config)
    packet = {"schemaVersion": 1, "protocol": PROTOCOL, "action": action, "request": dict(request)}
    encoded = _canonical(packet)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        connection.settimeout(5.0)
        connection.connect(str(ENDPOINT_PATH))
        _, peer_uid, _ = _peer_credentials(connection)
        if peer_uid != config.controller_uid or peer_uid in {config.broker_uid, config.worker_uid}:
            raise ControllerProtocolError("controller peer credential does not match the distinct configured controller UID")
        connection.sendall(encoded)
        response = connection.recv(MAX_MESSAGE_BYTES + 1)
        if not response or len(response) > MAX_MESSAGE_BYTES:
            raise ControllerProtocolError("controller response is empty or oversized")
        extra = connection.recv(1)
        if extra:
            raise ControllerProtocolError("controller sent more than one response packet")
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"fixed controller exchange failed: {exc}") from exc
    finally:
        connection.close()
    try:
        value = json.loads(response)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("controller returned malformed JSON") from exc
    if not isinstance(value, dict) or set(value) != _RESPONSE_FIELDS or _canonical(value) != response:
        raise ControllerProtocolError("controller response is not a canonical closed object")
    if value.get("schemaVersion") != 1 or value.get("protocol") != PROTOCOL or value.get("action") != action or value.get("requestSha256") != _sha(encoded):
        raise ControllerProtocolError("controller response does not bind the exact request")
    if value.get("provenanceDomain") != PRODUCTION_PROVENANCE or value.get("status") not in {"accepted", "completed", "validated"}:
        raise ControllerProtocolError("controller response is not live production provenance")
    _digest(value.get("receiptSha256"), "receiptSha256")
    if not isinstance(value.get("controllerHmac"), str) or not value["controllerHmac"].startswith("hmac-sha256:"):
        raise ControllerProtocolError("controller response lacks controller-only HMAC evidence")
    receipt_material = dict(value)
    receipt_sha256 = receipt_material.pop("receiptSha256")
    if receipt_sha256 != _sha(_canonical(receipt_material)):
        raise ControllerProtocolError("controller response receipt digest is invalid")
    if not _OPERATION_ID.fullmatch(str(value.get("operationId", ""))):
        raise ControllerProtocolError("controller response operationId is invalid")
    if not isinstance(value.get("sessionNonce"), str) or not _NONCE.fullmatch(value["sessionNonce"]):
        raise ControllerProtocolError("controller response session nonce is invalid")
    _digest(value.get("resultSha256"), "resultSha256", nullable=True)
    return value


def open_operation(operation: str, binding: Mapping[str, Any]) -> tuple[ControllerConfig, dict[str, Any]]:
    config = load_controller_config()
    if operation not in ALLOWED_OPERATIONS:
        raise ControllerProtocolError("operation is outside the fixed controller set")
    now = int(time.time())
    request = {
        "operationId": hashlib.sha256(_canonical({"operation": operation, "binding": dict(binding)})).hexdigest(),
        "clientNonce": secrets.token_hex(32),
        "operation": operation,
        "repositoryLocatorSha256": binding["repositoryLocatorSha256"],
        "rootSetSha256": config.root_set_sha256,
        "requestSha256": binding["requestSha256"],
        "runtimeManifestSha256": config.runtime_manifest_sha256,
        "moduleSha256": config.module_sha256,
        "schemaSha256": config.schema_sha256,
        "configEpoch": config.config_epoch,
        "keyEpoch": config.key_epoch,
        "issuedAtUnix": now,
        "expiresAtUnix": now + MAX_OPERATION_SECONDS,
    }
    response = _request("OPEN", request, config)
    if (
        response.get("operationId") != request["operationId"]
        or response.get("state") not in {"accepted", "completed"}
        or response.get("status") != (
            "completed" if response.get("state") == "completed" else "accepted"
        )
    ):
        raise ControllerProtocolError("OPEN response changed the exact operation state")
    return config, response


def step_operation(config: ControllerConfig, session: Mapping[str, Any], target_state: str, *, transaction_intent_sha256: str | None, result_sha256: str | None) -> dict[str, Any]:
    if target_state not in _STATES[1:]:
        raise ControllerProtocolError("invalid controller STEP target")
    request = {
        "operationId": session["operationId"],
        "sessionNonce": session["sessionNonce"],
        "stepNonce": secrets.token_hex(32),
        "predecessorReceiptSha256": session["receiptSha256"],
        "targetState": target_state,
        "transactionIntentSha256": transaction_intent_sha256,
        "resultSha256": result_sha256,
    }
    response = _request("STEP", request, config)
    if (
        response.get("operationId") != session.get("operationId")
        or response.get("sessionNonce") != session.get("sessionNonce")
        or response.get("state") != target_state
        or response.get("status")
        != ("completed" if target_state == "completed" else "accepted")
        or response.get("resultSha256") != result_sha256
    ):
        raise ControllerProtocolError("STEP response changed the exact requested successor")
    return response


def validate_stored_receipt(config: ControllerConfig, *, operation_id: str, stored_receipt_sha256: str, expected_state: str, expected_result_sha256: str | None) -> dict[str, Any]:
    request = {
        "operationId": operation_id,
        "validationNonce": secrets.token_hex(32),
        "storedReceiptSha256": stored_receipt_sha256,
        "expectedState": expected_state,
        "expectedResultSha256": expected_result_sha256,
    }
    response = _request("VALIDATE", request, config)
    if (
        response.get("operationId") != operation_id
        or response.get("state") != expected_state
        or response.get("status") != "validated"
        or response.get("resultSha256") != expected_result_sha256
    ):
        raise ControllerProtocolError(
            "VALIDATE response changed the exact stored controller result"
        )
    return response


# Controller implementation.  It deliberately shares no client override path.
def _sign_response(key: bytes, action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    body = {**dict(payload), "schemaVersion": 1, "protocol": PROTOCOL, "action": action, "provenanceDomain": PRODUCTION_PROVENANCE}
    material = _canonical(body)
    auth = "hmac-sha256:" + hmac.new(key, (PROTOCOL + "/" + action + "\0").encode() + material, hashlib.sha256).hexdigest()
    result = {**body, "controllerHmac": auth}
    result["receiptSha256"] = _sha(_canonical(result))
    return result


def _state_file(operation_id: str) -> Path:
    if not _OPERATION_ID.fullmatch(operation_id):
        raise ControllerProtocolError("invalid operationId")
    return STATE_ROOT / f"{operation_id}.json"


def _read_state_bytes(path: Path, *, missing_ok: bool = False) -> bytes | None:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ControllerProtocolError("controller operation state does not exist")
    except OSError as exc:
        raise ControllerProtocolError(f"cannot inspect controller state: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o077
        or before.st_size > MAX_MESSAGE_BYTES
    ):
        raise ControllerProtocolError("controller operation state metadata is unsafe")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_mode, before.st_size
            ):
                raise ControllerProtocolError("controller state changed before open")
            data = os.read(descriptor, MAX_MESSAGE_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot read controller state: {exc}") from exc
    if (
        len(data) > MAX_MESSAGE_BYTES
        or (after.st_dev, after.st_ino, after.st_mode, after.st_size)
        != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size)
    ):
        raise ControllerProtocolError("controller state changed during read")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("controller state contains malformed JSON") from exc
    if not isinstance(value, dict) or _canonical(value) != data:
        raise ControllerProtocolError("controller state is not exact canonical JSON")
    return data


def _load_state(
    path: Path,
    key: bytes,
    *,
    missing_ok: bool = False,
) -> tuple[bytes, dict[str, Any]] | None:
    raw = _read_state_bytes(path, missing_ok=missing_ok)
    if raw is None:
        return None
    value = json.loads(raw)
    state = value.get("state")
    fields = {
        "openBindingSha256",
        "expiresAtUnix",
        "state",
        "usedNonces",
        "response",
    }
    if state != "accepted":
        fields.add("transactionIntentSha256")
    data = _closed_mapping(value, fields, "controller durable state")
    _digest(data["openBindingSha256"], "state openBindingSha256")
    _positive_int(data["expiresAtUnix"], "state expiresAtUnix")
    if state not in _STATES:
        raise ControllerProtocolError("controller durable state has an unknown state")
    if state != "accepted":
        _digest(data["transactionIntentSha256"], "state transactionIntentSha256")
    nonces = data["usedNonces"]
    if (
        not isinstance(nonces, list)
        or not nonces
        or len(nonces) != len(set(nonces))
        or any(not isinstance(nonce, str) or not _NONCE.fullmatch(nonce) for nonce in nonces)
    ):
        raise ControllerProtocolError("controller durable state has an invalid nonce set")
    response = _closed_mapping(data["response"], _RESPONSE_FIELDS, "stored controller response")
    if (
        response["schemaVersion"] != 1
        or response["protocol"] != PROTOCOL
        or response["provenanceDomain"] != PRODUCTION_PROVENANCE
        or response["action"] not in {"OPEN", "STEP"}
        or response["state"] != state
        or response["operationId"] != path.stem
        or not isinstance(response["sessionNonce"], str)
        or not _NONCE.fullmatch(response["sessionNonce"])
        or not isinstance(response["controllerHmac"], str)
        or not _HMAC.fullmatch(response["controllerHmac"])
    ):
        raise ControllerProtocolError("stored controller response identity is invalid")
    _digest(response["requestSha256"], "stored response requestSha256")
    _digest(response["receiptSha256"], "stored response receiptSha256")
    _digest(response["resultSha256"], "stored response resultSha256", nullable=True)
    expected_status = "completed" if state == "completed" else "accepted"
    if response["status"] != expected_status:
        raise ControllerProtocolError("stored controller response status is invalid")
    if (state in {"accepted", "intent-bound", "effect-authorized"}) != (
        response["resultSha256"] is None
    ):
        raise ControllerProtocolError("stored controller result/state relation is invalid")
    receipt_material = dict(response)
    receipt_sha256 = receipt_material.pop("receiptSha256")
    if receipt_sha256 != _sha(_canonical(receipt_material)):
        raise ControllerProtocolError("stored controller response receipt is invalid")
    hmac_material = dict(receipt_material)
    observed_hmac = hmac_material.pop("controllerHmac")
    expected_hmac = "hmac-sha256:" + hmac.new(
        key,
        (PROTOCOL + "/" + response["action"] + "\0").encode()
        + _canonical(hmac_material),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(observed_hmac, expected_hmac):
        raise ControllerProtocolError("stored controller response HMAC is invalid")
    return raw, data


def _write_state(path: Path, value: Mapping[str, Any], expected: bytes | None) -> None:
    current = _read_state_bytes(path, missing_ok=True)
    if current != expected:
        raise ControllerProtocolError("controller durable state predecessor changed")
    encoded = _canonical(dict(value))
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory = os.open(STATE_ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _serve_packet(packet: bytes, peer_uid: int, config: ControllerConfig, key: bytes) -> bytes:
    try:
        value = json.loads(packet)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerProtocolError("controller request contains malformed JSON") from exc
    data = _closed_mapping(value, _REQUEST_FIELDS, "controller request")
    if _canonical(data) != packet or data["schemaVersion"] != 1 or data["protocol"] != PROTOCOL:
        raise ControllerProtocolError("controller request is not exact canonical protocol v1")
    if peer_uid != config.broker_uid or peer_uid in {config.controller_uid, config.worker_uid}:
        raise ControllerProtocolError("request peer is not the distinct configured broker UID")
    action = data["action"]
    request = data["request"]
    request_sha = _sha(packet)
    if action == "OPEN":
        opened = _closed_mapping(request, _OPEN_FIELDS, "OPEN request")
        for field in ("repositoryLocatorSha256", "rootSetSha256", "requestSha256", "runtimeManifestSha256", "moduleSha256", "schemaSha256"):
            _digest(opened[field], field)
        if opened["operation"] not in ALLOWED_OPERATIONS or opened["rootSetSha256"] != config.root_set_sha256:
            raise ControllerProtocolError("OPEN request operation/root set mismatch")
        if not isinstance(opened["clientNonce"], str) or not _NONCE.fullmatch(opened["clientNonce"]):
            raise ControllerProtocolError("OPEN client nonce is invalid")
        if opened["operationId"] != hashlib.sha256(
            _canonical(
                {
                    "operation": opened["operation"],
                    "binding": {
                        "repositoryLocatorSha256": opened["repositoryLocatorSha256"],
                        "requestSha256": opened["requestSha256"],
                    },
                }
            )
        ).hexdigest():
            raise ControllerProtocolError("OPEN operationId does not bind the exact request")
        if (opened["runtimeManifestSha256"], opened["moduleSha256"], opened["schemaSha256"], opened["configEpoch"], opened["keyEpoch"]) != (
            config.runtime_manifest_sha256, config.module_sha256, config.schema_sha256, config.config_epoch, config.key_epoch
        ):
            raise ControllerProtocolError("OPEN request configured identity mismatch")
        now = int(time.time())
        if opened["issuedAtUnix"] > now + MAX_CLOCK_SKEW_SECONDS or opened["expiresAtUnix"] <= now or opened["expiresAtUnix"] - opened["issuedAtUnix"] > MAX_OPERATION_SECONDS:
            raise ControllerProtocolError("OPEN request lifetime is invalid")
        path = _state_file(opened["operationId"])
        loaded = _load_state(path, key, missing_ok=True)
        prior_bytes = None if loaded is None else loaded[0]
        open_binding = {
            key_name: opened[key_name]
            for key_name in sorted(
                _OPEN_FIELDS - {"clientNonce", "issuedAtUnix", "expiresAtUnix"}
            )
        }
        open_binding_sha256 = _sha(_canonical(open_binding))
        if prior_bytes is not None:
            assert loaded is not None
            prior = loaded[1]
            if prior.get("openBindingSha256") != open_binding_sha256:
                raise ControllerProtocolError("operationId was rebound to a different OPEN request")
            if opened["clientNonce"] in prior.get("usedNonces", []):
                raise ControllerProtocolError("OPEN nonce was already consumed")
            if prior.get("state") in {"effect-authorized", "result-stored"}:
                raise ControllerProtocolError("operation outcome is uncertain; inspect durable controller state")
            state = str(prior.get("state"))
            if state != "completed" and int(prior.get("expiresAtUnix", 0)) <= now:
                raise ControllerProtocolError("controller operation expired before recovery")
            response = _sign_response(key, action, {
                "status": "completed" if state == "completed" else "accepted",
                "state": state,
                "requestSha256": request_sha,
                "operationId": opened["operationId"],
                "sessionNonce": prior["response"]["sessionNonce"],
                "resultSha256": prior["response"].get("resultSha256"),
            })
            successor = {
                **prior,
                "usedNonces": [*prior["usedNonces"], opened["clientNonce"]],
                "response": response,
            }
            _write_state(path, successor, prior_bytes)
            return _canonical(response)
        session_nonce = secrets.token_hex(32)
        response = _sign_response(key, action, {
            "status": "accepted", "state": "accepted", "requestSha256": request_sha,
            "operationId": opened["operationId"], "sessionNonce": session_nonce,
            "resultSha256": None,
        })
        _write_state(path, {
            "openBindingSha256": open_binding_sha256,
            "expiresAtUnix": opened["expiresAtUnix"],
            "state": "accepted",
            "usedNonces": [opened["clientNonce"]],
            "response": response,
        }, None)
        return _canonical(response)
    if action == "STEP":
        step = _closed_mapping(request, _STEP_FIELDS, "STEP request")
        if not isinstance(step["stepNonce"], str) or not _NONCE.fullmatch(step["stepNonce"]):
            raise ControllerProtocolError("STEP nonce is invalid")
        path = _state_file(step["operationId"])
        loaded = _load_state(path, key)
        assert loaded is not None
        prior_bytes, prior = loaded
        if int(prior.get("expiresAtUnix", 0)) <= int(time.time()):
            raise ControllerProtocolError("controller operation expired before STEP")
        if step["stepNonce"] in prior.get("usedNonces", []):
            raise ControllerProtocolError("STEP nonce was already consumed")
        current = prior["state"]
        target = step["targetState"]
        if target not in _STATES or _STATES.index(target) != _STATES.index(current) + 1:
            raise ControllerProtocolError("STEP is not the unique state successor")
        if step["sessionNonce"] != prior["response"]["sessionNonce"] or step["predecessorReceiptSha256"] != prior["response"]["receiptSha256"]:
            raise ControllerProtocolError("STEP predecessor/session mismatch")
        if target in {"intent-bound", "effect-authorized"}:
            _digest(step["transactionIntentSha256"], "transactionIntentSha256")
            if step["resultSha256"] is not None:
                raise ControllerProtocolError("pre-effect STEP cannot carry a result")
        if target in {"result-stored", "completed"}:
            _digest(step["resultSha256"], "resultSha256")
            if step["transactionIntentSha256"] is not None:
                raise ControllerProtocolError("result STEP cannot change the transaction intent")
        if target == "effect-authorized" and step["transactionIntentSha256"] != prior.get("transactionIntentSha256"):
            raise ControllerProtocolError("effect authorization changed the bound transaction intent")
        if target == "completed" and step["resultSha256"] != prior["response"].get("resultSha256"):
            raise ControllerProtocolError("completion changed the stored result")
        response = _sign_response(key, action, {
            "status": "completed" if target == "completed" else "accepted",
            "state": target, "requestSha256": request_sha,
            "operationId": step["operationId"], "sessionNonce": step["sessionNonce"],
            "resultSha256": step["resultSha256"],
        })
        successor = {
            **prior,
            "state": target,
            "usedNonces": [*prior["usedNonces"], step["stepNonce"]],
            "response": response,
        }
        if target == "intent-bound":
            successor["transactionIntentSha256"] = step["transactionIntentSha256"]
        _write_state(path, successor, prior_bytes)
        return _canonical(response)
    if action == "VALIDATE":
        validation = _closed_mapping(request, _VALIDATE_FIELDS, "VALIDATE request")
        if not isinstance(validation["validationNonce"], str) or not _NONCE.fullmatch(validation["validationNonce"]):
            raise ControllerProtocolError("VALIDATE nonce is invalid")
        if validation["expectedState"] not in _STATES:
            raise ControllerProtocolError("VALIDATE state is invalid")
        _digest(validation["storedReceiptSha256"], "storedReceiptSha256")
        _digest(validation["expectedResultSha256"], "expectedResultSha256", nullable=True)
        path = _state_file(validation["operationId"])
        loaded = _load_state(path, key)
        assert loaded is not None
        prior_bytes, prior = loaded
        if prior.get("state") != "completed" and int(prior.get("expiresAtUnix", 0)) <= int(time.time()):
            raise ControllerProtocolError("controller operation expired before VALIDATE")
        if validation["validationNonce"] in prior.get("usedNonces", []):
            raise ControllerProtocolError("VALIDATE nonce was already consumed")
        if prior["state"] != validation["expectedState"] or prior["response"]["receiptSha256"] != validation["storedReceiptSha256"] or prior["response"].get("resultSha256") != validation["expectedResultSha256"]:
            raise ControllerProtocolError("stored receipt is not the current controller result")
        response = _sign_response(key, action, {
            "status": "validated", "state": prior["state"], "requestSha256": request_sha,
            "operationId": validation["operationId"], "sessionNonce": prior["response"]["sessionNonce"],
            "resultSha256": prior["response"].get("resultSha256"),
        })
        _write_state(path, {**prior, "usedNonces": [*prior["usedNonces"], validation["validationNonce"]]}, prior_bytes)
        return _canonical(response)
    raise ControllerProtocolError("unknown controller action")


def serve_forever() -> None:
    if not sys.platform.startswith("linux"):
        raise ControllerProtocolError("controller service requires Linux")
    config = load_controller_config()
    if os.geteuid() != config.controller_uid:
        raise ControllerProtocolError("controller process does not run as configured controller UID")
    try:
        key_info = os.lstat(CONTROLLER_KEY_PATH)
        if (
            stat.S_ISLNK(key_info.st_mode)
            or not stat.S_ISREG(key_info.st_mode)
            or key_info.st_uid != config.controller_uid
            or key_info.st_nlink != 1
            or stat.S_IMODE(key_info.st_mode) & 0o077
        ):
            raise ControllerProtocolError(
                "controller HMAC key must be a controller-owned private regular file"
            )
        key_fd = os.open(
            CONTROLLER_KEY_PATH,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(key_fd)
            if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode) != (
                key_info.st_dev, key_info.st_ino, key_info.st_uid, key_info.st_mode
            ):
                raise ControllerProtocolError("controller HMAC key changed before open")
            key = os.read(key_fd, 4097)
        finally:
            os.close(key_fd)
    except ControllerProtocolError:
        raise
    except OSError as exc:
        raise ControllerProtocolError(f"cannot read controller HMAC key: {exc}") from exc
    if len(key) < 32 or len(key) > 4096:
        raise ControllerProtocolError("controller HMAC key must contain 32..4096 bytes")
    _validate_controller_directory(STATE_ROOT, config, "controller state root")
    _validate_controller_directory(
        ENDPOINT_PATH.parent, config, "controller endpoint parent"
    )
    if ENDPOINT_PATH.exists() or ENDPOINT_PATH.is_symlink():
        raise ControllerProtocolError("controller endpoint already exists; operator must reconcile it")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(str(ENDPOINT_PATH))
    os.chmod(ENDPOINT_PATH, 0o600)
    listener.listen(16)
    try:
        while True:
            connection, _ = listener.accept()
            try:
                try:
                    _, peer_uid, _ = _peer_credentials(connection)
                    packet = connection.recv(MAX_MESSAGE_BYTES + 1)
                    if not packet or len(packet) > MAX_MESSAGE_BYTES:
                        raise ControllerProtocolError(
                            "controller connection supplied an empty or oversized packet"
                        )
                    try:
                        extra = connection.recv(
                            1,
                            getattr(socket, "MSG_PEEK", 0)
                            | getattr(socket, "MSG_DONTWAIT", 0),
                        )
                    except BlockingIOError:
                        extra = b""
                    if extra:
                        raise ControllerProtocolError(
                            "controller connection supplied more than one request packet"
                        )
                    response = _serve_packet(packet, peer_uid, config, key)
                    connection.sendall(response)
                except ControllerProtocolError:
                    # Invalid clients receive no signed oracle response and
                    # cannot terminate the controller accept loop.
                    pass
            finally:
                connection.close()
    finally:
        listener.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="startup-factory-beads-controller")
    parser.add_argument("command", choices=("validate-config", "serve"))
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            serve_forever()
        else:
            config = load_controller_config()
            print(_canonical({
                "schemaVersion": 1,
                "protocol": PROTOCOL,
                "configured": True,
                "endpointPath": str(ENDPOINT_PATH),
                "rootSetSha256": config.root_set_sha256,
                "proofState": "configured_unproved",
            }).decode())
        return 0
    except ControllerProtocolError as exc:
        print(f"startup-factory-beads-controller: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
