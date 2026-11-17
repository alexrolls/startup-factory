"""Read root-issued sandbox enrollment evidence without creating authority.

There is deliberately no receipt writer or qualification runner. A receipt is
useful only when its exact bytes are pinned by the protected profile, every
mandatory qualification gate passed, and its dedicated account/namespace and
existing registry inode still match. Reading a JSON object alone proves none
of those properties.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from .execution_backend import (
    BackendContractError, DockerProfile, _absolute_path, _digest, _integer,
    _read_protected, canonical_digest,
)
from .sandbox_qualification import REQUIRED_CHECK_IDS
from .sandbox_registry import SandboxRegistry


MAX_RECEIPT_BYTES = 64 * 1024
MAX_ENROLLMENT_SECONDS = 30 * 86400
_REGISTRY_ID = re.compile(r"reg-[0-9a-f]{32}\Z")
RECEIPT_FIELDS = frozenset({
    "schemaVersion", "backend", "protocolVersion", "profileBasisDigest",
    "controllerUid", "namespace", "dedicatedAccount", "exclusiveNamespace",
    "registry", "issuedAt", "expiresAt", "checks",
})
REGISTRY_FIELDS = frozenset({"root", "device", "inode", "registryId"})
CHECK_FIELDS = frozenset({"passed", "evidenceDigest"})


class EnrollmentError(ValueError):
    """Enrollment evidence is missing, expired, unsafe, or inconsistent."""


def profile_basis_digest(profile: DockerProfile) -> str:
    """Avoid a digest cycle: the receipt pins every profile field except itself."""
    if type(profile) is not DockerProfile:
        raise EnrollmentError("enrollment requires a validated Docker profile")
    value = profile.as_dict()
    del value["qualificationDigest"]
    return canonical_digest(value)


def _closed(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise EnrollmentError(f"{label} has an unknown or incomplete schema")
    return value


def _decode(raw: bytes) -> Any:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RECEIPT_BYTES:
        raise EnrollmentError("enrollment receipt exceeds its byte limit or is empty")
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 8:
                raise EnrollmentError("enrollment receipt nesting limit exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise EnrollmentError("invalid enrollment receipt JSON")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise EnrollmentError("duplicate enrollment receipt key")
            result[key] = value
        return result

    def constant(_value: str) -> Any:
        raise EnrollmentError("nonfinite enrollment receipt number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise EnrollmentError("invalid enrollment receipt JSON") from exc


@dataclasses.dataclass(frozen=True)
class EnrollmentReceipt:
    profile_basis_digest: str
    controller_uid: int
    namespace: str
    registry_root: str
    registry_device: int
    registry_inode: int
    registry_id: str
    issued_at: int
    expires_at: int
    checks: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
            "profileBasisDigest": self.profile_basis_digest,
            "controllerUid": self.controller_uid, "namespace": self.namespace,
            "dedicatedAccount": True, "exclusiveNamespace": True,
            "registry": {"root": self.registry_root, "device": self.registry_device,
                         "inode": self.registry_inode, "registryId": self.registry_id},
            "issuedAt": self.issued_at, "expiresAt": self.expires_at,
            "checks": {name: {"passed": True, "evidenceDigest": digest} for name, digest in self.checks},
        }

    @classmethod
    def from_dict(cls, value: Any) -> "EnrollmentReceipt":
        try:
            value = _closed(value, RECEIPT_FIELDS, "enrollment receipt")
            if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or type(value["protocolVersion"]) is not int or value["protocolVersion"] != 1 or value["backend"] != "docker-sandboxes":
                raise EnrollmentError("unsupported enrollment receipt version")
            if value["dedicatedAccount"] is not True or value["exclusiveNamespace"] is not True:
                raise EnrollmentError("dedicated account and exclusive namespace are mandatory")
            _digest(value["profileBasisDigest"], "profile basis digest")
            _integer(value["controllerUid"], "controller UID", 1, 2**31 - 1)
            if not isinstance(value["namespace"], str) or len(value["namespace"]) > 20 or value["namespace"] == "sf-qualification" or not re.fullmatch(r"sf-[a-z0-9]+(?:-[a-z0-9]+)*", value["namespace"]):
                raise EnrollmentError("enrollment requires a dedicated factory namespace")
            registry = _closed(value["registry"], REGISTRY_FIELDS, "enrolled registry")
            _absolute_path(registry["root"], "registry root")
            _integer(registry["device"], "registry device", 0, 2**63 - 1)
            _integer(registry["inode"], "registry inode", 1, 2**63 - 1)
            if not isinstance(registry["registryId"], str) or not _REGISTRY_ID.fullmatch(registry["registryId"]):
                raise EnrollmentError("invalid enrolled registry identity")
            _integer(value["issuedAt"], "receipt issue time", 1, 2**63 - 1)
            _integer(value["expiresAt"], "receipt expiry time", 1, 2**63 - 1)
            if not 0 < value["expiresAt"] - value["issuedAt"] <= MAX_ENROLLMENT_SECONDS:
                raise EnrollmentError("enrollment validity interval is invalid")
            checks = _closed(value["checks"], frozenset(REQUIRED_CHECK_IDS), "qualification gates")
            validated: list[tuple[str, str]] = []
            for name in sorted(checks):
                check = _closed(checks[name], CHECK_FIELDS, "qualification gate")
                if check["passed"] is not True:
                    raise EnrollmentError("every mandatory qualification gate must pass")
                validated.append((name, _digest(check["evidenceDigest"], "qualification evidence digest")))
            return cls(value["profileBasisDigest"], value["controllerUid"], value["namespace"], registry["root"], registry["device"], registry["inode"], registry["registryId"], value["issuedAt"], value["expiresAt"], tuple(validated))
        except BackendContractError as exc:
            raise EnrollmentError("invalid enrollment receipt binding") from exc


def parse_receipt(raw: bytes) -> EnrollmentReceipt:
    """Validate closed data only; this does not authenticate root ownership."""
    return EnrollmentReceipt.from_dict(_decode(raw))


def load_enrollment(profile: DockerProfile, path: Path, registry: SandboxRegistry, *, now: int | None = None, transaction: Any = None) -> EnrollmentReceipt:
    """Authenticate an existing root-issued receipt and the pinned registry.

    A caller already holding ``registry.locked()`` supplies that transaction to
    preserve namespace→authority lock ordering. This function never initializes
    the registry, takes over an epoch, writes a receipt, or executes a runtime.
    """
    try:
        if type(profile) is not DockerProfile or type(registry) is not SandboxRegistry:
            raise EnrollmentError("enrollment requires validated profile and registry objects")
        if os.geteuid() == 0 or os.geteuid() != profile.controller_uid:
            raise EnrollmentError("enrollment requires the assigned nonroot controller UID")
        raw, observed = _read_protected(Path(path), maximum=MAX_RECEIPT_BYTES, capture=True, executable=False)
        if raw is None or "sha256:" + observed != profile.qualification_digest or hashlib.sha256(raw).hexdigest() != observed:
            raise EnrollmentError("receipt bytes differ from the protected profile qualification digest")
        receipt = parse_receipt(raw)
        current = int(time.time()) if now is None else now
        _integer(current, "current time", 1, 2**63 - 1)
        if not receipt.issued_at <= current < receipt.expires_at:
            raise EnrollmentError("enrollment receipt is not currently valid")
        if receipt.profile_basis_digest != profile_basis_digest(profile) or receipt.controller_uid != profile.controller_uid or receipt.namespace != profile.namespace or receipt.namespace != registry.namespace or receipt.registry_root != str(registry.root):
            raise EnrollmentError("enrollment receipt targets another profile, account, namespace, or registry")
        # Require an existing marker before acquiring a transaction: the public
        # registry lock can initialize an otherwise empty directory.
        marker, _ = registry._file("registry.identity", maximum=4096)
        identity = _decode(marker)
        if type(identity) is not dict or set(identity) != {"schemaVersion", "registryId", "namespace"} or type(identity["schemaVersion"]) is not int or identity["schemaVersion"] != 1 or identity["registryId"] != receipt.registry_id or identity["namespace"] != receipt.namespace:
            raise EnrollmentError("enrolled registry marker differs")

        def check(tx: Any) -> None:
            # records() revalidates transaction liveness and pinned files.
            tx.records()
            if tx.registry_id != receipt.registry_id:
                raise EnrollmentError("enrolled registry identity differs")
            opened = os.fstat(registry._root_fd)
            named = os.stat(registry.root, follow_symlinks=False)
            expected = (receipt.registry_device, receipt.registry_inode)
            if not stat.S_ISDIR(named.st_mode) or (opened.st_dev, opened.st_ino) != expected or (named.st_dev, named.st_ino) != expected:
                raise EnrollmentError("enrolled registry root inode differs")

        if transaction is None:
            with registry.locked() as tx:
                check(tx)
        else:
            if getattr(transaction, "_registry", None) is not registry:
                raise EnrollmentError("enrollment transaction belongs to another registry")
            check(transaction)
        return receipt
    except EnrollmentError:
        raise
    except (BackendContractError, OSError, ValueError, TypeError, KeyError) as exc:
        raise EnrollmentError("protected enrollment evidence is unavailable or inconsistent") from exc
