"""Pinned model-only policy intent and observed sbx v0.54.0 rule semantics.

No rule snapshot proves transport containment, proxy credential isolation or
permission to launch. Independent live qualification remains mandatory. The
create-time explicit deny lock stays in place until every scoped HTTP rule has
been installed and verified; activation removes that exact lock only.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
import re
import uuid
from typing import Any

from .execution_backend import BackendContractError, DockerProfile, canonical_digest
from .sandbox_deployment import DeploymentError, decode_object, read_root_protected

MAX_POLICY_BYTES = 16 * 1024
MAX_EFFECTIVE_BYTES = 64 * 1024
MODEL_HOST = "api.openai.com:443"
# Closed first-provider surface. No hostname-only TCP/UDP rule, wildcard,
# organizational endpoint, arbitrary path, query string or redirect allowance.
HTTP_PAIRS = frozenset({("POST", "/v1/responses"), ("GET", "/v1/responses"),
                        ("POST", "/v1/chat/completions"), ("GET", "/v1/models")})
_NAMESPACE = re.compile(r"sf-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")


class NetworkPolicyError(BackendContractError):
    """Policy intent or the exact effective rule set could not be established."""


@dataclasses.dataclass(frozen=True, order=True)
class HttpRule:
    method: str
    path: str
    host: str = MODEL_HOST

    def __post_init__(self) -> None:
        if (type(self.method) is not str or type(self.path) is not str
            or self.host != MODEL_HOST or (self.method, self.path) not in HTTP_PAIRS):
            raise NetworkPolicyError("unsupported model HTTP method, host or path")

    def as_dict(self) -> dict[str, Any]:
        return {"host": self.host, "method": self.method, "path": self.path}


@dataclasses.dataclass(frozen=True)
class ModelNetworkPolicy:
    namespace: str
    rules: tuple[HttpRule, ...]
    source_bytes: bytes = dataclasses.field(repr=False)

    def __post_init__(self) -> None:
        if (type(self.namespace) is not str or len(self.namespace) > 20
            or not _NAMESPACE.fullmatch(self.namespace) or self.namespace == "sf-qualification"
            or type(self.rules) is not tuple or not 1 <= len(self.rules) <= 4
            or any(type(rule) is not HttpRule for rule in self.rules)
            or len(set(self.rules)) != len(self.rules) or type(self.source_bytes) is not bytes
            or not 0 < len(self.source_bytes) <= MAX_POLICY_BYTES):
            raise NetworkPolicyError("invalid bounded dedicated model policy")
        if canonical_digest(decode_object(self.source_bytes, maximum=MAX_POLICY_BYTES, depth_limit=5)) != canonical_digest(self.as_dict()):
            raise NetworkPolicyError("policy raw bytes do not bind its exact descriptor")

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.source_bytes).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {"schemaVersion": 1, "namespace": self.namespace, "preset": "deny-all",
                "provider": "openai", "rules": [rule.as_dict() for rule in self.rules]}

    @classmethod
    def from_dict(cls, value: Any, *, _raw: bytes | None = None) -> ModelNetworkPolicy:
        try:
            if (type(value) is not dict or set(value) != {"schemaVersion", "namespace", "preset", "provider", "rules"}
                or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
                or value["preset"] != "deny-all" or value["provider"] != "openai"
                or type(value["rules"]) is not list or not 1 <= len(value["rules"]) <= 4):
                raise NetworkPolicyError("unknown model policy schema")
            rules = []
            for row in value["rules"]:
                if type(row) is not dict or set(row) != {"host", "method", "path"}:
                    raise NetworkPolicyError("unknown HTTP rule schema")
                rules.append(HttpRule(row["method"], row["path"], row["host"]))
            return cls(value["namespace"], tuple(rules), _raw if _raw is not None else json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
        except (KeyError, TypeError, ValueError) as exc:
            raise NetworkPolicyError("invalid model policy descriptor") from exc


def parse_network_policy(raw: bytes) -> ModelNetworkPolicy:
    try:
        data = decode_object(raw, maximum=MAX_POLICY_BYTES, depth_limit=5)
        return ModelNetworkPolicy.from_dict(data, _raw=raw)
    except DeploymentError as exc:
        raise NetworkPolicyError("model policy JSON rejected") from exc


def load_network_policy(path: Path, profile: DockerProfile) -> ModelNetworkPolicy:
    """Read protected intent bytes; their raw digest must match the profile."""
    try:
        raw, _digest = read_root_protected(path, maximum=MAX_POLICY_BYTES)
        policy = parse_network_policy(raw)
        if policy.digest != profile.policy_digest or policy.namespace != profile.namespace:
            raise NetworkPolicyError("model policy differs from the protected profile binding")
        return policy
    except (DeploymentError, OSError) as exc:
        raise NetworkPolicyError("protected model policy could not be read") from exc


def _uuid(value: Any) -> str:
    if type(value) is not str:
        raise NetworkPolicyError("native policy rule requires a canonical UUID")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise NetworkPolicyError("native policy rule requires a canonical UUID") from exc
    return value


def _filesystem_rows() -> list[dict[str, Any]]:
    result = []
    for kind, actions in (("read", ["fs:mount:read"]), ("write", ["fs:mount:read", "fs:mount:write"])):
        name = "default-fs-" + kind + "-allow-all"
        result.append({"actions": actions, "applies_to": "all", "decision": "allow", "editable": False,
            "id": name, "layer": "local", "name": name, "origin": "local", "policy_id": "local-policy",
            "provenance": {"created_via": "default"}, "resource_type": "filesystem:" + kind,
            "resources": ["**"], "scope": "global", "status": "active"})
    return result


def _fallback() -> dict[str, Any]:
    return {"actions": ["net:connect:tcp", "net:connect:udp"], "applies_to": "all", "decision": "deny",
        "editable": False, "id": "default-deny-all", "layer": "local", "name": "default-deny-all",
        "origin": "local", "policy_name": "default-deny-all",
        "reason": "Implicit fallback when no applicable policy decides the request.",
        "resource_type": "network", "resources": ["**"], "scope": "global", "status": "active"}


def verify_effective_policy(descriptor: ModelNetworkPolicy, native_rules: Any, *,
                            sandbox_name: str | None = None, stage: str = "global") -> dict[str, Any]:
    """Validate the *entire* observed rule set, independent of list ordering.

    global: empty dedicated namespace's deny-default baseline;
    locked: baseline plus exact create-time scoped deny-all;
    staged: lock plus all intended scoped HTTP allows;
    active: all intended scoped HTTP allows, with only implicit deny fallback.
    Default filesystem rows authorize no host mounts: mountless metadata is a
    separate mandatory check. No rule, layer, kit/global allowance is ignored.
    """
    if (type(descriptor) is not ModelNetworkPolicy or stage not in {"global", "locked", "staged", "active"}
        or (stage == "global") != (sandbox_name is None)
        or sandbox_name is not None and (type(sandbox_name) is not str or not _NAME.fullmatch(sandbox_name))):
        raise NetworkPolicyError("invalid effective-policy verification context")
    try:
        if type(native_rules) is bytes:
            data = decode_object(native_rules, maximum=MAX_EFFECTIVE_BYTES, depth_limit=8)
        else:
            raw = json.dumps(native_rules, allow_nan=False, separators=(",", ":")).encode()
            data = decode_object(raw, maximum=MAX_EFFECTIVE_BYTES, depth_limit=8)
        if set(data) != {"rules"} or type(data["rules"]) is not list or len(data["rules"]) > 8:
            raise NetworkPolicyError("unknown or oversized native policy schema")
        rows = data["rules"].copy()
        if any(type(row) is not dict or type(row.get("editable")) is not bool for row in rows):
            raise NetworkPolicyError("native rule boolean fields must have exact types")
        for expected in [*_filesystem_rows(), _fallback()]:
            matches = [index for index, row in enumerate(rows) if row == expected]
            if len(matches) != 1:
                raise NetworkPolicyError("native default policy differs from the pinned deny-all baseline")
            rows.pop(matches[0])
        lock_id = None
        found = set()
        identifiers = set()
        for row in rows:
            if type(row) is not dict:
                raise NetworkPolicyError("unknown native scoped rule")
            rule_id, policy_id = _uuid(row.get("id")), _uuid(row.get("policy_id"))
            if rule_id in identifiers:
                raise NetworkPolicyError("duplicate native rule identity")
            identifiers.add(rule_id)
            shared = {"applies_to": "sandbox:" + str(sandbox_name), "editable": True, "id": rule_id,
                "layer": "local", "name": rule_id, "origin": "scoped", "policy_id": policy_id,
                "provenance": {"created_via": "added"}, "sandbox_id": sandbox_name,
                "scope": "sandbox:" + str(sandbox_name), "status": "active"}
            lock = {**shared, "actions": ["net:connect:tcp", "net:connect:udp"], "decision": "deny",
                    "resource_type": "network", "resources": ["**"]}
            if row == lock:
                if lock_id is not None or stage not in {"locked", "staged"}:
                    raise NetworkPolicyError("unexpected or duplicate scoped deny lock")
                lock_id = rule_id
                continue
            matched = None
            for rule in descriptor.rules:
                expected = {**shared, "actions": ["http:request:" + rule.method.lower()], "decision": "allow",
                    "http_targets": [{"host": rule.host, "path": rule.path}], "methods": [rule.method],
                    "resource_type": "http", "resources": [rule.host]}
                if row == expected:
                    matched = rule
                    break
            if matched is None or matched in found or stage not in {"staged", "active"}:
                raise NetworkPolicyError("unknown, extra, duplicate or incorrectly scoped network allowance")
            found.add(matched)
        if ((stage in {"locked", "staged"}) != (lock_id is not None)
            or found != (set(descriptor.rules) if stage in {"staged", "active"} else set())):
            raise NetworkPolicyError("native policy activation stage is incomplete")
        return {"stage": stage, "lockRuleId": lock_id, "rulesDigest": canonical_digest({"rules": sorted(data["rules"], key=lambda row: row["id"])})}
    except (DeploymentError, TypeError, ValueError, RecursionError) as exc:
        raise NetworkPolicyError("native effective policy could not be verified") from exc
