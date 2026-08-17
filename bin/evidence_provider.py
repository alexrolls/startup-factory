#!/usr/bin/env python3
"""Strict, offline validation and indexing for untrusted evidence manifests.

Schema-valid evidence is still untrusted diagnostic input.  This module never
grants approval, changes tracker state, or bypasses a delivery gate.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import stat
import struct
import sys
import zlib
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 1_048_576
MAX_BINDING_BYTES = 65_536
MAX_ASSERTIONS = 100
MAX_ARTIFACTS = 200
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 100 * 1024 * 1024
MAX_ITEMS = 1_000
MAX_TEXT = 2_048

TOP_KEYS = {
    "schemaVersion",
    "provider",
    "subject",
    "capability",
    "invocation",
    "target",
    "status",
    "assertions",
    "artifacts",
    "redactions",
}
PROVIDER_KEYS = {"id", "version", "executableSha256"}
SUBJECT_KEYS = {"taskId", "attempt", "commit"}
INVOCATION_KEYS = {"sanitizedArgv", "environmentNames", "startedAt", "finishedAt"}
TARGET_KEYS = {"origin", "allowedOrigins"}
ASSERTION_KEYS = {
    "id",
    "acceptanceCriterion",
    "entryPath",
    "status",
    "behavioral",
    "precondition",
    "consoleErrors",
    "failedRequests",
    "accessibilityViolations",
    "artifactIds",
}
CHECK_GROUP_KEYS = {"status", "checks"}
CHECK_KEYS = {"id", "type", "status"}
CONSOLE_KEYS = {"phase", "type", "messageSha256", "urlPath"}
REQUEST_KEYS = {"phase", "method", "resourceType", "urlPath", "failureSha256"}
ACCESSIBILITY_KEYS = {"phase", "id", "impact", "count"}
ARTIFACT_KEYS = {
    "id",
    "assertionId",
    "kind",
    "viewport",
    "phase",
    "path",
    "mimeType",
    "sizeBytes",
    "sha256",
}
REDACTION_KEYS = {"kind", "method"}
EXPECTED_BINDING_KEYS = {"provider", "subject", "capability", "target"}
STATUSES = {"passed", "failed", "error"}
PHASES = {"behavioral", "precondition"}
VIEWPORTS = {"desktop", "tablet", "mobile"}
RESOURCE_TYPES = {
    "document",
    "stylesheet",
    "image",
    "media",
    "font",
    "script",
    "texttrack",
    "xhr",
    "fetch",
    "eventsource",
    "websocket",
    "manifest",
    "other",
}
IMPACTS = {"critical", "serious", "moderate", "minor"}
REQUIRED_REDACTIONS = [
    {"kind": "console-message", "method": "sha256"},
    {"kind": "request-query", "method": "removed"},
    {"kind": "form-value", "method": "masked"},
    {"kind": "artifact-path", "method": "basename-only"},
    {"kind": "environment-value", "method": "omitted"},
]
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
SEMVER_RE = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z"
)
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
RFC3339_Z_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
SANITIZED_ARGV_BASE = [
    "--journey",
    "<journey-json>",
    "--manifest",
    "<manifest-json>",
    "--artifacts",
    "<artifact-directory>",
    "--project-root",
    "<project-root>",
]


class EvidenceValidationError(ValueError):
    """A stable, non-authoritative evidence validation failure."""


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceValidationError("duplicate JSON key: %s" % key)
        value[key] = item
    return value


def _read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise EvidenceValidationError("%s is not readable" % label) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise EvidenceValidationError("%s must be a non-symlink regular file" % label)
    if before.st_nlink != 1:
        raise EvidenceValidationError("%s must not be hard-linked" % label)
    if before.st_size > limit:
        raise EvidenceValidationError("%s exceeds the size cap" % label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceValidationError("%s could not be opened safely" % label) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise EvidenceValidationError("%s must be a regular file" % label)
        if opened.st_nlink != 1:
            raise EvidenceValidationError("%s must not be hard-linked" % label)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise EvidenceValidationError("%s changed while it was opened" % label)
        chunks: list[bytes] = []
        count = 0
        while True:
            chunk = os.read(descriptor, min(65_536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > limit:
                raise EvidenceValidationError("%s exceeds the size cap" % label)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_json_document(path: Path, limit: int, label: str):
    raw = _read_regular_file(path, limit, label)
    try:
        text = raw.decode("utf-8", "strict")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys), raw
    except EvidenceValidationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError("%s must be valid duplicate-free UTF-8 JSON" % label) from exc


def _load_json(path: Path, limit: int, label: str):
    return _load_json_document(path, limit, label)[0]


def _canonical_digest(value) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _object(value, keys: set[str], path: str) -> dict:
    if not isinstance(value, dict):
        raise EvidenceValidationError("%s must be an object" % path)
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        detail = []
        if missing:
            detail.append("missing " + ",".join(missing))
        if extra:
            detail.append("extra " + ",".join(extra))
        raise EvidenceValidationError("%s has invalid fields (%s)" % (path, "; ".join(detail)))
    return value


def _array(value, path: str, maximum: int = MAX_ITEMS) -> list:
    if not isinstance(value, list):
        raise EvidenceValidationError("%s must be an array" % path)
    if len(value) > maximum:
        raise EvidenceValidationError("%s exceeds the item cap" % path)
    return value


def _text(value, path: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EvidenceValidationError("%s must be a bounded non-empty string" % path)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise EvidenceValidationError("%s contains control characters" % path)
    return value


def _identifier(value, path: str) -> str:
    value = _text(value, path, 128)
    if not ID_RE.fullmatch(value):
        raise EvidenceValidationError("%s is not a safe identifier" % path)
    return value


def _enum(value, allowed: set[str], path: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise EvidenceValidationError("%s has an unsupported value" % path)
    return value


def _integer(value, path: str, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise EvidenceValidationError("%s must be an integer in range" % path)
    return value


def _hash(value, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise EvidenceValidationError("%s must be a lowercase sha256 digest" % path)
    return value


def _url_path(value, path: str) -> str:
    value = _text(value, path, 2_048)
    parsed = urlsplit(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.path != value
    ):
        raise EvidenceValidationError("%s must be an origin-free path without query or fragment" % path)
    return value


def _origin(value, path: str) -> str:
    value = _text(value, path, 2_048)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise EvidenceValidationError("%s is not a canonical origin" % path) from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname != parsed.hostname.casefold()
        or any(ord(character) > 127 for character in parsed.hostname)
    ):
        raise EvidenceValidationError("%s is not a canonical HTTP(S) origin" % path)
    if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
        raise EvidenceValidationError("%s must omit the default port" % path)
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise EvidenceValidationError("%s has an invalid hostname" % path)
    if ":" in host:
        host = "[" + host + "]"
    canonical = parsed.scheme + "://" + host + ((":" + str(port)) if port else "")
    if value != canonical:
        raise EvidenceValidationError("%s is not canonical" % path)
    return value


def _timestamp(value, path: str) -> dt.datetime:
    if not isinstance(value, str) or not RFC3339_Z_RE.fullmatch(value):
        raise EvidenceValidationError("%s must be an RFC3339 UTC timestamp" % path)
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceValidationError("%s is not a real timestamp" % path) from exc


def _validate_provider(value) -> dict:
    provider = _object(value, PROVIDER_KEYS, "provider")
    if _identifier(provider["id"], "provider.id") != "startup-factory.playwright":
        raise EvidenceValidationError("provider.id is unsupported")
    if not isinstance(provider["version"], str) or not SEMVER_RE.fullmatch(provider["version"]):
        raise EvidenceValidationError("provider.version must be a stable semantic version")
    _hash(provider["executableSha256"], "provider.executableSha256")
    return provider


def _validate_subject(value) -> dict:
    subject = _object(value, SUBJECT_KEYS, "subject")
    _text(subject["taskId"], "subject.taskId", 256)
    _integer(subject["attempt"], "subject.attempt", 1, 1_000_000)
    if not isinstance(subject["commit"], str) or not COMMIT_RE.fullmatch(subject["commit"]):
        raise EvidenceValidationError("subject.commit must be a lowercase 40-hex commit")
    return subject


def _validate_invocation(value) -> dict:
    invocation = _object(value, INVOCATION_KEYS, "invocation")
    argv = _array(invocation["sanitizedArgv"], "invocation.sanitizedArgv", 64)
    for index, item in enumerate(argv):
        _text(item, "invocation.sanitizedArgv[%d]" % index, 512)
    allowed_argv = [
        SANITIZED_ARGV_BASE,
        [*SANITIZED_ARGV_BASE, "--allow-private-origins"],
        [*SANITIZED_ARGV_BASE, "--allow-public-origins"],
        [
            *SANITIZED_ARGV_BASE,
            "--allow-private-origins",
            "--allow-public-origins",
        ],
    ]
    if argv not in allowed_argv:
        raise EvidenceValidationError(
            "invocation.sanitizedArgv does not match the fixed placeholder sequence"
        )
    names = _array(invocation["environmentNames"], "invocation.environmentNames", 16)
    if names != ["LANG", "LC_ALL", "TZ"]:
        raise EvidenceValidationError("invocation.environmentNames must contain only the fixed safe names")
    started = _timestamp(invocation["startedAt"], "invocation.startedAt")
    finished = _timestamp(invocation["finishedAt"], "invocation.finishedAt")
    if finished < started:
        raise EvidenceValidationError("invocation.finishedAt precedes invocation.startedAt")
    return invocation


def _validate_target(value) -> dict:
    target = _object(value, TARGET_KEYS, "target")
    origin = _origin(target["origin"], "target.origin")
    allowed = _array(target["allowedOrigins"], "target.allowedOrigins", 32)
    validated = [_origin(item, "target.allowedOrigins[%d]" % index) for index, item in enumerate(allowed)]
    if validated != sorted(set(validated)) or origin not in validated:
        raise EvidenceValidationError("target.allowedOrigins must be sorted, unique, and include target.origin")
    return target


def _validate_checks(value, path: str) -> dict:
    group = _object(value, CHECK_GROUP_KEYS, path)
    status_value = _enum(group["status"], STATUSES, path + ".status")
    checks = _array(group["checks"], path + ".checks", 100)
    identifiers: set[str] = set()
    for index, item in enumerate(checks):
        item_path = "%s.checks[%d]" % (path, index)
        check = _object(item, CHECK_KEYS, item_path)
        identifier = _identifier(check["id"], item_path + ".id")
        if identifier in identifiers:
            raise EvidenceValidationError("%s contains duplicate check IDs" % path)
        identifiers.add(identifier)
        _identifier(check["type"], item_path + ".type")
        _enum(check["status"], STATUSES, item_path + ".status")
    if status_value == "passed" and (not checks or any(item["status"] != "passed" for item in checks)):
        raise EvidenceValidationError("%s passed without passing executable checks" % path)
    if status_value == "failed" and not any(item["status"] == "failed" for item in checks):
        raise EvidenceValidationError("%s failed without a failed check" % path)
    return group


def _validate_console(value, path: str) -> list:
    items = _array(value, path, 500)
    for index, item in enumerate(items):
        item_path = "%s[%d]" % (path, index)
        entry = _object(item, CONSOLE_KEYS, item_path)
        _enum(entry["phase"], PHASES, item_path + ".phase")
        _enum(entry["type"], {"error", "assert"}, item_path + ".type")
        _hash(entry["messageSha256"], item_path + ".messageSha256")
        _url_path(entry["urlPath"], item_path + ".urlPath")
    return items


def _validate_requests(value, path: str) -> list:
    items = _array(value, path, 500)
    for index, item in enumerate(items):
        item_path = "%s[%d]" % (path, index)
        entry = _object(item, REQUEST_KEYS, item_path)
        _enum(entry["phase"], PHASES, item_path + ".phase")
        method = _text(entry["method"], item_path + ".method", 16)
        if not re.fullmatch(r"[A-Z]{3,16}", method):
            raise EvidenceValidationError("%s.method must be an uppercase HTTP method" % item_path)
        _enum(entry["resourceType"], RESOURCE_TYPES, item_path + ".resourceType")
        _url_path(entry["urlPath"], item_path + ".urlPath")
        _hash(entry["failureSha256"], item_path + ".failureSha256")
    return items


def _validate_accessibility(value, path: str) -> list:
    items = _array(value, path, 500)
    for index, item in enumerate(items):
        item_path = "%s[%d]" % (path, index)
        entry = _object(item, ACCESSIBILITY_KEYS, item_path)
        _enum(entry["phase"], PHASES, item_path + ".phase")
        _identifier(entry["id"], item_path + ".id")
        _enum(entry["impact"], IMPACTS, item_path + ".impact")
        _integer(entry["count"], item_path + ".count", 1, 1_000_000)
    return items


def _validate_assertions(value) -> tuple[list[dict], dict[str, dict]]:
    assertions = _array(value, "assertions", MAX_ASSERTIONS)
    if not assertions:
        raise EvidenceValidationError("assertions must not be empty")
    index: dict[str, dict] = {}
    for position, item in enumerate(assertions):
        path = "assertions[%d]" % position
        assertion = _object(item, ASSERTION_KEYS, path)
        identifier = _identifier(assertion["id"], path + ".id")
        if identifier in index:
            raise EvidenceValidationError("assertions contain duplicate IDs")
        _text(assertion["acceptanceCriterion"], path + ".acceptanceCriterion", 1_024)
        _url_path(assertion["entryPath"], path + ".entryPath")
        status_value = _enum(assertion["status"], STATUSES, path + ".status")
        behavioral = _validate_checks(assertion["behavioral"], path + ".behavioral")
        precondition = _validate_checks(assertion["precondition"], path + ".precondition")
        console = _validate_console(assertion["consoleErrors"], path + ".consoleErrors")
        requests = _validate_requests(assertion["failedRequests"], path + ".failedRequests")
        accessibility = _validate_accessibility(
            assertion["accessibilityViolations"], path + ".accessibilityViolations"
        )
        artifact_ids = _array(assertion["artifactIds"], path + ".artifactIds", MAX_ARTIFACTS)
        for item_index, artifact_id in enumerate(artifact_ids):
            _identifier(artifact_id, "%s.artifactIds[%d]" % (path, item_index))
        if len(artifact_ids) != len(set(artifact_ids)):
            raise EvidenceValidationError("%s.artifactIds contains duplicates" % path)
        if status_value == "passed":
            if behavioral["status"] != "passed" or precondition["status"] != "passed":
                raise EvidenceValidationError("%s passed without behavioral and precondition success" % path)
            if console or requests or accessibility:
                raise EvidenceValidationError("%s passed with browser errors or violations" % path)
            if not artifact_ids:
                raise EvidenceValidationError("%s passed without a bound artifact" % path)
        if status_value == "failed" and not (
            behavioral["status"] == "failed"
            or precondition["status"] == "failed"
            or console
            or requests
            or accessibility
        ):
            raise EvidenceValidationError("%s failed without a failure signal" % path)
        index[identifier] = assertion
    return assertions, index


def _validate_png(content: bytes, path: str) -> None:
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise EvidenceValidationError("%s is not PNG media" % path)
    offset = 8
    first = True
    seen_end = False
    while offset < len(content):
        if offset + 12 > len(content):
            raise EvidenceValidationError("%s has a truncated PNG chunk" % path)
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        chunk_type = content[offset + 4 : offset + 8]
        end = offset + 12 + length
        if length > MAX_ARTIFACT_BYTES or end > len(content):
            raise EvidenceValidationError("%s has an invalid PNG chunk length" % path)
        data = content[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", content[offset + 8 + length : end])[0]
        if zlib.crc32(chunk_type + data) & 0xFFFFFFFF != expected_crc:
            raise EvidenceValidationError("%s has an invalid PNG checksum" % path)
        if first:
            if chunk_type != b"IHDR" or length != 13:
                raise EvidenceValidationError("%s lacks a valid PNG header" % path)
            width, height = struct.unpack(">II", data[:8])
            if not 1 <= width <= 16_384 or not 1 <= height <= 16_384:
                raise EvidenceValidationError("%s has unsafe PNG dimensions" % path)
            first = False
        if chunk_type == b"IEND":
            if length != 0 or end != len(content):
                raise EvidenceValidationError("%s has an invalid PNG ending" % path)
            seen_end = True
            break
        offset = end
    if not seen_end:
        raise EvidenceValidationError("%s lacks a PNG ending" % path)


def _artifact_path(root: Path, relative: object, path: str) -> Path:
    relative = _text(relative, path, 255)
    parsed = PurePosixPath(relative)
    if (
        parsed.is_absolute()
        or len(parsed.parts) != 1
        or relative in {".", ".."}
        or "/" in relative
        or "\\" in relative
    ):
        raise EvidenceValidationError("%s must be a safe basename" % path)
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise EvidenceValidationError("%s escapes or is missing from the artifact root" % path) from exc
    if candidate.is_symlink():
        raise EvidenceValidationError("%s must not be a symlink" % path)
    return candidate


def _validate_artifacts(value, root: Path, assertions: dict[str, dict]) -> tuple[list[dict], dict[str, dict]]:
    artifacts = _array(value, "artifacts", MAX_ARTIFACTS)
    index: dict[str, dict] = {}
    declared_total = 0
    for position, item in enumerate(artifacts):
        path = "artifacts[%d]" % position
        artifact = _object(item, ARTIFACT_KEYS, path)
        identifier = _identifier(artifact["id"], path + ".id")
        if identifier in index:
            raise EvidenceValidationError("artifacts contain duplicate IDs")
        assertion_id = _identifier(artifact["assertionId"], path + ".assertionId")
        if assertion_id not in assertions:
            raise EvidenceValidationError("%s.assertionId is unknown" % path)
        if artifact["kind"] != "screenshot":
            raise EvidenceValidationError("%s.kind is unsupported" % path)
        _enum(artifact["viewport"], VIEWPORTS, path + ".viewport")
        _enum(artifact["phase"], PHASES, path + ".phase")
        if artifact["mimeType"] != "image/png":
            raise EvidenceValidationError("%s.mimeType is unsupported" % path)
        size = _integer(artifact["sizeBytes"], path + ".sizeBytes", 1, MAX_ARTIFACT_BYTES)
        declared_total += size
        if declared_total > MAX_TOTAL_ARTIFACT_BYTES:
            raise EvidenceValidationError("artifacts exceed the total size cap")
        expected_hash = _hash(artifact["sha256"], path + ".sha256")
        file_path = _artifact_path(root, artifact["path"], path + ".path")
        content = _read_regular_file(file_path, MAX_ARTIFACT_BYTES, path + ".path")
        if len(content) != size:
            raise EvidenceValidationError("%s size does not match the artifact" % path)
        actual_hash = "sha256:" + hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            raise EvidenceValidationError("%s hash does not match the artifact" % path)
        _validate_png(content, path + ".path")
        index[identifier] = artifact
    return artifacts, index


def _validate_bindings(manifest: dict, expected) -> dict:
    binding = _object(expected, EXPECTED_BINDING_KEYS, "expectedBinding")
    for key in sorted(EXPECTED_BINDING_KEYS):
        if manifest[key] != binding[key]:
            raise EvidenceValidationError("manifest %s does not match the expected binding" % key)
    return binding


def _validate_cross_references(
    assertions: dict[str, dict], artifacts: dict[str, dict]
) -> None:
    referenced: set[str] = set()
    for assertion_id, assertion in assertions.items():
        for artifact_id in assertion["artifactIds"]:
            if artifact_id not in artifacts:
                raise EvidenceValidationError("assertion references an unknown artifact ID")
            if artifacts[artifact_id]["assertionId"] != assertion_id:
                raise EvidenceValidationError("artifact assertion binding mismatch")
            if artifact_id in referenced:
                raise EvidenceValidationError("artifact is referenced more than once")
            referenced.add(artifact_id)
    if referenced != set(artifacts):
        raise EvidenceValidationError("manifest contains an unreferenced artifact")


def validate_and_index(
    manifest_path: str | os.PathLike[str],
    artifact_root: str | os.PathLike[str],
    expected_binding: dict,
) -> dict:
    """Validate one manifest and return a deterministic, non-authoritative index."""
    root_path = Path(artifact_root)
    if root_path.is_symlink() or not root_path.is_dir():
        raise EvidenceValidationError("artifact root must be a non-symlink directory")
    root = root_path.resolve()
    manifest_value, manifest_bytes = _load_json_document(
        Path(manifest_path), MAX_MANIFEST_BYTES, "manifest"
    )
    manifest = _object(
        manifest_value,
        TOP_KEYS,
        "manifest",
    )
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != SCHEMA_VERSION:
        raise EvidenceValidationError("manifest.schemaVersion is unsupported")
    _validate_provider(manifest["provider"])
    _validate_subject(manifest["subject"])
    if manifest["capability"] != "browser-qa":
        raise EvidenceValidationError("manifest.capability is unsupported")
    _validate_invocation(manifest["invocation"])
    _validate_target(manifest["target"])
    _validate_bindings(manifest, expected_binding)
    top_status = _enum(manifest["status"], STATUSES, "manifest.status")
    assertions, assertion_index = _validate_assertions(manifest["assertions"])
    artifacts, artifact_index = _validate_artifacts(manifest["artifacts"], root, assertion_index)
    redactions = _array(manifest["redactions"], "redactions", len(REQUIRED_REDACTIONS))
    for position, redaction in enumerate(redactions):
        _object(redaction, REDACTION_KEYS, "redactions[%d]" % position)
    if redactions != REQUIRED_REDACTIONS:
        raise EvidenceValidationError("redactions must exactly declare the required protections")
    _validate_cross_references(assertion_index, artifact_index)
    if top_status == "passed" and any(item["status"] != "passed" for item in assertions):
        raise EvidenceValidationError("manifest passed with a non-passing assertion")
    if top_status == "failed" and not any(item["status"] == "failed" for item in assertions):
        raise EvidenceValidationError("manifest failed without a failed assertion")
    artifact_set = [
        {"id": identifier, **copy.deepcopy(artifact)}
        for identifier, artifact in sorted(artifact_index.items())
    ]
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "manifestValid": True,
        "untrusted": True,
        "authoritative": False,
        "manifestSha256": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
        "artifactSetSha256": _canonical_digest(artifact_set),
        "provider": copy.deepcopy(manifest["provider"]),
        "subject": copy.deepcopy(manifest["subject"]),
        "capability": manifest["capability"],
        "target": copy.deepcopy(manifest["target"]),
        "status": top_status,
        "assertionIndex": {
            identifier: {
                "status": assertion["status"],
                "acceptanceCriterion": assertion["acceptanceCriterion"],
                "entryPath": assertion["entryPath"],
                "artifactIds": list(assertion["artifactIds"]),
            }
            for identifier, assertion in sorted(assertion_index.items())
        },
        "artifactIndex": {
            identifier: {
                "assertionId": artifact["assertionId"],
                "kind": artifact["kind"],
                "viewport": artifact["viewport"],
                "phase": artifact["phase"],
                "path": artifact["path"],
                "mimeType": artifact["mimeType"],
                "sizeBytes": artifact["sizeBytes"],
                "sha256": artifact["sha256"],
            }
            for identifier, artifact in sorted(artifact_index.items())
        },
    }
    result["indexSha256"] = _canonical_digest(result)
    return result


def validate_manifest(
    manifest_path: str | os.PathLike[str],
    artifact_root: str | os.PathLike[str],
    expected_binding: dict,
) -> dict:
    """Validate and return a compact diagnostic summary."""
    index = validate_and_index(manifest_path, artifact_root, expected_binding)
    return {
        key: index[key]
        for key in (
            "schemaVersion",
            "manifestValid",
            "untrusted",
            "authoritative",
            "manifestSha256",
            "artifactSetSha256",
            "indexSha256",
            "provider",
            "subject",
            "capability",
            "target",
            "status",
        )
    } | {
        "assertionCount": len(index["assertionIndex"]),
        "artifactCount": len(index["artifactIndex"]),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "index"):
        command = subparsers.add_parser(name)
        command.add_argument("--manifest", required=True)
        command.add_argument("--artifact-root", required=True)
        command.add_argument("--expected-binding", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        expected = _load_json(Path(args.expected_binding), MAX_BINDING_BYTES, "expected binding")
        result = (
            validate_manifest(args.manifest, args.artifact_root, expected)
            if args.command == "validate"
            else validate_and_index(args.manifest, args.artifact_root, expected)
        )
    except EvidenceValidationError as exc:
        print("evidence-provider: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
