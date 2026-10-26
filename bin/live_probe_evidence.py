#!/usr/bin/env python3
"""Offline validation of operator-collected, untrusted live-probe transcripts.

This module performs no live execution and grants no delivery authority.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

from evidence_provider import (
    COMMIT_RE,
    SEMVER_RE,
    EvidenceValidationError,
    _array,
    _artifact_path,
    _canonical_digest,
    _enum,
    _hash,
    _identifier,
    _integer,
    _load_json_document,
    _origin,
    _read_regular_file,
    _text,
    _timestamp,
    _url_path,
)


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 524_288
MAX_BINDING_BYTES = 262_144
MAX_PROBES = 100
MAX_CHECKS = 50
MAX_ARTIFACTS = 200
MAX_ARTIFACT_BYTES = 262_144
MAX_TOTAL_ARTIFACT_BYTES = 4 * 1024 * 1024
STATUSES = {"passed", "failed", "error"}
PHASES = {"precondition", "behavioral"}
BINDING_KEYS = {"provider", "subject", "capability", "target", "requiredProbes"}
TOP_KEYS = {
    "schemaVersion", "provider", "subject", "capability", "target", "collection",
    "status", "probes", "artifacts", "redactions",
}
PROBE_BINDING_KEYS = {"id", "acceptanceCriterionId", "entryPath", "locale", "variantId"}
REQUIRED_PROBE_KEYS = PROBE_BINDING_KEYS | {"preconditionCheckIds", "behavioralCheckIds"}
PROBE_KEYS = PROBE_BINDING_KEYS | {
    "startedAt", "finishedAt", "status", "precondition", "behavioral",
}
ARTIFACT_KEYS = {
    "id", "probeId", "phase", "kind", "path", "mimeType", "sizeBytes", "sha256",
}
REQUIRED_REDACTIONS = [
    {"kind": "credentials", "method": "removed"},
    {"kind": "personal-data", "method": "masked"},
    {"kind": "request-query", "method": "removed"},
    {"kind": "environment-value", "method": "omitted"},
    {"kind": "artifact-path", "method": "basename-only"},
]


def _object(value, keys: set[str], path: str) -> dict:
    # Do not echo unknown field names or their values into diagnostics.
    if not isinstance(value, dict) or set(value) != keys:
        raise EvidenceValidationError("%s has invalid fields" % path)
    return value


def _document(path: Path, limit: int, label: str):
    try:
        value, raw = _load_json_document(path, limit, label)
    except RecursionError as exc:
        raise EvidenceValidationError("%s exceeds the JSON nesting cap" % label) from exc
    except EvidenceValidationError as exc:
        if str(exc).startswith("duplicate JSON key:"):
            raise EvidenceValidationError("%s contains a duplicate JSON key" % label) from exc
        raise
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if isinstance(item, (dict, list)):
            if depth >= 16:
                raise EvidenceValidationError("%s exceeds the JSON nesting cap" % label)
            children = item.values() if isinstance(item, dict) else item
            pending.extend((child, depth + 1) for child in children)
    return value, raw


def _ids(value, path: str, maximum: int) -> list[str]:
    items = _array(value, path, maximum)
    for position, item in enumerate(items):
        _identifier(item, "%s[%d]" % (path, position))
    if not items or items != sorted(set(items)):
        raise EvidenceValidationError("%s must be non-empty, sorted, and unique" % path)
    return items


def _aggregate(statuses: list[str]) -> str:
    return "error" if "error" in statuses else "failed" if "failed" in statuses else "passed"


def _status(value, statuses: list[str], path: str) -> str:
    status = _enum(value, STATUSES, path)
    if not statuses or status != _aggregate(statuses):
        raise EvidenceValidationError("%s does not match its check status aggregate" % path)
    return status


def _interval(value: dict, path: str, enclosing=None):
    start = _timestamp(value["startedAt"], path + ".startedAt")
    finish = _timestamp(value["finishedAt"], path + ".finishedAt")
    if finish < start:
        raise EvidenceValidationError("%s.finishedAt precedes startedAt" % path)
    if enclosing is not None and not enclosing[0] <= start <= finish <= enclosing[1]:
        raise EvidenceValidationError("%s timestamps fall outside collection interval" % path)
    return start, finish


def _provider(value) -> dict:
    item = _object(value, {"id", "version", "procedureSha256"}, "provider")
    if item["id"] != "startup-factory.live-probe":
        raise EvidenceValidationError("provider.id is unsupported")
    if not isinstance(item["version"], str) or not SEMVER_RE.fullmatch(item["version"]):
        raise EvidenceValidationError("provider.version must be a stable semantic version")
    _hash(item["procedureSha256"], "provider.procedureSha256")
    return item


def _subject(value) -> dict:
    item = _object(value, {"taskId", "attempt", "commit"}, "subject")
    _text(item["taskId"], "subject.taskId", 256)
    _integer(item["attempt"], "subject.attempt", 1, 1_000_000)
    if not isinstance(item["commit"], str) or not COMMIT_RE.fullmatch(item["commit"]):
        raise EvidenceValidationError("subject.commit must be a lowercase 40-hex commit")
    return item


def _target(value) -> dict:
    item = _object(value, {"origin", "deploymentId"}, "target")
    _origin(item["origin"], "target.origin")
    _identifier(item["deploymentId"], "target.deploymentId")
    return item


def _probe_binding(value, path: str) -> None:
    for key in ("id", "acceptanceCriterionId", "variantId"):
        _identifier(value[key], path + "." + key)
    _url_path(value["entryPath"], path + ".entryPath")
    locale = _identifier(value["locale"], path + ".locale")
    if not re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,4}", locale):
        raise EvidenceValidationError("%s.locale must be a bounded language tag" % path)


def _expected_binding(value) -> tuple[dict, dict[str, dict]]:
    binding = _object(value, BINDING_KEYS, "expectedBinding")
    _provider(binding["provider"])
    _subject(binding["subject"])
    _target(binding["target"])
    if binding["capability"] != "live-probe":
        raise EvidenceValidationError("expectedBinding.capability is unsupported")
    required = _array(binding["requiredProbes"], "expectedBinding.requiredProbes", MAX_PROBES)
    if not required:
        raise EvidenceValidationError("expectedBinding.requiredProbes must not be empty")
    index = {}
    for position, value in enumerate(required):
        path = "expectedBinding.requiredProbes[%d]" % position
        probe = _object(value, REQUIRED_PROBE_KEYS, path)
        _probe_binding(probe, path)
        if probe["id"] in index:
            raise EvidenceValidationError("expectedBinding.requiredProbes contains duplicate IDs")
        for phase in sorted(PHASES):
            _ids(probe[phase + "CheckIds"], path + "." + phase + "CheckIds", MAX_CHECKS)
        index[probe["id"]] = probe
    return binding, index


def _collection(value):
    item = _object(value, {"method", "engine", "startedAt", "finishedAt"}, "collection")
    if item["method"] != "operator":
        raise EvidenceValidationError("collection.method must be operator")
    if item["engine"] is not None:
        engine = _object(item["engine"], {"id", "version", "modelId"}, "collection.engine")
        _identifier(engine["id"], "collection.engine.id")
        _identifier(engine["version"], "collection.engine.version")
        if engine["modelId"] is not None:
            _identifier(engine["modelId"], "collection.engine.modelId")
    return _interval(item, "collection")


def _checks(value, required_ids, path: str, interval) -> dict:
    group = _object(value, {"status", "checks"}, path)
    checks = _array(group["checks"], path + ".checks", MAX_CHECKS)
    index = {}
    for position, value in enumerate(checks):
        check_path = "%s.checks[%d]" % (path, position)
        check = _object(value, {"id", "status", "observedAt", "artifactId"}, check_path)
        identifier = _identifier(check["id"], check_path + ".id")
        if identifier in index:
            raise EvidenceValidationError("%s contains duplicate check IDs" % path)
        status = _enum(check["status"], STATUSES, check_path + ".status")
        observed = _timestamp(check["observedAt"], check_path + ".observedAt")
        if not interval[0] <= observed <= interval[1]:
            raise EvidenceValidationError("%s.observedAt falls outside probe interval" % check_path)
        if check["artifactId"] is None:
            if status != "error":
                raise EvidenceValidationError("%s requires a transcript artifact" % check_path)
        else:
            _identifier(check["artifactId"], check_path + ".artifactId")
        index[identifier] = check
    if set(index) != set(required_ids):
        raise EvidenceValidationError("%s check IDs do not match the expected binding" % path)
    _status(group["status"], [check["status"] for check in checks], path + ".status")
    return group


def _probes(value, required, collection_interval) -> dict[str, dict]:
    probes = _array(value, "probes", MAX_PROBES)
    index = {}
    for position, value in enumerate(probes):
        path = "probes[%d]" % position
        probe = _object(value, PROBE_KEYS, path)
        _probe_binding(probe, path)
        identifier = probe["id"]
        if identifier in index:
            raise EvidenceValidationError("probes contain duplicate IDs")
        if identifier not in required or any(
            probe[key] != required[identifier][key] for key in PROBE_BINDING_KEYS
        ):
            raise EvidenceValidationError("%s does not match the expected binding" % path)
        interval = _interval(probe, path, collection_interval)
        for phase in sorted(PHASES):
            _checks(probe[phase], required[identifier][phase + "CheckIds"], path + "." + phase, interval)
        precondition = probe["precondition"]
        behavioral = probe["behavioral"]
        if precondition["status"] != "passed" and any(
            check["status"] == "passed" for check in behavioral["checks"]
        ):
            raise EvidenceValidationError("%s passed behavior without checked preconditions" % path)
        if max(_timestamp(check["observedAt"], path) for check in precondition["checks"]) > min(
            _timestamp(check["observedAt"], path) for check in behavioral["checks"]
        ):
            raise EvidenceValidationError("%s behavioral checks precede preconditions" % path)
        _status(probe["status"], [precondition["status"], behavioral["status"]], path + ".status")
        index[identifier] = probe
    if set(index) != set(required):
        raise EvidenceValidationError("probe IDs do not match the expected binding")
    return index


def _artifacts(value, root: Path, probes: dict) -> dict[str, dict]:
    items = _array(value, "artifacts", MAX_ARTIFACTS)
    index = {}
    paths = set()
    total = 0
    for position, value in enumerate(items):
        path = "artifacts[%d]" % position
        item = _object(value, ARTIFACT_KEYS, path)
        identifier = _identifier(item["id"], path + ".id")
        if identifier in index:
            raise EvidenceValidationError("artifacts contain duplicate IDs")
        _identifier(item["probeId"], path + ".probeId")
        if item["probeId"] not in probes:
            raise EvidenceValidationError("%s.probeId is unknown" % path)
        _enum(item["phase"], PHASES, path + ".phase")
        if item["kind"] != "transcript" or item["mimeType"] != "text/plain":
            raise EvidenceValidationError("%s must be a plain-text transcript" % path)
        if not isinstance(item["path"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.txt", item["path"]):
            raise EvidenceValidationError("%s.path must be a safe .txt basename" % path)
        if item["path"] in paths:
            raise EvidenceValidationError("artifacts reuse a transcript path")
        paths.add(item["path"])
        size = _integer(item["sizeBytes"], path + ".sizeBytes", 1, MAX_ARTIFACT_BYTES)
        total += size
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise EvidenceValidationError("artifacts exceed the total size cap")
        digest = _hash(item["sha256"], path + ".sha256")
        content = _read_regular_file(_artifact_path(root, item["path"], path), MAX_ARTIFACT_BYTES, path)
        if len(content) != size:
            raise EvidenceValidationError("%s size does not match the artifact" % path)
        if "sha256:" + hashlib.sha256(content).hexdigest() != digest:
            raise EvidenceValidationError("%s hash does not match the artifact" % path)
        try:
            transcript = content.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise EvidenceValidationError("%s must be UTF-8 plain text" % path) from exc
        if not transcript.strip() or any(
            unicodedata.category(character).startswith("C") and character != "\n"
            for character in transcript
        ):
            raise EvidenceValidationError("%s contains empty text or unsafe control characters" % path)
        index[identifier] = item
    referenced = set()
    for probe_id, probe in probes.items():
        for phase in sorted(PHASES):
            for check in probe[phase]["checks"]:
                artifact_id = check["artifactId"]
                if artifact_id is None:
                    continue
                if artifact_id not in index:
                    raise EvidenceValidationError("check references an unknown transcript artifact")
                artifact = index[artifact_id]
                if artifact["probeId"] != probe_id or artifact["phase"] != phase:
                    raise EvidenceValidationError("transcript probe or phase binding mismatch")
                referenced.add(artifact_id)
    if referenced != set(index):
        raise EvidenceValidationError("manifest contains an unreferenced transcript artifact")
    return index


def validate_and_index(manifest_path, artifact_root, expected_binding: dict) -> dict:
    """Check evidence against independent caller expectations; return diagnostics."""
    binding, required = _expected_binding(expected_binding)
    root_path = Path(artifact_root)
    if root_path.is_symlink() or not root_path.is_dir():
        raise EvidenceValidationError("artifact root must be a non-symlink directory")
    manifest, raw = _document(Path(manifest_path), MAX_MANIFEST_BYTES, "manifest")
    _object(manifest, TOP_KEYS, "manifest")
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != SCHEMA_VERSION:
        raise EvidenceValidationError("manifest.schemaVersion is unsupported")
    _provider(manifest["provider"])
    _subject(manifest["subject"])
    _target(manifest["target"])
    for key in ("provider", "subject", "capability", "target"):
        if manifest[key] != binding[key]:
            raise EvidenceValidationError("manifest %s does not match the expected binding" % key)
    collection_interval = _collection(manifest["collection"])
    probes = _probes(manifest["probes"], required, collection_interval)
    artifacts = _artifacts(manifest["artifacts"], root_path.resolve(), probes)
    if manifest["redactions"] != REQUIRED_REDACTIONS:
        raise EvidenceValidationError("redactions must exactly declare the required protections")
    top_status = _status(manifest["status"], [probe["status"] for probe in probes.values()], "manifest.status")
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "manifestValid": True,
        "untrusted": True,
        "authoritative": False,
        "manifestSha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "expectedBindingSha256": _canonical_digest(binding),
        "artifactSetSha256": _canonical_digest([artifacts[key] for key in sorted(artifacts)]),
        "provider": copy.deepcopy(binding["provider"]),
        "subject": copy.deepcopy(binding["subject"]),
        "capability": binding["capability"],
        "target": copy.deepcopy(binding["target"]),
        "status": top_status,
        "probeIndex": {
            identifier: {
                **{key: probe[key] for key in sorted(PROBE_BINDING_KEYS - {"id"})},
                "status": probe["status"],
                **{
                    phase + "CheckIds": sorted(check["id"] for check in probe[phase]["checks"])
                    for phase in sorted(PHASES)
                },
                "artifactIds": sorted({
                    check["artifactId"] for phase in PHASES for check in probe[phase]["checks"]
                    if check["artifactId"] is not None
                }),
            }
            for identifier, probe in sorted(probes.items())
        },
        "artifactIndex": copy.deepcopy(dict(sorted(artifacts.items()))),
    }
    result["indexSha256"] = _canonical_digest(result)
    return result


def validate_manifest(manifest_path, artifact_root, expected_binding: dict) -> dict:
    result = validate_and_index(manifest_path, artifact_root, expected_binding)
    result["probeCount"] = len(result.pop("probeIndex"))
    result["artifactCount"] = len(result.pop("artifactIndex"))
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "index"):
        command = subparsers.add_parser(name)
        command.add_argument("--manifest", required=True)
        command.add_argument("--artifact-root", required=True)
        command.add_argument("--expected-binding", required=True)
    args = parser.parse_args(argv)
    try:
        expected = _document(Path(args.expected_binding), MAX_BINDING_BYTES, "expected binding")[0]
        operation = validate_manifest if args.command == "validate" else validate_and_index
        result = operation(args.manifest, args.artifact_root, expected)
    except EvidenceValidationError as exc:
        print("live-probe-evidence: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
