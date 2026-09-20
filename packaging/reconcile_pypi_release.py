#!/usr/bin/env python3
"""Reconcile an exact Startup Factory distribution set with public PyPI.

PyPI distribution filenames are immutable.  A release retry therefore cannot
blindly upload the complete local ``dist`` directory: a previous attempt may
have published all or only some of those files.  This helper treats PyPI as an
untrusted, bounded input, verifies every existing file and its PEP 740 publish
provenance, and prepares a private directory containing only artifacts that are
still absent.  It never overwrites or silently skips an existing artifact.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


PROJECT = "startup-factory"
WHEEL_PROJECT = "startup_factory"
PUBLISHER_REPOSITORY = "alexrolls/startup-factory"
PUBLISHER_WORKFLOW = "release.yml"
PUBLISHER_ENVIRONMENT = "pypi"
PYPI_ORIGIN = "https://pypi.org"
PYPI_JSON_ACCEPT = "application/json"
PYPI_INTEGRITY_ACCEPT = "application/vnd.pypi.integrity.v1+json"
PUBLISH_PREDICATE = "https://docs.pypi.org/attestations/publish/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
SAFE_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}\Z")
MAX_DISTRIBUTION_BYTES = 1024 * 1024 * 1024
MAX_RELEASE_JSON_BYTES = 512 * 1024
MAX_PROVENANCE_JSON_BYTES = 2 * 1024 * 1024
MAX_STATEMENT_BYTES = 128 * 1024
MAX_JSON_DEPTH = 20
MAX_JSON_NODES = 8192
HTTP_TIMEOUT_SECONDS = 5.0


class ReconciliationError(RuntimeError):
    """The local or remote release state cannot be trusted."""


class RemoteUnavailable(ReconciliationError):
    """PyPI could not be read because of a bounded transient failure."""


class RemoteConflict(ReconciliationError):
    """PyPI has a release state that cannot be resumed automatically."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Artifact:
    name: str
    path: Path
    sha256: str
    size: int
    package_type: str


FetchJson = Callable[..., object | None]


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Reject redirects before urllib can contact the supplied destination."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        close = getattr(file_pointer, "close", None)
        if callable(close):
            close()
        del request, code, message, headers, new_url
        raise ReconciliationError("PyPI redirected away from the fixed endpoint")


PYPI_OPENER = urllib.request.build_opener(_RejectRedirects())


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("JSON contains too many values")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON nesting is too deep")
        if isinstance(current, dict):
            if len(current) > 256:
                raise ValueError("JSON object contains too many members")
            if not all(isinstance(key, str) for key in current):
                raise ValueError("JSON object key is not text")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            if len(current) > 256:
                raise ValueError("JSON array contains too many values")
            stack.extend((item, depth + 1) for item in current)
        elif current is not None and not isinstance(current, (str, int, float, bool)):
            raise ValueError("JSON contains an unsupported value")


def _decode_json(payload: bytes, *, label: str) -> object:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite number: {token}")
            ),
        )
        _validate_json_shape(value)
        return value
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ReconciliationError(f"{label} is not bounded canonical JSON") from exc


def _fetch_json(
    url: str,
    *,
    accept: str,
    limit: int,
    timeout: float = HTTP_TIMEOUT_SECONDS,
) -> object | None:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "User-Agent": "startup-factory-release-reconciler/1",
        },
        method="GET",
    )
    try:
        with PYPI_OPENER.open(request, timeout=timeout) as response:
            if response.status != 200:
                if response.status in {403, 408, 425, 429} or response.status >= 500:
                    raise RemoteUnavailable("PyPI is temporarily unavailable")
                raise ReconciliationError("PyPI returned an unexpected HTTP status")
            if response.geturl() != url:
                raise ReconciliationError("PyPI redirected away from the fixed endpoint")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared = int(content_length, 10)
                except ValueError as exc:
                    raise ReconciliationError("PyPI returned an invalid Content-Length") from exc
                if declared < 0 or declared > limit:
                    raise ReconciliationError("PyPI JSON response exceeds its size limit")
            payload = response.read(limit + 1)
            if len(payload) > limit:
                raise ReconciliationError("PyPI JSON response exceeds its size limit")
    except urllib.error.HTTPError as exc:
        code = exc.code
        response_url = exc.geturl()
        exc.close()
        if code == 404 and response_url == url:
            return None
        if code in {403, 408, 425, 429} or code >= 500:
            raise RemoteUnavailable("PyPI request is temporarily unavailable") from exc
        raise ReconciliationError("PyPI request failed closed") from exc
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise RemoteUnavailable("PyPI request is temporarily unavailable") from exc
    return _decode_json(payload, label="PyPI response")


def _directory(path: Path) -> Path:
    requested = path.expanduser().absolute()
    try:
        metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise ReconciliationError("distribution directory is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReconciliationError("distribution directory must be a non-symlink directory")
    return resolved


def _hash_regular(path: Path, *, label: str) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReconciliationError(f"cannot open {label}") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        named_before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(named_before.st_mode)
            or (before.st_dev, before.st_ino) != (named_before.st_dev, named_before.st_ino)
            or before.st_size > MAX_DISTRIBUTION_BYTES
        ):
            raise ReconciliationError(f"{label} is not a bounded stable regular file")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_DISTRIBUTION_BYTES:
                raise ReconciliationError(f"{label} exceeds its size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        named_after = path.lstat()
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            size != after.st_size
            or identity_before != identity_after
            or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        ):
            raise ReconciliationError(f"{label} changed while it was read")
    except OSError as exc:
        raise ReconciliationError(f"cannot read {label}") from exc
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def _local_artifacts(version: str, distributions: Path) -> dict[str, Artifact]:
    if VERSION.fullmatch(version) is None:
        raise ReconciliationError("version must be stable numeric SemVer")
    root = _directory(distributions)
    specifications = {
        f"{WHEEL_PROJECT}-{version}-py3-none-any.whl": "bdist_wheel",
        f"{WHEEL_PROJECT}-{version}.tar.gz": "sdist",
    }
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise ReconciliationError("cannot list distribution directory") from exc
    if {entry.name for entry in entries} != set(specifications):
        raise ReconciliationError("distribution directory has the wrong exact inventory")
    artifacts: dict[str, Artifact] = {}
    for name, package_type in specifications.items():
        path = root / name
        digest, size = _hash_regular(path, label=f"local distribution {name}")
        artifacts[name] = Artifact(name, path, digest, size, package_type)
    return artifacts


def _normalized_project(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _remote_artifacts(
    payload: object, expected: dict[str, Artifact], *, version: str
) -> dict[str, Artifact]:
    if not isinstance(payload, dict):
        raise RemoteConflict("invalid-release-json", "PyPI release JSON is not an object")
    info = payload.get("info")
    urls = payload.get("urls")
    if not isinstance(info, dict) or not isinstance(urls, list):
        raise RemoteConflict("invalid-release-json", "PyPI release JSON has no typed release data")
    project_name = info.get("name")
    if not isinstance(project_name, str) or _normalized_project(project_name) != PROJECT:
        raise RemoteConflict("wrong-project", "PyPI release JSON identifies another project")
    if info.get("version") != version:
        raise RemoteConflict("wrong-version", "PyPI release JSON identifies another version")
    if not urls or len(urls) > 16:
        raise RemoteConflict("invalid-release-files", "PyPI release has an invalid file inventory")

    remote: dict[str, Artifact] = {}
    for entry in urls:
        if not isinstance(entry, dict):
            raise RemoteConflict("invalid-release-files", "PyPI release file is not an object")
        name = entry.get("filename")
        if (
            not isinstance(name, str)
            or SAFE_FILENAME.fullmatch(name) is None
            or name not in expected
        ):
            raise RemoteConflict("unexpected-file", "PyPI release contains an unexpected filename")
        if name in remote:
            raise RemoteConflict("duplicate-file", "PyPI release repeats a distribution filename")
        artifact = expected[name]
        if entry.get("packagetype") != artifact.package_type:
            raise RemoteConflict("wrong-package-type", "PyPI distribution type does not match")
        if entry.get("yanked") is not False:
            raise RemoteConflict("yanked-file", "PyPI distribution is yanked or has invalid yank state")
        digests = entry.get("digests")
        digest = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise RemoteConflict("invalid-digest", "PyPI distribution has no valid SHA-256")
        if digest != artifact.sha256:
            raise RemoteConflict("digest-mismatch", "PyPI distribution bytes differ from the candidate")
        remote[name] = artifact
    return remote


def _validate_provenance(payload: object, artifact: Artifact) -> None:
    # PyPI is the trust boundary here: its HTTPS Integrity API exposes the
    # Trusted Publisher identity after PyPI has verified the uploaded PEP 740
    # attestation.  This release helper validates that authoritative identity,
    # the bounded verification-material shape, and the exact signed subject; it
    # deliberately does not implement a second ad-hoc Sigstore verifier.
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "attestation_bundles"}
        or payload.get("version") != 1
    ):
        raise RemoteConflict("invalid-provenance", "PyPI provenance schema/version is invalid")
    bundles = payload.get("attestation_bundles")
    if not isinstance(bundles, list) or len(bundles) != 1:
        raise RemoteConflict("invalid-provenance", "PyPI must expose exactly one provenance bundle")
    bundle = bundles[0]
    if not isinstance(bundle, dict) or set(bundle) != {"publisher", "attestations"}:
        raise RemoteConflict("invalid-provenance", "PyPI provenance bundle is invalid")
    publisher = bundle.get("publisher")
    publisher_keys = set(publisher) if isinstance(publisher, dict) else set()
    required_publisher_keys = {"kind", "repository", "workflow", "environment"}
    allowed_publisher_keys = (
        required_publisher_keys,
        required_publisher_keys | {"claims"},
    )
    if (
        not isinstance(publisher, dict)
        or publisher_keys not in allowed_publisher_keys
        or ("claims" in publisher and publisher["claims"] is not None)
        or {
            "kind": publisher.get("kind"),
            "repository": publisher.get("repository"),
            "workflow": publisher.get("workflow"),
            "environment": publisher.get("environment"),
        }
        != {
            "kind": "GitHub",
            "repository": PUBLISHER_REPOSITORY,
            "workflow": PUBLISHER_WORKFLOW,
            "environment": PUBLISHER_ENVIRONMENT,
        }
    ):
        raise RemoteConflict("foreign-provenance", "PyPI provenance has the wrong publisher identity")
    attestations = bundle.get("attestations")
    if not isinstance(attestations, list) or len(attestations) != 1:
        raise RemoteConflict("invalid-provenance", "PyPI must expose exactly one publish attestation")
    attestation = attestations[0]
    if (
        not isinstance(attestation, dict)
        or set(attestation) != {"version", "envelope", "verification_material"}
        or attestation.get("version") != 1
    ):
        raise RemoteConflict("invalid-provenance", "PyPI publish attestation version is invalid")
    envelope = attestation.get("envelope")
    verification_material = attestation.get("verification_material")
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"signature", "statement"}
        or not isinstance(verification_material, dict)
        or set(verification_material) != {"certificate", "transparency_entries"}
    ):
        raise RemoteConflict("invalid-provenance", "PyPI publish attestation envelope is invalid")
    certificate = verification_material.get("certificate")
    transparency_entries = verification_material.get("transparency_entries")
    if not isinstance(certificate, str) or not certificate or len(certificate) > 1024 * 1024:
        raise RemoteConflict("invalid-provenance", "PyPI publish attestation certificate is invalid")
    try:
        certificate_bytes = base64.b64decode(certificate, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RemoteConflict(
            "invalid-provenance", "PyPI publish attestation certificate is not valid base64"
        ) from exc
    if not certificate_bytes or len(certificate_bytes) > 512 * 1024:
        raise RemoteConflict("invalid-provenance", "PyPI publish attestation certificate is invalid")
    if (
        not isinstance(transparency_entries, list)
        or not 1 <= len(transparency_entries) <= 16
        or any(not isinstance(entry, dict) or not entry for entry in transparency_entries)
    ):
        raise RemoteConflict(
            "invalid-provenance", "PyPI publish attestation transparency log is invalid"
        )
    signature = envelope.get("signature")
    if not isinstance(signature, str) or not signature or len(signature) > 128 * 1024:
        raise RemoteConflict("invalid-provenance", "PyPI publish attestation has no signature")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RemoteConflict(
            "invalid-provenance", "PyPI publish attestation signature is not valid base64"
        ) from exc
    if not signature_bytes or len(signature_bytes) > 64 * 1024:
        raise RemoteConflict("invalid-provenance", "PyPI publish attestation signature is invalid")
    encoded = envelope.get("statement")
    if not isinstance(encoded, str) or len(encoded) > MAX_STATEMENT_BYTES * 2:
        raise RemoteConflict("invalid-provenance", "PyPI publish statement is invalid")
    try:
        statement_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RemoteConflict("invalid-provenance", "PyPI publish statement is not valid base64") from exc
    if len(statement_bytes) > MAX_STATEMENT_BYTES:
        raise RemoteConflict("invalid-provenance", "PyPI publish statement exceeds its size limit")
    try:
        statement = _decode_json(statement_bytes, label="PyPI publish statement")
    except ReconciliationError as exc:
        raise RemoteConflict("invalid-provenance", str(exc)) from exc
    if not isinstance(statement, dict) or set(statement) != {
        "_type",
        "subject",
        "predicateType",
        "predicate",
    }:
        raise RemoteConflict("invalid-provenance", "PyPI publish statement schema is invalid")
    if (
        statement.get("_type") != STATEMENT_TYPE
        or statement.get("predicateType") != PUBLISH_PREDICATE
        or statement.get("predicate") not in (None, {})
    ):
        raise RemoteConflict("invalid-provenance", "PyPI publish statement type is invalid")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise RemoteConflict("invalid-provenance", "PyPI publish statement subject is invalid")
    subject = subjects[0]
    if (
        not isinstance(subject, dict)
        or set(subject) != {"name", "digest"}
        or subject.get("name") != artifact.name
    ):
        raise RemoteConflict("provenance-subject-mismatch", "PyPI provenance names another artifact")
    digest = subject.get("digest")
    if not isinstance(digest, dict) or set(digest) != {"sha256"} or digest.get("sha256") != artifact.sha256:
        raise RemoteConflict("provenance-digest-mismatch", "PyPI provenance binds different bytes")


def _result(
    *,
    version: str,
    expected: dict[str, Artifact],
    published: set[str],
    state: str,
    reason_code: str | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "ok": state != "conflict",
        "project": PROJECT,
        "version": version,
        "state": state,
        "expectedArtifacts": [
            {"name": item.name, "sha256": item.sha256}
            for item in sorted(expected.values(), key=lambda value: value.name)
        ],
        "publishedArtifacts": sorted(published),
        "missingArtifacts": sorted(set(expected) - published),
        "provenanceVerified": state in {"partial-exact", "complete-exact"},
        "reasonCode": reason_code,
        "reason": reason,
        "uploadDirectory": None,
        "uploadArtifacts": [],
    }


def _copy_exact(source: Artifact, target: Path) -> None:
    read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        source_fd = os.open(source.path, read_flags)
    except OSError as exc:
        raise ReconciliationError("cannot reopen exact PyPI upload artifact") from exc
    target_fd = -1
    try:
        target_fd = os.open(target, write_flags, 0o600)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            offset = 0
            while offset < len(chunk):
                offset += os.write(target_fd, chunk[offset:])
        os.fsync(target_fd)
    except OSError as exc:
        raise ReconciliationError("cannot prepare exact PyPI upload artifact") from exc
    finally:
        os.close(source_fd)
        if target_fd >= 0:
            os.close(target_fd)
    digest, size = _hash_regular(target, label=f"prepared distribution {source.name}")
    if (digest, size) != (source.sha256, source.size):
        raise ReconciliationError("prepared PyPI upload artifact changed while copied")


def _prepare_upload(
    destination: Path,
    *,
    missing: Sequence[str],
    artifacts: dict[str, Artifact],
) -> Path:
    requested = destination.expanduser().absolute()
    parent = requested.parent
    try:
        parent_metadata = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise ReconciliationError("PyPI upload-directory parent is unavailable") from exc
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ReconciliationError("PyPI upload-directory parent must be a non-symlink directory")
    target = resolved_parent / requested.name
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ReconciliationError("cannot inspect PyPI upload directory") from exc
    else:
        raise ReconciliationError("PyPI upload directory already exists")

    created: list[Path] = []
    try:
        os.mkdir(target, 0o700)
        os.chmod(target, 0o700)
        for name in sorted(missing):
            if name not in artifacts:
                raise ReconciliationError("missing upload artifact is not part of the exact release")
            prepared = target / name
            created.append(prepared)
            _copy_exact(artifacts[name], prepared)
            os.chmod(prepared, 0o600)
    except Exception:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        try:
            target.rmdir()
        except OSError:
            pass
        raise
    return target


def reconcile_release(
    *,
    version: str,
    distributions: Path,
    fetch_json: FetchJson = _fetch_json,
    prepare_upload: Path | None = None,
) -> dict[str, object]:
    expected = _local_artifacts(version, distributions)
    release_url = f"{PYPI_ORIGIN}/pypi/{PROJECT}/{version}/json"
    try:
        release = fetch_json(
            release_url,
            accept=PYPI_JSON_ACCEPT,
            limit=MAX_RELEASE_JSON_BYTES,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        if release is None:
            result = _result(
                version=version,
                expected=expected,
                published=set(),
                state="absent",
            )
        else:
            remote = _remote_artifacts(release, expected, version=version)
            for name, artifact in remote.items():
                encoded_name = urllib.parse.quote(name, safe="")
                provenance_url = (
                    f"{PYPI_ORIGIN}/integrity/{PROJECT}/{version}/"
                    f"{encoded_name}/provenance"
                )
                provenance = fetch_json(
                    provenance_url,
                    accept=PYPI_INTEGRITY_ACCEPT,
                    limit=MAX_PROVENANCE_JSON_BYTES,
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                if provenance is None:
                    raise RemoteConflict(
                        "missing-provenance",
                        "an existing PyPI distribution has no publish provenance",
                    )
                _validate_provenance(provenance, artifact)
            published = set(remote)
            state = "complete-exact" if published == set(expected) else "partial-exact"
            result = _result(
                version=version,
                expected=expected,
                published=published,
                state=state,
            )
    except RemoteConflict as exc:
        result = _result(
            version=version,
            expected=expected,
            published=set(),
            state="conflict",
            reason_code=exc.code,
            reason=str(exc),
        )
    except RemoteUnavailable as exc:
        result = _result(
            version=version,
            expected=expected,
            published=set(),
            state="conflict",
            reason_code="remote-unavailable",
            reason=str(exc),
        )
    except ReconciliationError as exc:
        result = _result(
            version=version,
            expected=expected,
            published=set(),
            state="conflict",
            reason_code="remote-read-failed",
            reason=str(exc),
        )

    if prepare_upload is not None and result["state"] in {"absent", "partial-exact"}:
        missing = result["missingArtifacts"]
        assert isinstance(missing, list)
        prepared = _prepare_upload(
            prepare_upload,
            missing=[str(item) for item in missing],
            artifacts=expected,
        )
        result["uploadDirectory"] = os.fspath(prepared)
        result["uploadArtifacts"] = list(missing)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reconcile exact Startup Factory distributions with public PyPI"
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--distributions", type=Path, required=True)
    parser.add_argument("--prepare-upload", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument(
        "--retry-transient",
        action="store_true",
        help="return retryable status 1 for transient post-publication reads",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.prepare_upload is not None and arguments.require_complete:
        print(
            "pypi-reconcile: --prepare-upload and --require-complete are mutually exclusive",
            file=sys.stderr,
        )
        return 2
    if arguments.retry_transient and not arguments.require_complete:
        print(
            "pypi-reconcile: --retry-transient requires --require-complete",
            file=sys.stderr,
        )
        return 2
    try:
        result = reconcile_release(
            version=arguments.version,
            distributions=arguments.distributions,
            prepare_upload=arguments.prepare_upload,
        )
    except ReconciliationError as exc:
        print(f"pypi-reconcile: {exc}", file=sys.stderr)
        return 2
    if arguments.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(f"PyPI release {result['version']}: {result['state']}")
    if result["state"] == "conflict":
        if arguments.retry_transient and result["reasonCode"] in {
            "missing-provenance",
            "remote-unavailable",
        }:
            return 1
        return 2
    if arguments.require_complete and result["state"] != "complete-exact":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
