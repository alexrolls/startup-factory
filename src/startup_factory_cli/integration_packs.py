"""Strict, data-only integration packs and single-target setup plans.

Integration packs are untrusted JSON.  This module is deliberately the only
loader and validator used by repository and installed command surfaces.  It
never evaluates a manifest value, turns one into argv, or treats configuration
as proof that an external integration is working.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from .installer import InstallerError
from .project_config import (
    PROJECT_CONFIG_RELATIVE_PATH,
    apply_changes_at,
    plan_changes,
    read_project_config_at,
    render_changes,
)
from .secret_safety import contains_secret_like, redact_secret_like


SCHEMA_VERSION = 1
PLAN_SCHEMA_VERSION = 2
VALIDATOR_VERSION = 2
RUNTIME_VERSION = "0.2.0"
MAX_PACK_BYTES = 64 * 1024
MAX_TARGET_BYTES = 1024 * 1024
MAX_PLAN_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_CONTAINER_ITEMS = 128
MAX_TOTAL_ITEMS = 512
MAX_STRING_LENGTH = 512
MAX_DISCOVERY_DEPTH = 4
MAX_DISCOVERY_ENTRIES = 1024
MAX_DISCOVERED_PACKS = 128

PACK_KINDS = ("tracker", "ci", "deployment")
COMPATIBILITY_STATES = ("supported", "experimental", "unsupported")
SUPPORTED_PLATFORMS = ("darwin", "linux", "windows")
RUNTIME_SUPPORTED_PLATFORMS = ("darwin", "linux")
WSL_PLATFORMS = ("wsl1", "wsl2")
TRACKER_ADAPTERS = ("GitHubIssues", "Jira", "Linear", "Markdown")
CI_PROVIDERS = ("github-actions",)
CI_EVIDENCE_CONTRACTS = ("exact-commit-green-checks",)
DEPLOYMENT_TARGETS = ("docker-compose", "kubernetes")
CREDENTIAL_POLICIES = ("none", "adapter-managed", "required-environment")
TARGET_ROOTS = ("project", "runtime")

_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_OUTPUT_FILE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}\.json\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SHELL_OR_INTERPOLATION = re.compile(
    r"(?:\$\(|\$\{|`|\{\{|\}\}|[;&|<>]|^#!|\r|\n)", re.M
)
_FORBIDDEN_FIELD = re.compile(
    r"(?i)(?:^|[-_])(?:argv|cmd|command|exec|executable|hook|run|script|shell)(?:$|[-_])"
)

_UNSAFE_ENVIRONMENT_NAMES = {
    "BASH_ENV",
    "CDPATH",
    "DOCKER_HOST",
    "ENV",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GLOBIGNORE",
    "HOME",
    "IFS",
    "KUBECONFIG",
    "NODE_OPTIONS",
    "PATH",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUBYOPT",
    "SHELL",
    "SSH_AUTH_SOCK",
}


class IntegrationPackError(InstallerError):
    """Raised when an integration pack or plan fails closed."""

    def __init__(self, message: str) -> None:
        # Some lower-level OS and parser errors may contain caller-controlled
        # path or field text. Never retain recognized secret bytes in an error.
        super().__init__(redact_secret_like(str(message)))


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise IntegrationPackError(f"{label} has invalid keys: {'; '.join(details)}")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _reject_surrogates(value: str, label: str) -> None:
    # JSON permits escaped lone surrogates, but UTF-8 output and canonical
    # plan rendering do not. Reject them at the shared manifest/plan boundary.
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise IntegrationPackError(f"{label} contains an invalid Unicode surrogate")


def _decode_json_object(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key is forbidden")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise IntegrationPackError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrationPackError(f"{label} must contain one JSON object")
    pending: list[object] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                _reject_surrogates(key, label)
                if contains_secret_like(key):
                    raise IntegrationPackError(f"{label} contains secret-like material")
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            _reject_surrogates(item, label)
            if contains_secret_like(item):
                raise IntegrationPackError(f"{label} contains secret-like material")
    return value


_ROOT_IDENTITY_KEYS = {"device", "inode", "mode"}


def _root_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": metadata.st_mode,
    }


def _validated_root_identity(value: object, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise IntegrationPackError(f"{label} must be an object")
    _exact_keys(value, _ROOT_IDENTITY_KEYS, label)
    if any(type(item) is not int or item < 0 for item in value.values()):
        raise IntegrationPackError(f"{label} values must be non-negative integers")
    return dict(value)


def _directory_flags(label: str) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory or os.open not in os.supports_dir_fd:
        raise IntegrationPackError(
            f"{label} requires secure dirfd and no-follow directory opens"
        )
    return os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)


def _open_root(path: Path, label: str) -> tuple[Path, int, dict[str, int]]:
    """Open every root component without following links and hold its identity."""

    candidate = Path(path)
    candidate_text = os.fspath(candidate)
    if (
        not candidate_text
        or len(candidate_text) > 4096
        or _CONTROL.search(candidate_text)
    ):
        raise IntegrationPackError(f"{label} must be a bounded control-free path")
    if any(part == ".." for part in candidate.parts):
        raise IntegrationPackError(f"{label} must be a normalized directory path")
    absolute = Path(os.path.abspath(os.fspath(candidate)))
    flags = _directory_flags(label)
    descriptor: int | None = None
    try:
        descriptor = os.open(absolute.anchor, flags)
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):  # pragma: no cover - O_DIRECTORY.
            raise IntegrationPackError(f"{label} must be a directory")
        return absolute, descriptor, _root_identity(metadata)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise IntegrationPackError(f"{label} is unavailable or unsafe: {exc}") from exc
    except IntegrationPackError:
        if descriptor is not None:
            os.close(descriptor)
        raise


@contextlib.contextmanager
def _held_root(path: Path, label: str):
    absolute, descriptor, identity = _open_root(path, label)
    try:
        yield absolute, descriptor, identity
    finally:
        os.close(descriptor)


def _safe_root(path: Path, label: str) -> Path:
    with _held_root(path, label) as (absolute, _, __):
        return absolute


def _safe_relative(value: str, label: str, *, basename_only: bool = False) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise IntegrationPackError(f"{label} must be a normalized relative path")
    if _CONTROL.search(value) or value.startswith("/") or value.endswith("/"):
        raise IntegrationPackError(f"{label} must be a normalized relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise IntegrationPackError(f"{label} must not escape or contain empty components")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or str(parsed) != value or (basename_only and len(parts) != 1):
        raise IntegrationPackError(f"{label} must be a normalized relative path")
    return value


def _candidate_under(root: Path, path: Path, label: str) -> tuple[Path, str]:
    root = Path(os.path.abspath(os.fspath(root)))
    candidate = path if path.is_absolute() else root / path
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root).as_posix()
    except ValueError as exc:
        raise IntegrationPackError(f"{label} escapes its declared root") from exc
    _safe_relative(relative, label)
    return candidate, relative


def _open_relative_parent(
    root_descriptor: int,
    relative: str,
    label: str,
    *,
    missing_ok: bool = False,
) -> tuple[int, str] | None:
    relative = _safe_relative(relative, label)
    parts = PurePosixPath(relative).parts
    flags = _directory_flags(label)
    descriptor = os.dup(root_descriptor)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise IntegrationPackError(f"{label} root descriptor is not a directory")
        for component in parts[:-1]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except FileNotFoundError:
        os.close(descriptor)
        if missing_ok:
            return None
        raise IntegrationPackError(f"{label} is unavailable") from None
    except OSError as exc:
        os.close(descriptor)
        raise IntegrationPackError(f"{label} parent is unavailable or unsafe: {exc}") from exc
    except IntegrationPackError:
        os.close(descriptor)
        raise


def _read_bounded_regular_at(
    root_descriptor: int,
    relative: str,
    *,
    label: str,
    max_bytes: int,
    missing_ok: bool = False,
) -> tuple[bytes, os.stat_result] | None:
    if max_bytes <= 0:
        raise IntegrationPackError(f"{label} byte limit must be positive")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    non_blocking = getattr(os, "O_NONBLOCK", 0)
    if (
        not no_follow
        or not non_blocking
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise IntegrationPackError(
            f"{label} requires secure no-follow, non-blocking dirfd reads"
        )
    opened_parent = _open_relative_parent(
        root_descriptor, relative, label, missing_ok=missing_ok
    )
    if opened_parent is None:
        return None
    parent_descriptor, name = opened_parent
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | no_follow
            | non_blocking
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise IntegrationPackError(
                f"{label} must be a bounded non-symlink regular file"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise IntegrationPackError(f"{label} is unavailable") from None
    except IntegrationPackError:
        raise
    except OSError as exc:
        raise IntegrationPackError(f"cannot securely read {label}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)
    if len(raw) > max_bytes:
        raise IntegrationPackError(f"{label} exceeds {max_bytes} bytes")
    stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable):
        raise IntegrationPackError(f"{label} changed while it was read")
    if stat.S_ISLNK(named.st_mode) or any(
        getattr(named, field) != getattr(after, field) for field in stable
    ):
        raise IntegrationPackError(f"{label} changed while it was read")
    return raw, after


def _read_bounded_regular(
    path: Path,
    *,
    root: Path,
    label: str,
    max_bytes: int,
) -> tuple[bytes, os.stat_result, str, dict[str, int]]:
    with _held_root(root, f"{label} root") as (
        absolute_root,
        root_descriptor,
        root_identity,
    ):
        _, relative = _candidate_under(absolute_root, path, label)
        result = _read_bounded_regular_at(
            root_descriptor,
            relative,
            label=label,
            max_bytes=max_bytes,
        )
        assert result is not None
        raw, metadata = result
    return raw, metadata, relative, root_identity


def _validate_tree(value: object) -> None:
    total = 0

    def visit(item: object, depth: int, path: tuple[str, ...]) -> None:
        nonlocal total
        total += 1
        if total > MAX_TOTAL_ITEMS:
            raise IntegrationPackError("integration pack contains too many values")
        if depth > MAX_DEPTH:
            raise IntegrationPackError("integration pack nesting is too deep")
        if isinstance(item, dict):
            if len(item) > MAX_CONTAINER_ITEMS:
                raise IntegrationPackError("integration pack object contains too many keys")
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 64:
                    raise IntegrationPackError("integration pack contains an invalid key")
                if _CONTROL.search(key) or _FORBIDDEN_FIELD.search(key):
                    raise IntegrationPackError(f"integration pack contains forbidden field: {key}")
                visit(child, depth + 1, (*path, key))
            return
        if isinstance(item, list):
            if len(item) > MAX_CONTAINER_ITEMS:
                raise IntegrationPackError("integration pack array contains too many values")
            for index, child in enumerate(item):
                visit(child, depth + 1, (*path, str(index)))
            return
        if isinstance(item, str):
            if not item or len(item) > MAX_STRING_LENGTH or _CONTROL.search(item):
                raise IntegrationPackError("integration pack contains an invalid string")
            if _SHELL_OR_INTERPOLATION.search(item):
                raise IntegrationPackError(
                    "integration pack contains executable or interpolated content"
                )
            if contains_secret_like(item):
                raise IntegrationPackError("integration pack contains secret-like material")
            return
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int) and not isinstance(item, bool):
            return
        raise IntegrationPackError("integration pack contains an unsupported JSON value")

    visit(value, 0, ())


def _string(value: object, label: str, *, max_length: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or _CONTROL.search(value)
    ):
        raise IntegrationPackError(f"{label} must be a non-empty bounded string")
    return value


def _identifier(value: object, label: str) -> str:
    text = _string(value, label, max_length=64)
    if _ID.fullmatch(text) is None:
        raise IntegrationPackError(f"{label} must be a normalized lowercase identifier")
    return text


def _ci_check_name(value: object) -> str:
    text = _string(value, "CI required check", max_length=256)
    if text != text.strip():
        raise IntegrationPackError(
            "CI required check must not have leading or trailing whitespace"
        )
    return text


def _environment_name(value: object) -> str:
    name = _string(value, "credential environment name", max_length=128)
    if _ENVIRONMENT_NAME.fullmatch(name) is None:
        raise IntegrationPackError("credential environment name is unsafe")
    if (
        name in _UNSAFE_ENVIRONMENT_NAMES
        or name.startswith(("LD_", "DYLD_", "GIT_", "STARTUP_FACTORY_"))
    ):
        raise IntegrationPackError(f"credential environment name is unsafe: {name}")
    return name


def _unique_strings(
    value: object,
    label: str,
    *,
    maximum: int,
    normalizer,
    require_sorted: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise IntegrationPackError(f"{label} must be an array with at most {maximum} values")
    result = tuple(normalizer(item) for item in value)
    if len(result) != len(set(result)):
        raise IntegrationPackError(f"{label} must not contain duplicates")
    if require_sorted and list(result) != sorted(result):
        raise IntegrationPackError(f"{label} must use deterministic sorted order")
    return result


@dataclasses.dataclass(frozen=True)
class IntegrationPack:
    schema_version: int
    pack_id: str
    kind: str
    display_name: str
    summary: str
    compatibility: Mapping[str, Any]
    prerequisites: tuple[str, ...]
    credential_policy: str
    credentials: tuple[str, ...]
    capability: Mapping[str, Any]
    source_path: Path
    source_root: Path
    source_root_identity: Mapping[str, int]
    source_relative: str
    source_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "id": self.pack_id,
            "kind": self.kind,
            "displayName": self.display_name,
            "summary": self.summary,
            "compatibility": dict(self.compatibility),
            "prerequisites": list(self.prerequisites),
            "credentials": {
                "policy": self.credential_policy,
                "required": list(self.credentials),
            },
            "capability": json.loads(json.dumps(self.capability)),
            "source": self.source_relative,
            "sourceDigest": self.source_digest,
        }


def _validate_compatibility(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IntegrationPackError("compatibility must be an object")
    _exact_keys(value, {"minimumVersion", "platforms", "state"}, "compatibility")
    minimum = _string(value["minimumVersion"], "minimum compatibility version", max_length=32)
    if _VERSION.fullmatch(minimum) is None:
        raise IntegrationPackError("minimum compatibility version must be numeric SemVer")
    state = _string(value["state"], "compatibility state", max_length=32)
    if state not in COMPATIBILITY_STATES:
        raise IntegrationPackError("unknown compatibility state")
    platforms = _unique_strings(
        value["platforms"],
        "compatibility platforms",
        maximum=len(SUPPORTED_PLATFORMS),
        normalizer=lambda item: _string(item, "compatibility platform", max_length=16),
        require_sorted=True,
    )
    if not platforms or any(platform not in SUPPORTED_PLATFORMS for platform in platforms):
        raise IntegrationPackError("unknown or empty compatibility platform set")
    return {"minimumVersion": minimum, "platforms": list(platforms), "state": state}


def _runtime_platform() -> str:
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("linux"):
        kernel = os.uname()
        kernel_identity = f"{kernel.release}\n{kernel.version}".casefold()
        if "microsoft" in kernel_identity or "wsl" in kernel_identity:
            if "wsl2" in kernel_identity or "microsoft-standard" in kernel_identity:
                return "wsl2"
            return "wsl1"
        return "linux"
    if sys.platform in {"win32", "cygwin", "msys"}:
        return "windows"
    return sys.platform.casefold()


def _version_tuple(value: str) -> tuple[int, int, int]:
    if _VERSION.fullmatch(value) is None:
        raise IntegrationPackError(f"runtime version is not numeric SemVer: {value}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _compatibility_report(
    pack: "IntegrationPack",
    *,
    allow_experimental: bool,
    runtime_platform: str | None = None,
) -> dict[str, Any]:
    if type(allow_experimental) is not bool:
        raise IntegrationPackError("allow_experimental must be boolean")
    platform = (
        runtime_platform if runtime_platform is not None else _runtime_platform()
    )
    compatibility_platform = "linux" if platform in WSL_PLATFORMS else platform
    if platform in WSL_PLATFORMS:
        runtime_state = "experimental"
    elif platform in RUNTIME_SUPPORTED_PLATFORMS:
        runtime_state = "supported"
    else:
        runtime_state = "unsupported"
    minimum = str(pack.compatibility["minimumVersion"])
    state = str(pack.compatibility["state"])
    supported_platforms = list(pack.compatibility["platforms"])
    reasons: list[str] = []
    if runtime_state == "unsupported":
        reasons.append(
            f"core runtime platform {platform} is unsupported by Startup Factory {RUNTIME_VERSION}"
        )
    elif runtime_state == "experimental" and not allow_experimental:
        reasons.append(
            f"core runtime platform {platform} is experimental and requires explicit preview opt-in"
        )
    if compatibility_platform not in supported_platforms:
        reasons.append(f"platform {platform} is not declared compatible")
    if _version_tuple(RUNTIME_VERSION) < _version_tuple(minimum):
        reasons.append(
            f"runtime {RUNTIME_VERSION} is older than required {minimum}"
        )
    if state == "unsupported":
        reasons.append("pack compatibility state is unsupported")
    if state == "experimental" and not allow_experimental:
        reasons.append("experimental pack requires explicit preview opt-in")
    compatible = not reasons
    return {
        "status": "compatible" if compatible else "incompatible",
        "packState": state,
        "runtimeState": runtime_state,
        "platform": platform,
        "compatibilityPlatform": compatibility_platform,
        "supportedPlatforms": supported_platforms,
        "runtimeVersion": RUNTIME_VERSION,
        "minimumVersion": minimum,
        "experimentalAllowed": allow_experimental,
        "reasons": reasons,
    }


def _require_compatible(
    pack: "IntegrationPack",
    *,
    allow_experimental: bool,
    runtime_platform: str | None = None,
) -> dict[str, Any]:
    report = _compatibility_report(
        pack,
        allow_experimental=allow_experimental,
        runtime_platform=runtime_platform,
    )
    if report["status"] != "compatible":
        raise IntegrationPackError(
            "integration pack is incompatible: " + "; ".join(report["reasons"])
        )
    return report


def _validate_credentials(value: object) -> tuple[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise IntegrationPackError("credentials must be an object")
    _exact_keys(value, {"policy", "required"}, "credentials")
    policy = _string(value["policy"], "credential policy", max_length=32)
    if policy not in CREDENTIAL_POLICIES:
        raise IntegrationPackError("unknown credential policy")
    required = _unique_strings(
        value["required"],
        "required credential environment names",
        maximum=16,
        normalizer=_environment_name,
        require_sorted=True,
    )
    if policy in {"none", "adapter-managed"} and required:
        raise IntegrationPackError(
            f"{policy} credentials must not claim unconditional environment requirements"
        )
    if policy == "required-environment" and not required:
        raise IntegrationPackError(
            "required-environment credentials must name at least one environment variable"
        )
    return policy, required


def _validate_tracker_capability(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(value, {"adapter", "teamMode"}, "tracker capability")
    adapter = _string(value["adapter"], "tracker adapter", max_length=64)
    if adapter not in TRACKER_ADAPTERS:
        raise IntegrationPackError("unknown tracker adapter")
    if type(value["teamMode"]) is not bool:
        raise IntegrationPackError("tracker teamMode must be boolean")
    return {"adapter": adapter, "teamMode": value["teamMode"]}


def _validate_output_file(value: object) -> str:
    output = _safe_relative(
        _string(value, "output file", max_length=64), "output file", basename_only=True
    )
    if _OUTPUT_FILE.fullmatch(output) is None or output.startswith("."):
        raise IntegrationPackError("output file must be a normalized non-hidden JSON filename")
    return output


def _validate_ci_capability(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(
        value,
        {"provider", "evidenceContract", "outputFile", "template"},
        "CI capability",
    )
    provider = _string(value["provider"], "CI provider", max_length=64)
    evidence = _string(value["evidenceContract"], "CI evidence contract", max_length=64)
    if provider not in CI_PROVIDERS or evidence not in CI_EVIDENCE_CONTRACTS:
        raise IntegrationPackError("unknown CI provider or evidence contract")
    template = value["template"]
    if not isinstance(template, dict):
        raise IntegrationPackError("CI template must be an object")
    _exact_keys(
        template,
        {
            "schemaVersion",
            "active",
            "provider",
            "commitBinding",
            "proofContract",
            "requiredChecks",
            "activation",
        },
        "CI template",
    )
    if template["schemaVersion"] != 1 or type(template["schemaVersion"]) is not int:
        raise IntegrationPackError("CI template schemaVersion must be 1")
    if template["active"] is not False:
        raise IntegrationPackError("CI template must remain inactive")
    if template["provider"] != provider:
        raise IntegrationPackError("CI template provider does not match the capability")
    if template["commitBinding"] != "exact" or template["proofContract"] != evidence:
        raise IntegrationPackError("CI template must retain exact-commit proof binding")
    if template["activation"] != "operator-reviewed-copy":
        raise IntegrationPackError("CI template activation must require operator review")
    checks = _unique_strings(
        template["requiredChecks"],
        "CI required checks",
        maximum=32,
        normalizer=_ci_check_name,
        require_sorted=True,
    )
    if not checks:
        raise IntegrationPackError("CI required checks must name at least one check")
    normalized_template = dict(template)
    normalized_template["requiredChecks"] = list(checks)
    return {
        "provider": provider,
        "evidenceContract": evidence,
        "outputFile": _validate_output_file(value["outputFile"]),
        "template": normalized_template,
    }


def _validate_deployment_capability(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(value, {"target", "outputFile", "template"}, "deployment capability")
    target = _string(value["target"], "deployment target", max_length=64)
    if target not in DEPLOYMENT_TARGETS:
        raise IntegrationPackError("unknown deployment target")
    template = value["template"]
    if not isinstance(template, dict):
        raise IntegrationPackError("deployment template must be an object")
    _exact_keys(
        template,
        {
            "schemaVersion",
            "enabled",
            "target",
            "mode",
            "releaseAuthority",
            "containsCredentialValues",
            "activation",
        },
        "deployment template",
    )
    if template["schemaVersion"] != 1 or type(template["schemaVersion"]) is not int:
        raise IntegrationPackError("deployment template schemaVersion must be 1")
    if template["enabled"] is not False or template["releaseAuthority"] is not False:
        raise IntegrationPackError("deployment template must be inactive and grant no authority")
    if template["containsCredentialValues"] is not False:
        raise IntegrationPackError("deployment template must contain no credential values")
    if template["target"] != target or template["mode"] != "approval-required":
        raise IntegrationPackError("deployment template target or mode is invalid")
    if template["activation"] != "external-reviewed-config-only":
        raise IntegrationPackError("deployment template activation must remain external")
    return {
        "target": target,
        "outputFile": _validate_output_file(value["outputFile"]),
        "template": dict(template),
    }


def _pack_from_raw(
    raw: bytes,
    *,
    source_root: Path,
    source_root_identity: Mapping[str, int],
    relative: str,
) -> IntegrationPack:
    document = _decode_json_object(raw, "integration pack")
    _validate_tree(document)
    _exact_keys(
        document,
        {
            "schemaVersion",
            "id",
            "kind",
            "displayName",
            "summary",
            "compatibility",
            "prerequisites",
            "credentials",
            "capability",
        },
        "integration pack",
    )
    if document["schemaVersion"] != SCHEMA_VERSION or type(document["schemaVersion"]) is not int:
        raise IntegrationPackError("unsupported integration-pack schemaVersion")
    pack_id = _identifier(document["id"], "pack id")
    kind = _string(document["kind"], "pack kind", max_length=16)
    if kind not in PACK_KINDS:
        raise IntegrationPackError("unknown pack kind")
    display_name = _string(document["displayName"], "display name", max_length=96)
    summary = _string(document["summary"], "summary", max_length=240)
    compatibility = _validate_compatibility(document["compatibility"])
    prerequisites = _unique_strings(
        document["prerequisites"],
        "prerequisites",
        maximum=16,
        normalizer=lambda item: _string(item, "prerequisite", max_length=200),
    )
    credential_policy, credentials = _validate_credentials(document["credentials"])
    capability = document["capability"]
    if not isinstance(capability, dict):
        raise IntegrationPackError("capability must be an object")
    if kind == "tracker":
        normalized_capability = _validate_tracker_capability(capability)
    elif kind == "ci":
        normalized_capability = _validate_ci_capability(capability)
    else:
        normalized_capability = _validate_deployment_capability(capability)
    return IntegrationPack(
        schema_version=SCHEMA_VERSION,
        pack_id=pack_id,
        kind=kind,
        display_name=display_name,
        summary=summary,
        compatibility=compatibility,
        prerequisites=prerequisites,
        credential_policy=credential_policy,
        credentials=credentials,
        capability=normalized_capability,
        source_path=(source_root / relative),
        source_root=source_root,
        source_root_identity=dict(source_root_identity),
        source_relative=relative,
        source_digest=_digest(raw),
    )


def _validate_pack_at(
    source_root: Path,
    root_descriptor: int,
    source_root_identity: Mapping[str, int],
    relative: str,
) -> IntegrationPack:
    result = _read_bounded_regular_at(
        root_descriptor,
        _safe_relative(relative, "integration pack"),
        label="integration pack",
        max_bytes=MAX_PACK_BYTES,
    )
    assert result is not None
    raw, _ = result
    return _pack_from_raw(
        raw,
        source_root=source_root,
        source_root_identity=source_root_identity,
        relative=relative,
    )


def validate_pack(path: Path | str, *, root: Path | str | None = None) -> IntegrationPack:
    """Load and validate one exact pack through the canonical trust boundary."""

    source_path = Path(path)
    if root is None:
        # A caller may pass ``some/root/pack.json`` as a relative path.  Once
        # that path's parent becomes the trust root, pass only the basename to
        # the root-relative reader; otherwise it would append the parent twice.
        source_root = source_path.parent
        source_argument = Path(source_path.name)
    else:
        source_root = Path(root)
        source_argument = source_path
    with _held_root(source_root, "integration pack root") as (
        absolute_root,
        root_descriptor,
        source_root_identity,
    ):
        _, relative = _candidate_under(
            absolute_root, source_argument, "integration pack"
        )
        return _validate_pack_at(
            absolute_root,
            root_descriptor,
            source_root_identity,
            relative,
        )


def _walk_json_files_at(root_descriptor: int) -> tuple[str, ...]:
    discovered: list[str] = []
    inspected = 0

    def visit(directory_descriptor: int, prefix: tuple[str, ...], depth: int) -> None:
        nonlocal inspected
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(directory_descriptor) as scan:
                for entry in scan:
                    inspected += 1
                    if inspected > MAX_DISCOVERY_ENTRIES:
                        raise IntegrationPackError(
                            "integration pack discovery contains too many entries"
                        )
                    entries.append(entry)
        except OSError as exc:
            raise IntegrationPackError(f"cannot inspect integration pack root: {exc}") from exc
        entries.sort(key=lambda item: item.name)
        for entry in entries:
            try:
                if entry.is_symlink():
                    raise IntegrationPackError(
                        f"integration pack discovery refuses symbolic link: {entry.name}"
                    )
                if entry.is_dir(follow_symlinks=False):
                    if depth >= MAX_DISCOVERY_DEPTH:
                        raise IntegrationPackError(
                            "integration pack discovery nesting is too deep"
                        )
                    child: int | None = None
                    try:
                        child = os.open(
                            entry.name,
                            _directory_flags("integration pack discovery"),
                            dir_fd=directory_descriptor,
                        )
                        child_metadata = os.fstat(child)
                        named_metadata = os.stat(
                            entry.name,
                            dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                        if (
                            not stat.S_ISDIR(named_metadata.st_mode)
                            or (child_metadata.st_dev, child_metadata.st_ino)
                            != (named_metadata.st_dev, named_metadata.st_ino)
                        ):
                            raise IntegrationPackError(
                                "integration pack discovery directory changed"
                            )
                    except IntegrationPackError:
                        if child is not None:
                            os.close(child)
                        raise
                    except OSError as exc:
                        if child is not None:
                            os.close(child)
                        raise IntegrationPackError(
                            f"cannot securely open integration pack directory: {exc}"
                        ) from exc
                    try:
                        assert child is not None
                        visit(child, (*prefix, entry.name), depth + 1)
                    finally:
                        os.close(child)
                elif entry.is_file(follow_symlinks=False) and entry.name.endswith(".json"):
                    discovered.append(PurePosixPath(*prefix, entry.name).as_posix())
                    if len(discovered) > MAX_DISCOVERED_PACKS:
                        raise IntegrationPackError(
                            "integration pack discovery contains too many packs"
                        )
            except OSError as exc:
                raise IntegrationPackError(f"cannot inspect integration pack entry: {exc}") from exc

    visit(root_descriptor, (), 0)
    return tuple(discovered)


def _open_optional_directory_at(
    root_descriptor: int, relative: str, label: str
) -> tuple[int, dict[str, int]] | None:
    opened = _open_relative_parent(
        root_descriptor, relative, label, missing_ok=True
    )
    if opened is None:
        return None
    parent_descriptor, name = opened
    child: int | None = None
    try:
        child = os.open(name, _directory_flags(label), dir_fd=parent_descriptor)
        metadata = os.fstat(child)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise IntegrationPackError(f"{label} changed while it was opened")
        return child, _root_identity(metadata)
    except FileNotFoundError:
        if child is not None:
            os.close(child)
        return None
    except IntegrationPackError:
        if child is not None:
            os.close(child)
        raise
    except OSError as exc:
        if child is not None:
            os.close(child)
        raise IntegrationPackError(f"{label} is unavailable or unsafe: {exc}") from exc
    finally:
        os.close(parent_descriptor)


def list_packs(
    reference_root: Path | str,
    *,
    project_root: Path | str | None = None,
) -> tuple[IntegrationPack, ...]:
    """Discover validated reference and optional project packs deterministically."""

    packs: list[IntegrationPack] = []
    by_id: dict[str, Path] = {}

    def consume(
        root: Path, root_descriptor: int, root_identity: Mapping[str, int]
    ) -> None:
        for relative in _walk_json_files_at(root_descriptor):
            if relative == "schema.json":
                continue
            pack = _validate_pack_at(
                root, root_descriptor, root_identity, relative
            )
            previous = by_id.get(pack.pack_id)
            if previous is not None:
                raise IntegrationPackError(
                    f"duplicate integration pack id {pack.pack_id}: {previous} and {pack.source_path}"
                )
            by_id[pack.pack_id] = pack.source_path
            packs.append(pack)

    with _held_root(
        Path(reference_root), "integration pack discovery root"
    ) as (root, root_descriptor, root_identity):
        consume(root, root_descriptor, root_identity)
    if project_root is not None:
        with _held_root(Path(project_root), "project root") as (
            project,
            project_descriptor,
            _,
        ):
            opened = _open_optional_directory_at(
                project_descriptor,
                ".startup-factory/integration-packs",
                "project integration-pack root",
            )
            if opened is not None:
                local_descriptor, local_identity = opened
                try:
                    consume(
                        project / ".startup-factory" / "integration-packs",
                        local_descriptor,
                        local_identity,
                    )
                finally:
                    os.close(local_descriptor)
    return tuple(sorted(packs, key=lambda item: (item.kind, item.pack_id)))


discover_packs = list_packs


@dataclasses.dataclass(frozen=True)
class PackPlan:
    schema_version: int
    validator_version: int
    runtime_version: str
    runtime_platform: str
    allow_experimental: bool
    pack_id: str
    kind: str
    source_path: str
    source_root: str
    source_root_identity: Mapping[str, int]
    source_digest: str
    project_root: str
    project_root_identity: Mapping[str, int]
    runtime_root: str
    runtime_root_identity: Mapping[str, int]
    target_root: str
    operation: str
    target_relative: str
    target_digest: str | None
    target_identity: Mapping[str, int] | None
    rendered_digest: str
    changes: tuple[Mapping[str, str], ...]
    plan_digest: str

    def core_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "validatorVersion": self.validator_version,
            "runtimeVersion": self.runtime_version,
            "runtimePlatform": self.runtime_platform,
            "allowExperimental": self.allow_experimental,
            "packId": self.pack_id,
            "kind": self.kind,
            "sourcePath": self.source_path,
            "sourceRoot": self.source_root,
            "sourceRootIdentity": dict(self.source_root_identity),
            "sourceDigest": self.source_digest,
            "projectRoot": self.project_root,
            "projectRootIdentity": dict(self.project_root_identity),
            "runtimeRoot": self.runtime_root,
            "runtimeRootIdentity": dict(self.runtime_root_identity),
            "targetRoot": self.target_root,
            "operation": self.operation,
            "target": self.target_relative,
            "targetDigest": self.target_digest,
            "targetIdentity": dict(self.target_identity) if self.target_identity else None,
            "renderedDigest": self.rendered_digest,
            "changes": [dict(change) for change in self.changes],
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self.core_dict(), "planDigest": self.plan_digest}

    def verify(self) -> None:
        if (
            type(self.schema_version) is not int
            or type(self.validator_version) is not int
            or self.schema_version != PLAN_SCHEMA_VERSION
            or self.validator_version != VALIDATOR_VERSION
        ):
            raise IntegrationPackError("unsupported integration-pack plan version")
        if (
            self.runtime_version != RUNTIME_VERSION
            or self.runtime_platform != _runtime_platform()
        ):
            raise IntegrationPackError(
                "integration-pack plan runtime version or platform changed"
            )
        if type(self.allow_experimental) is not bool:
            raise IntegrationPackError("plan allowExperimental must be boolean")
        if self.kind not in PACK_KINDS:
            raise IntegrationPackError("plan kind is invalid")
        if self.target_root not in TARGET_ROOTS:
            raise IntegrationPackError("plan targetRoot is invalid")
        expected_target_root = "runtime" if self.kind == "tracker" else "project"
        if self.target_root != expected_target_root:
            raise IntegrationPackError("plan targetRoot does not match pack kind")
        _validated_root_identity(
            self.source_root_identity, "plan sourceRootIdentity"
        )
        _validated_root_identity(
            self.project_root_identity, "plan projectRootIdentity"
        )
        _validated_root_identity(
            self.runtime_root_identity, "plan runtimeRootIdentity"
        )
        if _digest(_canonical(self.core_dict())) != self.plan_digest:
            raise IntegrationPackError("integration-pack plan digest does not match its content")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PackPlan":
        expected = {
            "schemaVersion",
            "validatorVersion",
            "runtimeVersion",
            "runtimePlatform",
            "allowExperimental",
            "packId",
            "kind",
            "sourcePath",
            "sourceRoot",
            "sourceRootIdentity",
            "sourceDigest",
            "projectRoot",
            "projectRootIdentity",
            "runtimeRoot",
            "runtimeRootIdentity",
            "targetRoot",
            "operation",
            "target",
            "targetDigest",
            "targetIdentity",
            "renderedDigest",
            "changes",
            "planDigest",
        }
        _exact_keys(value, expected, "integration-pack plan")
        if type(value["schemaVersion"]) is not int or type(value["validatorVersion"]) is not int:
            raise IntegrationPackError("integration-pack plan versions must be integers")
        if type(value["allowExperimental"]) is not bool:
            raise IntegrationPackError("plan allowExperimental must be boolean")
        identity = value["targetIdentity"]
        if identity is not None:
            if not isinstance(identity, dict):
                raise IntegrationPackError("plan targetIdentity must be an object or null")
            _exact_keys(
                identity,
                {"device", "inode", "mode", "size", "modifiedNs", "changedNs"},
                "plan targetIdentity",
            )
            if any(type(item) is not int or item < 0 for item in identity.values()):
                raise IntegrationPackError("plan targetIdentity values must be non-negative integers")
        changes = value["changes"]
        if not isinstance(changes, list) or len(changes) > 2:
            raise IntegrationPackError("plan changes must be a bounded array")
        normalized_changes: list[dict[str, str]] = []
        for change in changes:
            if not isinstance(change, dict):
                raise IntegrationPackError("plan change must be an object")
            _exact_keys(change, {"key", "before", "after"}, "plan change")
            normalized_changes.append(
                {
                    key: _string(change[key], f"plan change {key}", max_length=128)
                    for key in ("key", "before", "after")
                }
            )
        target_digest = value["targetDigest"]
        if target_digest is not None and (
            not isinstance(target_digest, str) or _SHA256.fullmatch(target_digest) is None
        ):
            raise IntegrationPackError("plan targetDigest must be a SHA-256 digest or null")
        for name in ("sourceDigest", "renderedDigest", "planDigest"):
            if not isinstance(value[name], str) or _SHA256.fullmatch(value[name]) is None:
                raise IntegrationPackError(f"plan {name} must be a SHA-256 digest")
        plan = cls(
            schema_version=value["schemaVersion"],
            validator_version=value["validatorVersion"],
            runtime_version=_string(
                value["runtimeVersion"], "plan runtime version", max_length=32
            ),
            runtime_platform=_string(
                value["runtimePlatform"], "plan runtime platform", max_length=32
            ),
            allow_experimental=value["allowExperimental"],
            pack_id=_identifier(value["packId"], "plan pack id"),
            kind=_string(value["kind"], "plan kind", max_length=16),
            source_path=_string(value["sourcePath"], "plan source path", max_length=4096),
            source_root=_string(value["sourceRoot"], "plan source root", max_length=4096),
            source_root_identity=_validated_root_identity(
                value["sourceRootIdentity"], "plan sourceRootIdentity"
            ),
            source_digest=value["sourceDigest"],
            project_root=_string(value["projectRoot"], "plan project root", max_length=4096),
            project_root_identity=_validated_root_identity(
                value["projectRootIdentity"], "plan projectRootIdentity"
            ),
            runtime_root=_string(
                value["runtimeRoot"], "plan runtime root", max_length=4096
            ),
            runtime_root_identity=_validated_root_identity(
                value["runtimeRootIdentity"], "plan runtimeRootIdentity"
            ),
            target_root=_string(value["targetRoot"], "plan target root", max_length=16),
            operation=_string(value["operation"], "plan operation", max_length=64),
            target_relative=_safe_relative(
                _string(value["target"], "plan target", max_length=256), "plan target"
            ),
            target_digest=target_digest,
            target_identity=dict(identity) if identity else None,
            rendered_digest=value["renderedDigest"],
            changes=tuple(normalized_changes),
            plan_digest=value["planDigest"],
        )
        plan.verify()
        return plan


def decode_plan(raw: bytes) -> PackPlan:
    if len(raw) > MAX_PLAN_BYTES:
        raise IntegrationPackError("integration-pack plan exceeds the safety cap")
    return PackPlan.from_dict(_decode_json_object(raw, "integration-pack plan"))


def load_plan(path: Path | str) -> PackPlan:
    """Securely component-walk and read one bounded, regular plan file."""

    candidate = Path(path)
    if not candidate.name or candidate.name in {".", ".."}:
        raise IntegrationPackError("integration-pack plan path must name a file")
    raw, _, _, _ = _read_bounded_regular(
        Path(candidate.name),
        root=candidate.parent,
        label="integration-pack plan",
        max_bytes=MAX_PLAN_BYTES,
    )
    return decode_plan(raw)


def _target_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": metadata.st_mode,
        "size": metadata.st_size,
        "modifiedNs": metadata.st_mtime_ns,
        "changedNs": metadata.st_ctime_ns,
    }


def _config_target_identity(config: object) -> dict[str, int]:
    identity = config.identity  # type: ignore[attr-defined]
    return {
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
        "size": identity.size,
        "modifiedNs": identity.modified_ns,
        "changedNs": identity.changed_ns,
    }


def _target_relative(pack: IntegrationPack) -> str:
    if pack.kind == "tracker":
        return PROJECT_CONFIG_RELATIVE_PATH.as_posix()
    output = str(pack.capability["outputFile"])
    return f".startup-factory/generated/{pack.kind}/{pack.pack_id}/{output}"


def _inspect_optional_target_at(
    root_descriptor: int, relative: str
) -> tuple[bytes, os.stat_result] | None:
    relative = _safe_relative(relative, "pack target")
    result = _read_bounded_regular_at(
        root_descriptor,
        relative,
        label="pack target",
        max_bytes=MAX_TARGET_BYTES,
        missing_ok=True,
    )
    if result is None:
        return None
    raw, metadata = result
    return raw, metadata


def _render_template(pack: IntegrationPack) -> bytes:
    value = {
        "schemaVersion": 1,
        "active": False,
        "generatedBy": "startup-factory-integration-pack-v1",
        "pack": {
            "id": pack.pack_id,
            "kind": pack.kind,
            "sourceDigest": pack.source_digest,
        },
        "configuration": pack.capability["template"],
    }
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"


def _desired_state(
    pack: IntegrationPack,
    project_descriptor: int,
    runtime_descriptor: int,
) -> tuple[
    str,
    bytes,
    tuple[Mapping[str, str], ...],
    bytes | None,
    Mapping[str, int] | None,
]:
    target_relative = _target_relative(pack)
    if pack.kind == "tracker":
        try:
            config = read_project_config_at(runtime_descriptor)
            updates = {
                "PRODUCT_MANAGEMENT_TOOL": str(pack.capability["adapter"]),
                "TEAM_MODE": "true" if pack.capability["teamMode"] else "false",
            }
            changes = plan_changes(config, updates)
            rendered = render_changes(config, changes)
        except IntegrationPackError:
            raise
        except (InstallerError, OSError) as exc:
            raise IntegrationPackError(f"cannot prepare tracker pack target: {exc}") from exc
        return (
            target_relative,
            rendered,
            tuple(change.as_dict() for change in changes),
            config.raw,
            _config_target_identity(config),
        )
    rendered = _render_template(pack)
    inspected = _inspect_optional_target_at(project_descriptor, target_relative)
    if inspected is None:
        return target_relative, rendered, (), None, None
    raw, metadata = inspected
    if raw != rendered:
        raise IntegrationPackError(
            "generated pack target already exists with different bytes"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o644:
        raise IntegrationPackError(
            "generated pack target must be a regular file with mode 0644"
        )
    return target_relative, rendered, (), raw, _target_identity(metadata)


def _coerce_pack(
    pack: IntegrationPack | Path | str,
    source_root: Path | str | None,
) -> IntegrationPack:
    if isinstance(pack, IntegrationPack):
        if source_root is not None:
            raise IntegrationPackError("source_root is redundant for an already loaded pack")
        return validate_pack(pack.source_path, root=pack.source_root)
    return validate_pack(Path(pack), root=Path(source_root) if source_root is not None else None)


def preview_pack(
    pack: IntegrationPack | Path | str,
    project_root: Path | str,
    *,
    runtime_root: Path | str | None = None,
    source_root: Path | str | None = None,
    allow_experimental: bool = False,
) -> PackPlan:
    """Return a digest-bound plan for one target under held verified roots."""

    loaded = _coerce_pack(pack, source_root)
    runtime_platform = _runtime_platform()
    _require_compatible(
        loaded,
        allow_experimental=allow_experimental,
        runtime_platform=runtime_platform,
    )
    runtime_candidate = Path(runtime_root) if runtime_root is not None else Path(project_root)
    with _held_root(Path(project_root), "project root") as (
        project,
        project_descriptor,
        project_identity,
    ), _held_root(runtime_candidate, "runtime root") as (
        runtime,
        runtime_descriptor,
        runtime_identity,
    ):
        target_relative, rendered, changes, existing, target_identity = _desired_state(
            loaded, project_descriptor, runtime_descriptor
        )
        operation = (
            "update-project-config"
            if loaded.kind == "tracker"
            else "create-inactive-template"
        )
        target_root = "runtime" if loaded.kind == "tracker" else "project"
        core = {
            "schemaVersion": PLAN_SCHEMA_VERSION,
            "validatorVersion": VALIDATOR_VERSION,
            "runtimeVersion": RUNTIME_VERSION,
            "runtimePlatform": runtime_platform,
            "allowExperimental": allow_experimental,
            "packId": loaded.pack_id,
            "kind": loaded.kind,
            "sourcePath": str(loaded.source_path),
            "sourceRoot": str(loaded.source_root),
            "sourceRootIdentity": dict(loaded.source_root_identity),
            "sourceDigest": loaded.source_digest,
            "projectRoot": str(project),
            "projectRootIdentity": project_identity,
            "runtimeRoot": str(runtime),
            "runtimeRootIdentity": runtime_identity,
            "targetRoot": target_root,
            "operation": operation,
            "target": target_relative,
            "targetDigest": _digest(existing) if existing is not None else None,
            "targetIdentity": dict(target_identity) if target_identity is not None else None,
            "renderedDigest": _digest(rendered),
            "changes": [dict(change) for change in changes],
        }
    return PackPlan(
        schema_version=PLAN_SCHEMA_VERSION,
        validator_version=VALIDATOR_VERSION,
        runtime_version=RUNTIME_VERSION,
        runtime_platform=runtime_platform,
        allow_experimental=allow_experimental,
        pack_id=loaded.pack_id,
        kind=loaded.kind,
        source_path=str(loaded.source_path),
        source_root=str(loaded.source_root),
        source_root_identity=dict(loaded.source_root_identity),
        source_digest=loaded.source_digest,
        project_root=str(project),
        project_root_identity=project_identity,
        runtime_root=str(runtime),
        runtime_root_identity=runtime_identity,
        target_root=target_root,
        operation=operation,
        target_relative=target_relative,
        target_digest=core["targetDigest"],
        target_identity=core["targetIdentity"],
        rendered_digest=core["renderedDigest"],
        changes=changes,
        plan_digest=_digest(_canonical(core)),
    )


preview = preview_pack


@dataclasses.dataclass(frozen=True)
class PackApplyReceipt:
    schema_version: int
    pack_id: str
    kind: str
    target: str
    plan_digest: str
    source_digest: str
    output_digest: str
    applied: bool
    idempotent: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "packId": self.pack_id,
            "kind": self.kind,
            "target": self.target,
            "planDigest": self.plan_digest,
            "sourceDigest": self.source_digest,
            "outputDigest": self.output_digest,
            "applied": self.applied,
            "idempotent": self.idempotent,
        }


def _open_or_create_directories(root_descriptor: int, parts: Sequence[str]) -> int:
    flags = _directory_flags("generated target")
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts:
            if not _ID.fullmatch(part) and part != ".startup-factory":
                raise IntegrationPackError("unsafe generated-directory component")
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise IntegrationPackError(
                        "cannot securely create generated target parent"
                    ) from exc
                try:
                    os.fsync(descriptor)
                except OSError as exc:
                    raise IntegrationPackError(
                        "cannot synchronize generated target parent"
                    ) from exc
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except OSError as exc:
                    raise IntegrationPackError(
                        "generated target parent must be a non-symlink directory"
                    ) from exc
            except OSError as exc:
                raise IntegrationPackError(
                    "generated target parent must be a non-symlink directory"
                ) from exc
            try:
                metadata = os.fstat(child)
                named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                os.close(child)
                raise IntegrationPackError(
                    "generated target parent changed while it was opened"
                ) from exc
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(named.st_mode)
                or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
            ):
                os.close(child)
                raise IntegrationPackError(
                    "generated target parent must be a non-symlink directory"
                )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _atomic_create_generated_at(
    project_descriptor: int, relative: str, content: bytes
) -> None:
    parts = PurePosixPath(_safe_relative(relative, "generated target")).parts
    parent_descriptor = _open_or_create_directories(
        project_descriptor, parts[:-1]
    )
    name = parts[-1]
    temp_name = f".{name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    descriptor = -1
    try:
        descriptor = os.open(
            temp_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        written = 0
        while written < len(content):
            count = os.write(descriptor, content[written:])
            if count <= 0:
                raise OSError(errno.EIO, "short write")
            written += count
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temp_name,
                name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise IntegrationPackError(
                "generated pack target changed before atomic creation"
            ) from exc
        os.unlink(temp_name, dir_fd=parent_descriptor)
        temp_name = ""
        os.fsync(parent_descriptor)
    except IntegrationPackError:
        raise
    except OSError as exc:
        raise IntegrationPackError(f"cannot create generated pack target: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temp_name:
            try:
                os.unlink(temp_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        os.close(parent_descriptor)


def apply_pack_plan(
    plan: PackPlan | Mapping[str, Any],
    *,
    project_root: Path | str,
    runtime_root: Path | str | None = None,
) -> PackApplyReceipt:
    """Revalidate and apply one exact plan, or recognize its exact prior output."""

    bound = PackPlan.from_dict(plan.as_dict() if isinstance(plan, PackPlan) else plan)
    runtime_candidate = Path(runtime_root) if runtime_root is not None else Path(project_root)
    with _held_root(Path(project_root), "project root") as (
        project,
        project_descriptor,
        project_identity,
    ), _held_root(runtime_candidate, "runtime root") as (
        runtime,
        runtime_descriptor,
        runtime_identity,
    ):
        if str(project) != bound.project_root or project_identity != dict(
            bound.project_root_identity
        ):
            raise IntegrationPackError(
                "plan project root identity does not match the requested project"
            )
        if str(runtime) != bound.runtime_root or runtime_identity != dict(
            bound.runtime_root_identity
        ):
            raise IntegrationPackError(
                "plan runtime root identity does not match the requested runtime"
            )

        pack = validate_pack(Path(bound.source_path), root=Path(bound.source_root))
        if (
            pack.pack_id != bound.pack_id
            or pack.kind != bound.kind
            or pack.source_digest != bound.source_digest
            or dict(pack.source_root_identity) != dict(bound.source_root_identity)
            or _target_relative(pack) != bound.target_relative
        ):
            raise IntegrationPackError("pack source or target changed after preview")
        _require_compatible(pack, allow_experimental=bound.allow_experimental)
        expected_operation = (
            "update-project-config"
            if pack.kind == "tracker"
            else "create-inactive-template"
        )
        expected_target_root = "runtime" if pack.kind == "tracker" else "project"
        if (
            bound.operation != expected_operation
            or bound.target_root != expected_target_root
        ):
            raise IntegrationPackError("plan operation or target root does not match pack kind")

        target_relative, rendered, changes, current, target_identity = _desired_state(
            pack, project_descriptor, runtime_descriptor
        )
        if (
            target_relative != bound.target_relative
            or _digest(rendered) != bound.rendered_digest
        ):
            raise IntegrationPackError("rendered pack output changed after preview")
        if current is not None and _digest(current) == bound.rendered_digest and current == rendered:
            if target_identity is None:
                raise IntegrationPackError(
                    "rendered pack target has no verifiable identity"
                )
            preview_was_idempotent = bound.target_digest == bound.rendered_digest
            if preview_was_idempotent:
                if (
                    bound.target_identity is None
                    or dict(target_identity) != dict(bound.target_identity)
                ):
                    raise IntegrationPackError(
                        "idempotent pack target identity changed after preview"
                    )
            elif pack.kind == "tracker":
                expected_mode = (bound.target_identity or {}).get("mode")
                if type(expected_mode) is not int or target_identity["mode"] != expected_mode:
                    raise IntegrationPackError(
                        "idempotent tracker target mode changed after preview"
                    )
            elif (
                not stat.S_ISREG(target_identity["mode"])
                or stat.S_IMODE(target_identity["mode"]) != 0o644
            ):
                raise IntegrationPackError(
                    "idempotent generated target must retain regular mode 0644"
                )
            return PackApplyReceipt(
                schema_version=1,
                pack_id=pack.pack_id,
                kind=pack.kind,
                target=target_relative,
                plan_digest=bound.plan_digest,
                source_digest=pack.source_digest,
                output_digest=bound.rendered_digest,
                applied=False,
                idempotent=True,
            )
        if current is None:
            if bound.target_digest is not None or bound.target_identity is not None:
                raise IntegrationPackError("pack target disappeared or changed after preview")
        elif (
            _digest(current) != bound.target_digest
            or target_identity is None
            or dict(target_identity) != dict(bound.target_identity or {})
        ):
            raise IntegrationPackError("pack target changed after preview")
        if tuple(changes) != tuple(bound.changes):
            raise IntegrationPackError("planned project changes changed after preview")

        if pack.kind == "tracker":
            try:
                config = read_project_config_at(runtime_descriptor)
                updates = {
                    "PRODUCT_MANAGEMENT_TOOL": str(pack.capability["adapter"]),
                    "TEAM_MODE": "true" if pack.capability["teamMode"] else "false",
                }
                config_changes = plan_changes(config, updates)
                if tuple(change.as_dict() for change in config_changes) != tuple(
                    bound.changes
                ):
                    raise IntegrationPackError(
                        "project configuration changed before apply"
                    )
                if (
                    bound.target_digest is None
                    or bound.target_identity is None
                    or _digest(config.raw) != bound.target_digest
                    or _config_target_identity(config) != dict(bound.target_identity)
                    or _digest(render_changes(config, config_changes))
                    != bound.rendered_digest
                ):
                    raise IntegrationPackError(
                        "project configuration changed before atomic apply"
                    )
                apply_changes_at(
                    config,
                    config_changes,
                    runtime_descriptor,
                    display_root=runtime,
                )
            except IntegrationPackError:
                raise
            except (InstallerError, OSError) as exc:
                raise IntegrationPackError(
                    f"cannot apply tracker pack target: {exc}"
                ) from exc
        else:
            _atomic_create_generated_at(project_descriptor, target_relative, rendered)

        if pack.kind == "tracker":
            try:
                final_raw = read_project_config_at(runtime_descriptor).raw
            except (InstallerError, OSError) as exc:
                raise IntegrationPackError(
                    f"cannot verify tracker pack target: {exc}"
                ) from exc
        else:
            final = _inspect_optional_target_at(project_descriptor, target_relative)
            final_raw = None if final is None else final[0]
        if (
            final_raw is None
            or final_raw != rendered
            or _digest(final_raw) != bound.rendered_digest
        ):
            raise IntegrationPackError(
                "pack target does not match the planned output after apply"
            )
        return PackApplyReceipt(
            schema_version=1,
            pack_id=pack.pack_id,
            kind=pack.kind,
            target=target_relative,
            plan_digest=bound.plan_digest,
            source_digest=pack.source_digest,
            output_digest=bound.rendered_digest,
            applied=True,
            idempotent=False,
        )


apply = apply_pack_plan


@dataclasses.dataclass(frozen=True)
class PackDoctorReport:
    schema_version: int
    pack_id: str
    kind: str
    source_digest: str
    compatibility: Mapping[str, Any]
    configured: Mapping[str, Any]
    detected: Mapping[str, Any]
    proved: Mapping[str, Any]
    credentials: Mapping[str, Any]
    operator_actions: tuple[str, ...]
    overall: str
    local_ready: bool
    ready: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "packId": self.pack_id,
            "kind": self.kind,
            "sourceDigest": self.source_digest,
            "compatibility": dict(self.compatibility),
            "configured": dict(self.configured),
            "detected": dict(self.detected),
            "proved": dict(self.proved),
            "credentials": {
                name: list(value) if isinstance(value, tuple) else value
                for name, value in self.credentials.items()
            },
            "operatorActions": list(self.operator_actions),
            "overall": self.overall,
            "localReady": self.local_ready,
            "ready": self.ready,
        }


def _configured_status(
    pack: IntegrationPack, project_descriptor: int, runtime_descriptor: int
) -> tuple[bool, str]:
    if pack.kind == "tracker":
        try:
            config = read_project_config_at(runtime_descriptor)
        except (InstallerError, OSError):
            return False, "project configuration is unavailable or invalid"
        expected_team = "true" if pack.capability["teamMode"] else "false"
        configured = (
            config.value("PRODUCT_MANAGEMENT_TOOL") == pack.capability["adapter"]
            and config.value("TEAM_MODE") == expected_team
        )
        return configured, (
            "exact tracker settings are configured"
            if configured
            else "tracker settings do not match this pack"
        )
    target = _inspect_optional_target_at(project_descriptor, _target_relative(pack))
    expected = _render_template(pack)
    configured = target is not None and target[0] == expected
    return configured, (
        "exact inactive template is configured"
        if configured
        else "exact inactive template is not configured"
    )


def _optional_project_path_kind_at(root_descriptor: int, relative: str) -> str | None:
    """Inspect one held-root-relative shape without following any symbolic link."""

    relative = _safe_relative(relative, "detected project path")
    opened = _open_relative_parent(
        root_descriptor, relative, "detected project path", missing_ok=True
    )
    if opened is None:
        return None
    parent_descriptor, name = opened
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise IntegrationPackError(
            f"cannot inspect detected project path: {exc}"
        ) from exc
    finally:
        os.close(parent_descriptor)
    if stat.S_ISLNK(metadata.st_mode):
        raise IntegrationPackError(
            "detected project path must not traverse symbolic links"
        )
    if stat.S_ISREG(metadata.st_mode):
        return "file"
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    return "other"


def _detected_status(
    pack: IntegrationPack, project_descriptor: int, runtime_descriptor: int
) -> tuple[bool, str]:
    if pack.kind == "tracker":
        detected = (
            _optional_project_path_kind_at(
                runtime_descriptor, f"adapters/{pack.capability['adapter']}.md"
            )
            == "file"
        )
        return detected, "tracker adapter file detected" if detected else "tracker adapter not detected"
    if pack.kind == "ci":
        detected = (
            _optional_project_path_kind_at(project_descriptor, ".github/workflows")
            == "directory"
        )
        return detected, "hosted CI workflow directory detected" if detected else "hosted CI not detected"
    target = pack.capability["target"]
    candidates = (
        ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
        if target == "docker-compose"
        else ("k8s", "kubernetes")
    )
    detected = any(
        _optional_project_path_kind_at(project_descriptor, name)
        in {"file", "directory"}
        for name in candidates
    )
    return detected, f"{target} project shape detected" if detected else f"{target} project shape not detected"


def _proved_status(
    pack: IntegrationPack, evidence: Mapping[str, Any] | None
) -> dict[str, Any]:
    del pack
    if evidence is not None:
        raise IntegrationPackError(
            "local doctor cannot authenticate protected integration evidence"
        )
    return {
        "status": "unknown",
        "message": "proof requires an authenticated external integration adapter",
    }


def doctor_pack(
    pack: IntegrationPack | Path | str,
    project_root: Path | str,
    *,
    runtime_root: Path | str | None = None,
    source_root: Path | str | None = None,
    allow_experimental: bool = False,
    environment: Mapping[str, str] | None = None,
    protected_evidence: Mapping[str, Any] | None = None,
) -> PackDoctorReport:
    """Report readiness levels without reading or returning credential values."""

    loaded = _coerce_pack(pack, source_root)
    compatibility = _compatibility_report(
        loaded, allow_experimental=allow_experimental
    )
    runtime_candidate = Path(runtime_root) if runtime_root is not None else Path(project_root)
    names = tuple(loaded.credentials)
    visible = environment if environment is not None else os.environ
    present = tuple(name for name in names if name in visible)
    missing = tuple(name for name in names if name not in visible)
    with _held_root(Path(project_root), "project root") as (
        _,
        project_descriptor,
        __,
    ), _held_root(runtime_candidate, "runtime root") as (
        _,
        runtime_descriptor,
        __,
    ):
        configured, configured_message = _configured_status(
            loaded, project_descriptor, runtime_descriptor
        )
        detected, detected_message = _detected_status(
            loaded, project_descriptor, runtime_descriptor
        )
    actions: list[str] = []
    if compatibility["status"] != "compatible":
        actions.append(
            "Select a pack compatible with this runtime and platform; experimental packs require explicit opt-in."
        )
    if not configured:
        actions.append(
            "Preview this pack, review the exact target and digest, then apply the saved plan."
        )
    if not detected:
        actions.append(
            "Install or configure the local integration prerequisite described by this pack."
        )
    if loaded.credential_policy == "adapter-managed":
        actions.append(
            "Choose and authenticate an adapter access mode outside repository configuration."
        )
    elif missing:
        actions.append(
            "Provide the listed credential environment names outside repository configuration; never store their values in the pack or project config."
        )
    actions.append(
        "Run the authenticated external integration adapter to create protected proof; local configuration never counts as proof."
    )
    credential_ready = loaded.credential_policy in {"none", "adapter-managed"} or not missing
    local_ready = (
        compatibility["status"] == "compatible"
        and configured
        and detected
        and credential_ready
    )
    proved = _proved_status(loaded, protected_evidence)
    ready = local_ready and proved["status"] == "proved"
    overall = "green" if ready else ("yellow" if local_ready else "red")
    return PackDoctorReport(
        schema_version=1,
        pack_id=loaded.pack_id,
        kind=loaded.kind,
        source_digest=loaded.source_digest,
        compatibility=compatibility,
        configured={
            "status": "configured" if configured else "missing",
            "message": configured_message,
        },
        detected={
            "status": "detected" if detected else "unknown",
            "message": detected_message,
        },
        proved=proved,
        credentials={
            "policy": loaded.credential_policy,
            "status": (
                "not-required"
                if loaded.credential_policy == "none"
                else "conditional"
                if loaded.credential_policy == "adapter-managed"
                else ("ready" if not missing else "missing")
            ),
            "message": (
                "this integration pack requires no external credentials"
                if loaded.credential_policy == "none"
                else "credential requirements are conditional on the adapter access mode; this pack does not select or authenticate that mode"
                if loaded.credential_policy == "adapter-managed"
                else "required environment names are present"
                if not missing
                else "one or more required environment names are absent"
            ),
            "required": names,
            "present": present,
            "missing": missing,
        },
        operator_actions=tuple(actions),
        overall=overall,
        local_ready=local_ready,
        ready=ready,
    )


doctor = doctor_pack


__all__ = [
    "RUNTIME_VERSION",
    "IntegrationPack",
    "IntegrationPackError",
    "PackApplyReceipt",
    "PackDoctorReport",
    "PackPlan",
    "apply",
    "apply_pack_plan",
    "decode_plan",
    "discover_packs",
    "doctor",
    "doctor_pack",
    "list_packs",
    "load_plan",
    "preview",
    "preview_pack",
    "validate_pack",
]
