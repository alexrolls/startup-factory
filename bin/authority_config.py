#!/usr/bin/env python3
"""Resolve authority-bearing settings from protected Startup Factory config.

Caller environment values are compatibility assertions only.  They may repeat
the configured value exactly, but they can never select lifecycle authority,
the tracker adapter, or the human-work exclusion policy.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(SKILL_DIR / "src"))

from startup_factory_cli.config_values import (  # noqa: E402
    ConfigValueError,
    parse_config_bytes,
    value_for,
)


class AuthorityConfigError(RuntimeError):
    """Raised when authority configuration is absent, ambiguous, or overridden."""


_ADAPTER_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")


def _read_regular(path: Path, label: str, limit: int = 1024 * 1024) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise AuthorityConfigError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise AuthorityConfigError(f"{label} must be a non-symlink regular file")
    if before.st_size <= 0 or before.st_size > limit:
        raise AuthorityConfigError(f"{label} must contain 1..{limit} bytes")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (before.st_dev, before.st_ino):
            raise AuthorityConfigError(f"{label} changed while being opened")
        chunks: list[bytes] = []
        size = 0
        while size <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > limit:
            raise AuthorityConfigError(f"{label} exceeds {limit} bytes")
        after = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise AuthorityConfigError(f"{label} changed while being read")
        return b"".join(chunks)
    except OSError as exc:
        raise AuthorityConfigError(f"cannot securely read {label}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_assignment_bytes(
    raw: bytes, key: str, label: str
) -> str | None:
    try:
        return value_for(parse_config_bytes(raw, label), key)
    except ConfigValueError as exc:
        raise AuthorityConfigError(f"{label}: {exc}") from exc


def parse_assignment(path: Path, key: str, label: str) -> str | None:
    return parse_assignment_bytes(_read_regular(path, label), key, label)


def _strict_json_object(raw: bytes, label: str) -> dict:
    def pairs(items: list[tuple[str, object]]) -> dict:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise AuthorityConfigError(f"{label} repeats JSON key {key}")
            value[key] = item
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except UnicodeDecodeError as exc:
        raise AuthorityConfigError(f"{label} must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise AuthorityConfigError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AuthorityConfigError(f"{label} must be a JSON object")
    return value


def _canonical_labels(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AuthorityConfigError(f"{label} must be a JSON array")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or item != item.strip()
            or len(item) > 255
            or any(ord(char) < 32 or ord(char) == 127 for char in item)
        ):
            raise AuthorityConfigError(
                f"{label} must contain canonical non-empty label names up to 255 characters"
            )
        folded = item.casefold()
        if folded in seen:
            raise AuthorityConfigError(f"{label} contains a case-insensitive duplicate")
        seen.add(folded)
        result.append(item)
    return tuple(result)


def configured_ignored_labels(
    automation_config: Path,
    ambient: str | None = None,
) -> tuple[str, ...]:
    config = _strict_json_object(
        _read_regular(automation_config, "automation config"), "automation config"
    )
    if "ignoredTaskLabels" not in config:
        raise AuthorityConfigError(
            "automation config must explicitly declare ignoredTaskLabels"
        )
    return resolve_ignored_labels(config["ignoredTaskLabels"], ambient)


def resolve_ignored_labels(
    configured_value: object,
    ambient: str | None = None,
) -> tuple[str, ...]:
    configured = _canonical_labels(
        configured_value, "configured ignoredTaskLabels"
    )
    if ambient is not None:
        try:
            supplied = json.loads(ambient)
        except json.JSONDecodeError as exc:
            raise AuthorityConfigError(
                "STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON is invalid JSON"
            ) from exc
        if _canonical_labels(
            supplied, "STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON"
        ) != configured:
            raise AuthorityConfigError(
                "STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON must exactly repeat configured ignoredTaskLabels"
            )
    return configured


def configured_tracker_adapter(
    project_management_config: Path,
    ambient: str | None = None,
) -> str:
    value = parse_assignment(
        project_management_config,
        "PRODUCT_MANAGEMENT_TOOL",
        "project-management config",
    )
    return resolve_tracker_adapter(value, ambient)


def resolve_tracker_adapter(configured_value: object, ambient: str | None = None) -> str:
    configured = configured_value
    if not isinstance(configured, str) or not _ADAPTER_RE.fullmatch(configured):
        raise AuthorityConfigError(
            "project-management config must declare one valid PRODUCT_MANAGEMENT_TOOL"
        )
    if ambient is not None and ambient != configured:
        raise AuthorityConfigError(
            "TRACKER_ADAPTER must exactly repeat configured PRODUCT_MANAGEMENT_TOOL"
        )
    return configured


def configured_lifecycle_root(
    team_config: Path,
    repository: Path,
    skill_dir: Path,
    ambient: str | None = None,
    *,
    required: bool,
) -> Path | None:
    return resolve_lifecycle_root(
        parse_assignment(team_config, "BROKER_LIFECYCLE_ROOT", "team config"),
        repository,
        skill_dir,
        ambient,
        required=required,
    )


def resolve_lifecycle_root(
    configured_value: object,
    repository: Path,
    skill_dir: Path,
    ambient: str | None = None,
    *,
    required: bool,
) -> Path | None:
    configured = configured_value
    if configured is None:
        if ambient is not None:
            raise AuthorityConfigError(
                "STARTUP_FACTORY_LIFECYCLE_STATE_ROOT cannot replace an absent "
                "BROKER_LIFECYCLE_ROOT; set BROKER_LIFECYCLE_ROOT to the same "
                "canonical path in config/team.config.md before enabling authority-bearing operations"
            )
        if required:
            raise AuthorityConfigError(
                "BROKER_LIFECYCLE_ROOT is required for this authority-bearing operation"
            )
        return None
    if not isinstance(configured, str) or not configured:
        raise AuthorityConfigError("BROKER_LIFECYCLE_ROOT must be a non-empty path")
    root = Path(configured)
    if (
        not root.is_absolute()
        or configured != os.path.normpath(configured)
        or str(root) != configured
    ):
        raise AuthorityConfigError(
            "BROKER_LIFECYCLE_ROOT must be an absolute normalized path"
        )
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise AuthorityConfigError(
            f"BROKER_LIFECYCLE_ROOT is unavailable: {exc}"
        ) from exc
    if resolved != root:
        raise AuthorityConfigError(
            "BROKER_LIFECYCLE_ROOT must already be its canonical non-symlink path"
        )
    for shared in (Path("/tmp"), Path("/private/tmp")):
        try:
            root.relative_to(shared)
        except ValueError:
            pass
        else:
            raise AuthorityConfigError(
                "BROKER_LIFECYCLE_ROOT must not live below a shared temporary directory"
            )
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise AuthorityConfigError(
                f"cannot inspect lifecycle path component {current}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AuthorityConfigError(
                f"lifecycle path components must be non-symlink directories: {current}"
            )
        if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(
            metadata.st_mode
        ) & 0o022:
            raise AuthorityConfigError(
                "lifecycle path components must be executor/root-owned and not "
                f"group/world-writable: {current}"
            )
    if stat.S_IMODE(root.lstat().st_mode) != 0o700:
        raise AuthorityConfigError("BROKER_LIFECYCLE_ROOT must have mode 0700")
    try:
        repository = repository.resolve(strict=True)
        skill_dir = skill_dir.resolve(strict=True)
    except OSError as exc:
        raise AuthorityConfigError(
            f"cannot resolve repository/skill trust boundary: {exc}"
        ) from exc
    for boundary, label in ((repository, "repository"), (skill_dir, "installed skill")):
        try:
            common = Path(os.path.commonpath((str(root), str(boundary))))
        except ValueError:
            continue
        if common in {root, boundary}:
            raise AuthorityConfigError(
                f"BROKER_LIFECYCLE_ROOT must be disjoint from the {label}"
            )
    if ambient is not None and ambient != str(resolved):
        raise AuthorityConfigError(
            "STARTUP_FACTORY_LIFECYCLE_STATE_ROOT must exactly repeat canonical BROKER_LIFECYCLE_ROOT"
        )
    return resolved


def resolve_policy_source(
    default_config: Path,
    repository: Path,
    skill_dir: Path,
    ambient: str | None = None,
    *,
    label: str,
) -> Path:
    """Authenticate the one config file selected for an authority-bearing run.

    The exact bundled default remains valid.  A supervisor may instead select
    an external file, but that file must be canonical, protected, outside both
    the repository and installed skill, and safe to re-open without a fallback.
    """
    if label not in {"automation config", "project-management config"}:
        raise AuthorityConfigError("unsupported policy source label")
    try:
        default_resolved = default_config.resolve(strict=True)
        repository = repository.resolve(strict=True)
        skill_dir = skill_dir.resolve(strict=True)
    except OSError as exc:
        raise AuthorityConfigError(
            f"cannot resolve {label} trust boundary: {exc}"
        ) from exc
    selected = Path(ambient) if ambient is not None else default_config
    selected_text = str(selected)
    if (
        not selected.is_absolute()
        or selected_text != os.path.normpath(selected_text)
    ):
        raise AuthorityConfigError(f"{label} must be an absolute normalized path")
    try:
        resolved = selected.resolve(strict=True)
    except OSError as exc:
        raise AuthorityConfigError(f"{label} is unavailable: {exc}") from exc
    for shared in (Path("/tmp"), Path("/private/tmp")):
        for candidate in (selected, resolved):
            try:
                candidate.relative_to(shared)
            except ValueError:
                continue
            raise AuthorityConfigError(
                f"{label} must not live below a shared temporary directory"
            )
    if resolved != selected:
        raise AuthorityConfigError(
            f"{label} must already be its canonical non-symlink path"
        )
    current = Path(resolved.anchor)
    for part in resolved.parent.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise AuthorityConfigError(
                f"cannot inspect {label} parent {current}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AuthorityConfigError(
                f"{label} parent chain must contain non-symlink directories"
            )
        if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(
            metadata.st_mode
        ) & 0o022:
            raise AuthorityConfigError(
                f"{label} parent chain must be executor/root-owned and not group/world-writable: {current}"
            )
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise AuthorityConfigError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AuthorityConfigError(f"{label} must be a non-symlink regular file")
    if metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
        raise AuthorityConfigError(f"{label} must contain 1..1048576 bytes")
    if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(
        metadata.st_mode
    ) & 0o022:
        raise AuthorityConfigError(
            f"{label} must be executor/root-owned and not group/world-writable"
        )
    if resolved != default_resolved:
        for boundary, boundary_label in (
            (repository, "repository"),
            (skill_dir, "installed skill"),
        ):
            try:
                common = Path(os.path.commonpath((str(resolved), str(boundary))))
            except ValueError:
                continue
            if common in {resolved, boundary}:
                raise AuthorityConfigError(
                    f"external {label} must be disjoint from the {boundary_label}"
                )
    return resolved


def validated_runtime_path(value: str, repository: Path, skill_dir: Path) -> str:
    """Canonicalize an agent-immutable runtime PATH without trusting search order.

    A directory owned by the invoking uid is not an authority boundary, even
    when its mode is 0700: an unprivileged process under that uid can replace a
    command after validation.  Generic PATH entries therefore require a fully
    root-owned, non-writable canonical chain.  Individually pinned executables
    use a separate identity-capture/recheck contract.
    """
    entries = value.split(":") if isinstance(value, str) else []
    try:
        boundaries = (repository.resolve(strict=True), skill_dir.resolve(strict=True))
    except OSError as exc:
        raise AuthorityConfigError(
            f"cannot resolve repository/skill PATH boundaries: {exc}"
        ) from exc
    def accepted(candidate: Path) -> Path | None:
        current = Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current /= part
            try:
                metadata = current.lstat()
            except OSError:
                return None
            if stat.S_ISLNK(metadata.st_mode):
                if metadata.st_uid != 0:
                    return None
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                return None
            mode = stat.S_IMODE(metadata.st_mode)
            if metadata.st_uid != 0 or mode & 0o022:
                return None
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            return None
        if not resolved.is_dir():
            return None
        # Validate the canonical target chain too. A protected symlink name is
        # not enough if its target traverses a writable delegated directory.
        current = Path(resolved.anchor)
        for part in resolved.parts[1:]:
            current /= part
            try:
                metadata = current.lstat()
            except OSError:
                return None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                return None
            mode = stat.S_IMODE(metadata.st_mode)
            if metadata.st_uid != 0 or mode & 0o022:
                return None
        for shared in (Path("/tmp"), Path("/private/tmp")):
            try:
                resolved.relative_to(shared)
            except ValueError:
                pass
            else:
                return None
        for boundary in boundaries:
            try:
                common = Path(os.path.commonpath((str(resolved), str(boundary))))
            except ValueError:
                continue
            if common in {resolved, boundary}:
                return None
        return resolved

    canonical: list[Path] = []
    for raw in entries:
        if not raw or not Path(raw).is_absolute():
            continue
        resolved = accepted(Path(raw))
        if resolved is None:
            continue
        if resolved not in canonical:
            canonical.append(resolved)
    if not canonical:
        raise AuthorityConfigError(
            "runtime PATH has no root-owned, agent-immutable directory entries"
        )
    return ":".join(str(path) for path in canonical)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    lifecycle = subparsers.add_parser("lifecycle-root")
    lifecycle.add_argument("--team-config", required=True, type=Path)
    lifecycle.add_argument("--repo", required=True, type=Path)
    lifecycle.add_argument("--skill", required=True, type=Path)
    lifecycle.add_argument("--ambient")
    lifecycle.add_argument("--required", action="store_true")

    adapter = subparsers.add_parser("tracker-adapter")
    adapter.add_argument("--pm-config", required=True, type=Path)
    adapter.add_argument("--ambient")

    labels = subparsers.add_parser("ignored-labels")
    labels.add_argument("--automation-config", required=True, type=Path)
    labels.add_argument("--ambient")

    policy_source = subparsers.add_parser("policy-source")
    policy_source.add_argument("--default-config", required=True, type=Path)
    policy_source.add_argument("--repo", required=True, type=Path)
    policy_source.add_argument("--skill", required=True, type=Path)
    policy_source.add_argument("--ambient")
    policy_source.add_argument(
        "--label",
        required=True,
        choices=("automation config", "project-management config"),
    )

    runtime_path = subparsers.add_parser("runtime-path")
    runtime_path.add_argument("--value", required=True)
    runtime_path.add_argument("--repo", required=True, type=Path)
    runtime_path.add_argument("--skill", required=True, type=Path)

    args = parser.parse_args()
    try:
        if args.command == "lifecycle-root":
            value = configured_lifecycle_root(
                args.team_config,
                args.repo,
                args.skill,
                args.ambient,
                required=args.required,
            )
            print("" if value is None else value)
        elif args.command == "tracker-adapter":
            print(configured_tracker_adapter(args.pm_config, args.ambient))
        elif args.command == "ignored-labels":
            value = configured_ignored_labels(args.automation_config, args.ambient)
            print(json.dumps(list(value), separators=(",", ":")))
        elif args.command == "policy-source":
            print(
                resolve_policy_source(
                    args.default_config,
                    args.repo,
                    args.skill,
                    args.ambient,
                    label=args.label,
                )
            )
        else:
            print(validated_runtime_path(args.value, args.repo, args.skill))
    except AuthorityConfigError as exc:
        parser.exit(1, f"authority-config: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
