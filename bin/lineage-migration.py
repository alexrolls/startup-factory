#!/usr/bin/env python3
"""Broker-only, one-shot migration of exact pre-claimLineage executions."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from broker_evidence import authority as publication_authority
from broker_evidence import verify_delivery
from outbox_capability import (
    CapabilityError,
    authority_lock as capability_authority_lock,
    verify_entry,
    verify_published_entry,
)


DOMAIN = b"lineageMigration/v1\0"
CONTROL_ID = re.compile(r"control-[0-9a-f]{32}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
DELIVERY = re.compile(r"delivery-[0-9a-f]{32}")
ROLE = re.compile(r"[a-z0-9][a-z0-9-]{1,79}")
MAX_MIGRATION_REQUESTS_PER_PASS = 32
MAX_MIGRATION_REQUEST_BYTES = 65536
MAX_VERDICT_COMMENTS = 4096
MAX_VERDICT_ENTRIES = 4096
MAX_VERDICT_ENTRY_BYTES = 65536
LEGACY_EXECUTION_FIELDS = {
    "schemaVersion", "featureId", "taskId", "taskKey", "attempt", "role",
    "branch", "worktree", "packetPath", "packetJsonPath", "reportPath",
    "modelProfile", "updatedAt",
}
LEGACY_EXECUTION_OPTIONAL_FIELDS = {"deliveryProfile"}
CLAIM_FIELDS = {
    "schemaVersion", "team", "featureId", "taskId", "taskKey", "attempt",
    "role", "claimId", "targetStatus", "claimDigest", "recordedAt",
}
LINEAGE_FIELDS = {
    "schemaVersion", "team", "featureId", "taskId", "taskKey", "targetStatus",
    "claimAttempt", "role", "claimId", "claimDigest",
}
REQUEST_FIELDS = {
    "schemaVersion", "id", "team", "featureId", "taskId", "taskKey", "actor",
    "authorizationTaskId", "authorizationTaskRevision", "authorizationTaskStatus",
    "contractRegistrySha256", "contractEntrySha256",
    "marker", "createdAt", "expiresAt", "observedLifecycleCreatedAt",
    "observedTaskRevision", "observedTaskStatus", "observedExecutionSha256",
    "observedClaimSha256", "branch", "worktree", "head", "packetPath",
    "packetSha256", "packetJsonPath", "packetJsonSha256", "reportPath",
    "reportSha256",
    "controlBodySha256", "producerCapability",
}
VERDICT_FAMILIES = (
    ("product", {"product-approval", "product-pushback"}, "product-approval", "PRODUCT_MANAGER"),
    ("principal", {"design-approved", "design-pushback"}, "design-approved", "PRINCIPAL_ARCHITECT"),
    (
        "sceptical",
        {"sceptical-design-approved", "sceptical-design-pushback"},
        "sceptical-design-approved",
        "SCEPTICAL_ARCHITECT",
    ),
)
SAFE_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class MigrationError(RuntimeError):
    pass


class RejectedMigration(MigrationError):
    """A pending request that is safe to quarantine without losing recovery."""


class ClaimAuthorityError(MigrationError):
    """The local claim lacks its exact fresh tracker-side authority receipt."""


class DirectoryRef:
    """One retained, no-follow directory inode and its expected pathname."""

    def __init__(self, path: Path, descriptor: int, label: str) -> None:
        self.path = path
        self.descriptor = descriptor
        self.label = label

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class ExactStateSnapshot:
    """Retained mutable workspace evidence, revalidated through commit."""

    def __init__(
        self,
        tasks: dict[str, Any],
        bound_directories: list[DirectoryRef],
        owned_directories: list[DirectoryRef],
    ) -> None:
        self.tasks = tasks
        self.tasks_raw = canonical(tasks)
        self.bound_directories = list(bound_directories)
        self.owned_directories = list(owned_directories)
        self.entries: list[
            tuple[DirectoryRef, str, str, int, bytes, os.stat_result]
        ] = []
        self.validators: list[Callable[[], None]] = []

    def retain(
        self,
        directory: DirectoryRef,
        name: str,
        label: str,
        maximum: int,
        raw: bytes,
        info: os.stat_result,
    ) -> None:
        self.entries.append((directory, name, label, maximum, raw, info))

    def adopt(self, *directories: DirectoryRef) -> None:
        for directory in directories:
            if directory not in self.bound_directories:
                self.bound_directories.append(directory)
            if directory not in self.owned_directories:
                self.owned_directories.append(directory)

    def retain_validator(self, validator: Callable[[], None]) -> None:
        self.validators.append(validator)

    def validate(self) -> None:
        if canonical(self.tasks) != self.tasks_raw:
            raise MigrationError("fresh task snapshot changed before migration commit")
        for directory in self.bound_directories:
            assert_directory_binding(directory)
        for directory, name, label, maximum, expected, expected_info in self.entries:
            current, current_info = regular_bytes_at(
                directory, name, label, maximum
            )
            if (
                current != expected
                or (current_info.st_dev, current_info.st_ino)
                != (expected_info.st_dev, expected_info.st_ino)
                or current_info.st_size != expected_info.st_size
                or current_info.st_mtime_ns != expected_info.st_mtime_ns
                or current_info.st_ctime_ns != expected_info.st_ctime_ns
            ):
                raise MigrationError(f"{label} changed after exact state snapshot")
        for validator in self.validators:
            validator()
        for directory in self.bound_directories:
            assert_directory_binding(directory)

    def close(self) -> None:
        for directory in reversed(self.owned_directories):
            directory.close()
        self.owned_directories.clear()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def task_key(task_id: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", task_id).strip("-").lower()[:32] or "task"
    return f"{slug}-{hashlib.sha256(task_id.encode()).hexdigest()[:10]}"


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise MigrationError(f"JSON object repeats field {key}")
        result[key] = value
    return result


def decode(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as exc:
        raise MigrationError(f"{label} is not canonical JSON data: {exc}") from exc
    if not isinstance(value, dict):
        raise MigrationError(f"{label} must be a JSON object")
    return value


def regular_bytes(path: Path, label: str, maximum: int = 2 * 1024 * 1024) -> bytes:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise MigrationError(f"{label} must be a non-symlink regular file")
        if not 0 < before.st_size <= maximum:
            raise MigrationError(f"{label} has an invalid bounded size")
        descriptor = os.open(path, SAFE_READ_FLAGS)
        try:
            opened = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise MigrationError(f"{label} changed identity while being read")
            raw = b""
            while len(raw) <= maximum:
                block = os.read(descriptor, maximum + 1 - len(raw))
                if not block:
                    break
                raw += block
            after = os.fstat(descriptor)
            if (
                len(raw) > maximum
                or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
            ):
                raise MigrationError(f"{label} changed while being read")
            return raw
        finally:
            os.close(descriptor)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise MigrationError(
                f"{label} must be a non-symlink regular file"
            ) from exc
        raise MigrationError(f"cannot read {label}: {exc}") from exc


def open_bound_bytes(
    path: Path, label: str, maximum: int
) -> tuple[int, bytes, os.stat_result]:
    """Read one regular file while retaining its authenticated descriptor."""

    descriptor = -1
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise MigrationError(f"{label} must be a non-symlink regular file")
        if not 0 < before.st_size <= maximum:
            raise MigrationError(f"{label} has an invalid bounded size")
        descriptor = os.open(path, SAFE_READ_FLAGS)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise MigrationError(f"{label} changed identity while being read")
        raw = b""
        while len(raw) <= maximum:
            block = os.read(descriptor, maximum + 1 - len(raw))
            if not block:
                break
            raw += block
        after = os.fstat(descriptor)
        if (
            len(raw) > maximum
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise MigrationError(f"{label} changed while being read")
        return descriptor, raw, opened
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise MigrationError(f"cannot read {label}: {exc}") from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def canonical_directory(raw: str, label: str) -> Path:
    candidate = Path(raw)
    try:
        resolved = candidate.resolve(strict=True)
        info = candidate.lstat()
    except OSError as exc:
        raise MigrationError(f"{label} is unavailable: {exc}") from exc
    if (
        not candidate.is_absolute()
        or candidate != Path(os.path.normpath(str(candidate)))
        or resolved != candidate
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
    ):
        raise MigrationError(f"{label} must be a canonical non-symlink directory")
    return resolved


def fsync_ref(directory: DirectoryRef) -> None:
    if not stat.S_ISDIR(os.fstat(directory.descriptor).st_mode):
        raise MigrationError(f"{directory.label} descriptor is no longer a directory")
    os.fsync(directory.descriptor)


def assert_directory_binding(directory: DirectoryRef) -> None:
    """Fail if a replaceable pathname no longer names the retained inode."""

    try:
        named = directory.path.lstat()
        opened = os.fstat(directory.descriptor)
    except OSError as exc:
        raise MigrationError(
            f"{directory.label} pathname changed during migration: {exc}"
        ) from exc
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise MigrationError(f"{directory.label} pathname changed during migration")


def open_directory_ref(path: Path, label: str) -> DirectoryRef:
    if not path.is_absolute() or path != Path(os.path.normpath(str(path))):
        raise MigrationError(f"{label} must be an absolute canonical directory")
    descriptor = -1
    try:
        descriptor = os.open(
            os.path.sep,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
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
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise MigrationError(f"{label} is not a directory")
        result = DirectoryRef(path, descriptor, label)
        assert_directory_binding(result)
        return result
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise MigrationError(f"cannot pin {label}: {exc}") from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def open_child_directory_ref(
    parent: DirectoryRef,
    name: str,
    label: str,
    *,
    create_private: bool = False,
) -> DirectoryRef:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", ".."}:
        raise MigrationError(f"{label} has an unsafe child name")
    if create_private:
        try:
            os.mkdir(name, 0o700, dir_fd=parent.descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise MigrationError(f"cannot create {label}: {exc}") from exc
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent.descriptor,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise MigrationError(f"{label} must be a non-symlink directory")
        if create_private and (
            info.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise MigrationError(
                f"{label} must be an owned mode-0700 non-symlink directory"
            )
        result = DirectoryRef(parent.path / name, descriptor, label)
        fsync_ref(parent)
        assert_directory_binding(parent)
        assert_directory_binding(result)
        return result
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise MigrationError(f"cannot pin {label}: {exc}") from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def entry_stat(directory: DirectoryRef, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MigrationError(f"cannot inspect {directory.label} entry: {exc}") from exc


def entry_exists(directory: DirectoryRef, name: str) -> bool:
    return entry_stat(directory, name) is not None


def regular_bytes_at(
    directory: DirectoryRef,
    name: str,
    label: str,
    maximum: int = 2 * 1024 * 1024,
) -> tuple[bytes, os.stat_result]:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            SAFE_READ_FLAGS,
            dir_fd=directory.descriptor,
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not 0 < opened.st_size <= maximum:
            raise MigrationError(f"{label} has an invalid bounded size")
        raw = b""
        while len(raw) <= maximum:
            block = os.read(descriptor, maximum + 1 - len(raw))
            if not block:
                break
            raw += block
        after = os.fstat(descriptor)
        if (
            len(raw) > maximum
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise MigrationError(f"{label} changed while being read")
        return raw, opened
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise MigrationError(
                f"{label} must be a non-symlink regular file"
            ) from exc
        raise MigrationError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def open_bound_bytes_at(
    directory: DirectoryRef,
    name: str,
    label: str,
    maximum: int,
) -> tuple[int, bytes, os.stat_result]:
    """Read and retain a relative leaf descriptor through its transaction."""

    descriptor = -1
    try:
        descriptor = os.open(
            name,
            SAFE_READ_FLAGS,
            dir_fd=directory.descriptor,
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not 0 < opened.st_size <= maximum:
            raise MigrationError(f"{label} has an invalid bounded size")
        raw = b""
        while len(raw) <= maximum:
            block = os.read(descriptor, maximum + 1 - len(raw))
            if not block:
                break
            raw += block
        after = os.fstat(descriptor)
        if (
            len(raw) > maximum
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise MigrationError(f"{label} changed while being read")
        return descriptor, raw, opened
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise MigrationError(f"cannot read {label}: {exc}") from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def migration_queue_refs(
    workspace: Path,
) -> tuple[DirectoryRef, DirectoryRef, DirectoryRef]:
    """Pin every queue directory beneath one retained workspace inode."""

    workspace_ref = open_directory_ref(workspace, "canonical migration workspace")
    outbox: DirectoryRef | None = None
    pending: DirectoryRef | None = None
    consumed: DirectoryRef | None = None
    try:
        outbox = open_child_directory_ref(
            workspace_ref,
            "lineage-migration-outbox",
            "lineage migration outbox",
            create_private=True,
        )
        pending = open_child_directory_ref(
            outbox,
            "pending",
            "pending lineage migration controls",
            create_private=True,
        )
        consumed = open_child_directory_ref(
            outbox,
            "consumed",
            "consumed lineage migration controls",
            create_private=True,
        )
        rejected = open_child_directory_ref(
            outbox,
            "rejected",
            "rejected lineage migration controls",
            create_private=True,
        )
        return pending, consumed, rejected
    except BaseException:
        if consumed is not None:
            consumed.close()
        if pending is not None:
            pending.close()
        raise
    finally:
        if outbox is not None:
            outbox.close()
        workspace_ref.close()


def safe_child(parent: Path, relative: str, label: str) -> Path:
    child = parent / relative
    lexical = Path(os.path.abspath(child))
    if os.path.commonpath((str(parent), str(lexical))) != str(parent):
        raise MigrationError(f"{label} escapes its canonical parent")
    cursor = parent
    for part in Path(relative).parts[:-1]:
        cursor = cursor / part
        if cursor.exists() or cursor.is_symlink():
            info = cursor.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise MigrationError(f"{label} crosses an unsafe parent")
    return lexical


def parse_assignment_bytes(raw: bytes, label: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise MigrationError(f"{label} is not UTF-8") from exc
    for line in lines:
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            raise MigrationError(f"{label} repeats {key}")
        values[key] = value.strip().strip('"')
    return values


def protocol_roles(
    repository: Path,
    workspace: Path,
    team: str,
    feature: str,
    *,
    workspace_directory: DirectoryRef,
    snapshot: ExactStateSnapshot,
) -> dict[str, str]:
    projection_raw, projection_info = regular_bytes_at(
        workspace_directory,
        "preset.env",
        "authenticated team role projection",
        1024 * 1024,
    )
    skill = Path(__file__).resolve().parent.parent
    completed = subprocess.run(
        [
            sys.executable, str(skill / "bin" / "team-context.py"), "verify",
            "--repo", str(repository), "--workspace", str(workspace),
            "--team", team, "--feature", feature, "--skill", str(skill),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise MigrationError("protected team preset authority is unavailable")
    try:
        context = json.loads(completed.stdout)
    except ValueError as exc:
        raise MigrationError("protected team preset authority is malformed") from exc
    if not isinstance(context, dict):
        raise MigrationError("protected team preset authority is malformed")
    preset = str(context.get("preset") or "")
    if not hmac.compare_digest(
        str(context.get("projectionSha256") or ""), digest(projection_raw)
    ):
        raise MigrationError(
            "authenticated team role projection changed during verification"
        )
    values = parse_assignment_bytes(
        projection_raw, "authenticated team role projection"
    )
    if values.get("PRESET") != preset:
        raise MigrationError(
            "authenticated team role projection has a mismatched preset identity"
        )
    names = {
        name: values.get(f"PROTOCOL_{name}", "")
        for name in (
            "TEAM_LEAD", "PRODUCT_MANAGER", "PRINCIPAL_ARCHITECT", "SCEPTICAL_ARCHITECT"
        )
    }
    if names["PRODUCT_MANAGER"] == "null":
        names["PRODUCT_MANAGER"] = names["TEAM_LEAD"]
    if any(not ROLE.fullmatch(value) for value in names.values()):
        raise MigrationError("protected team role mapping is incomplete or unsafe")
    snapshot.retain(
        workspace_directory,
        "preset.env",
        "authenticated team role projection",
        1024 * 1024,
        projection_raw,
        projection_info,
    )
    return names


def request_body(request: dict[str, Any]) -> dict[str, Any]:
    return {
        key: request.get(key)
        for key in sorted(REQUEST_FIELDS - {"controlBodySha256", "producerCapability"})
    }


def validate_request(request: dict[str, Any]) -> None:
    if set(request) != REQUEST_FIELDS or request.get("schemaVersion") != 1:
        raise MigrationError("lineage migration control has an unsupported schema")
    if not CONTROL_ID.fullmatch(str(request.get("id") or "")):
        raise MigrationError("lineage migration control has an invalid identity")
    if request.get("marker") != "lineage-migration":
        raise MigrationError("lineage migration control has an invalid marker")
    if not DIGEST.fullmatch(str(request.get("observedExecutionSha256") or "")):
        raise MigrationError("lineage migration control has an invalid execution digest")
    for name in (
        "observedClaimSha256", "packetSha256", "packetJsonSha256",
        "reportSha256",
        "contractRegistrySha256",
        "contractEntrySha256",
    ):
        if not DIGEST.fullmatch(str(request.get(name) or "")):
            raise MigrationError(f"lineage migration control has an invalid {name}")
    created, expires = request.get("createdAt"), request.get("expiresAt")
    if type(created) is not int or type(expires) is not int or not created < expires <= created + 300:
        raise MigrationError("lineage migration control has an invalid validity interval")
    expected = digest(canonical(request_body(request)))
    if request.get("controlBodySha256") != expected:
        raise MigrationError("lineage migration control body digest mismatch")


def task_from_snapshot(tasks: dict[str, Any], task_id: str) -> dict[str, Any]:
    matches = [
        item for item in tasks.get("tasks") or []
        if isinstance(item, dict) and str(item.get("taskId")) == task_id
    ]
    if len(matches) != 1:
        raise MigrationError("migration task is absent or duplicated in the fresh snapshot")
    task = matches[0]
    revision, status = task.get("revision"), task.get("status")
    if isinstance(revision, bool) or not isinstance(revision, (str, int, float)):
        raise MigrationError("migration task has no concrete tracker revision")
    if not isinstance(status, str) or not status.strip():
        raise MigrationError("migration task has no concrete tracker status")
    return task


def registered_contract(
    workspace: Path, *, directory: DirectoryRef | None = None
) -> dict[str, str]:
    owned_directory = directory is None
    directory = directory or open_directory_ref(
        workspace, "lineage migration workspace"
    )
    try:
        raw, _ = regular_bytes_at(
            directory, "CONTRACTS.md", "lineage migration registry", 1024 * 1024
        )
    finally:
        if owned_directory:
            directory.close()
    return registered_contract_raw(raw)


def registered_contract_raw(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise MigrationError("lineage migration registry is not UTF-8") from exc
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(
            r"(.+?#\d+) exports transaction `lineageMigration/v1` — .+", line
        )
        if match:
            matches.append((match.group(1), line))
    if len(matches) != 1:
        raise MigrationError("lineageMigration/v1 must have one unique registered owner")
    owner, entry = matches[0]
    return {
        "taskId": owner,
        "contractRegistrySha256": digest(raw),
        "contractEntrySha256": digest(entry.encode("utf-8")),
    }


def integrated_task_status() -> str:
    board = decode(
        regular_bytes(
            Path(__file__).resolve().parent.parent / "config" / "statuses.config.json",
            "status board", 1024 * 1024,
        ),
        "status board",
    )
    matches = [
        str(item.get("name"))
        for item in board.get("tasks", {}).get("statuses", [])
        if item.get("kind") == "integrated" and item.get("terminal") is True
    ]
    if len(matches) != 1:
        raise MigrationError("integrated terminal task status must resolve exactly once")
    return matches[0]


def lineage_from_claim(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "team": claim["team"],
        "featureId": claim["featureId"],
        "taskId": claim["taskId"],
        "taskKey": claim["taskKey"],
        "targetStatus": claim["targetStatus"],
        "claimAttempt": claim["attempt"],
        "role": claim["role"],
        "claimId": claim["claimId"],
        "claimDigest": claim["claimDigest"],
    }


def validate_claim(
    claim: dict[str, Any], *, team: str, feature: str, task: str, key: str, role: str,
    execution_attempt: int,
) -> dict[str, Any]:
    if set(claim) != CLAIM_FIELDS or claim.get("schemaVersion") != 1:
        raise MigrationError("legacy migration claim has an unsupported schema")
    attempt = claim.get("attempt")
    target = claim.get("targetStatus")
    if type(attempt) is not int or not 1 <= attempt <= execution_attempt:
        raise MigrationError("legacy migration claim attempt is invalid")
    if not isinstance(target, str) or not target.strip():
        raise MigrationError("legacy migration claim target is invalid")
    expected_id = "dispatch-" + hashlib.sha256(
        "\0".join((team, feature, task, role, str(attempt), target)).encode()
    ).hexdigest()[:32]
    identity = {
        "schemaVersion": 1, "team": team, "featureId": feature, "taskId": task,
        "taskKey": key, "attempt": attempt, "role": role, "claimId": expected_id,
        "targetStatus": target,
    }
    if any(claim.get(name) != value for name, value in identity.items()):
        raise MigrationError("legacy migration claim identity mismatch")
    if claim.get("claimDigest") != digest(canonical(identity)):
        raise MigrationError("legacy migration claim digest mismatch")
    if not isinstance(claim.get("recordedAt"), str) or not claim["recordedAt"]:
        raise MigrationError("legacy migration claim timestamp is invalid")
    return lineage_from_claim(claim)


def require_historical_claim_receipt(task: dict[str, Any], claim: dict[str, Any]) -> None:
    """Bind local claim bytes to one exact receipt in the fresh task snapshot."""

    role = claim["role"]
    target = claim["targetStatus"]
    claim_id = claim["claimId"]
    assignee = task.get("assignee")
    if assignee is not None and (
        not isinstance(assignee, str) or assignee != role
    ):
        raise ClaimAuthorityError(
            "tracker assignee conflicts with the durable migration claim"
        )
    if (
        not ROLE.fullmatch(str(role))
        or not re.fullmatch(r"dispatch-[0-9a-f]{32}", str(claim_id))
        or not isinstance(target, str)
        or target != target.strip()
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,79}", target)
    ):
        raise ClaimAuthorityError(
            "legacy migration claim receipt identity is non-canonical"
        )
    expected_tail = (
        f"claim-id: {claim_id}\n"
        f"role: {role}\n"
        f"target-status: {target}\n\n"
        "— dispatcher"
    )

    def exact_receipt(comment: Any) -> bool:
        if not isinstance(comment, dict):
            return False
        body = str(comment.get("body") or "").strip()
        if not body.startswith("[claim]") or "claim-id:" not in body:
            return False
        position = body.find("claim-id:")
        prefix = body[len("[claim]") : position]
        if prefix != "\n" and not re.fullmatch(
            r" \([0-9]{4}-[0-9]{2}-[0-9]{2}\): (?:\n)?", prefix
        ):
            return False
        return body[position:] == expected_tail

    comments = task.get("comments") or []
    if not isinstance(comments, list):
        raise ClaimAuthorityError("migration tracker claim comments are malformed")
    if sum(1 for comment in comments if exact_receipt(comment)) != 1:
        raise ClaimAuthorityError(
            "legacy migration claim lacks one exact historical tracker receipt"
        )


def git_value(
    worktree: Path, *arguments: str, directory: DirectoryRef | None = None
) -> str:
    if directory is None:
        command = ["git", "-C", str(worktree), *arguments]
        options: dict[str, Any] = {}
    else:
        command = ["git", *arguments]
        descriptor = directory.descriptor
        options = {
            "pass_fds": (descriptor,),
            "preexec_fn": lambda: os.fchdir(descriptor),
        }
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        **options,
    )
    if completed.returncode != 0:
        raise MigrationError("cannot authenticate migration git identity")
    return completed.stdout.strip()


def exact_state(
    workspace: Path,
    tasks: dict[str, Any],
    request: dict[str, Any],
    *,
    workspace_directory: DirectoryRef | None = None,
    execution_directory: DirectoryRef | None = None,
    task_source: tuple[DirectoryRef, str, bytes, os.stat_result] | None = None,
) -> tuple[bytes, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Capture one pinned, fd-relative snapshot of mutable workspace authority."""

    owned: list[DirectoryRef] = []
    if workspace_directory is None:
        workspace_directory = open_directory_ref(
            workspace, "lineage migration workspace"
        )
        owned.append(workspace_directory)
    try:
        if execution_directory is None:
            execution_directory = open_child_directory_ref(
                workspace_directory, "executions", "migration execution directory"
            )
            owned.append(execution_directory)
    except BaseException:
        for directory in reversed(owned):
            directory.close()
        raise

    snapshot = ExactStateSnapshot(
        tasks,
        [workspace_directory, execution_directory],
        owned,
    )
    try:
        if task_source is not None:
            task_directory, task_name, task_raw, task_info = task_source
            if decode(task_raw, "fresh task snapshot") != tasks:
                raise MigrationError("fresh task snapshot bytes are cross-bound")
            if task_directory not in snapshot.bound_directories:
                snapshot.bound_directories.append(task_directory)
            snapshot.retain(
                task_directory,
                task_name,
                "fresh task snapshot",
                64 * 1024 * 1024,
                task_raw,
                task_info,
            )
        task = task_from_snapshot(tasks, str(request["taskId"]))
        key = task_key(str(request["taskId"]))
        if request["taskKey"] != key:
            raise MigrationError("migration control has a non-canonical task key")

        claims = open_child_directory_ref(
            workspace_directory, "claims", "migration claims directory"
        )
        snapshot.adopt(claims)
        execution_raw, execution_info = regular_bytes_at(
            execution_directory, f"{key}.json", "legacy execution"
        )
        claim_raw, claim_info = regular_bytes_at(
            claims, f"{key}.json", "legacy claim"
        )
        registry_raw, registry_info = regular_bytes_at(
            workspace_directory,
            "CONTRACTS.md",
            "lineage migration registry",
            1024 * 1024,
        )
        snapshot.retain(
            claims,
            f"{key}.json",
            "legacy claim",
            2 * 1024 * 1024,
            claim_raw,
            claim_info,
        )
        snapshot.retain(
            workspace_directory,
            "CONTRACTS.md",
            "lineage migration registry",
            1024 * 1024,
            registry_raw,
            registry_info,
        )

        observed_execution = decode(execution_raw, "legacy execution")
        claim = decode(claim_raw, "legacy claim")
        fields = set(observed_execution)
        lineage_fields = {"claimLineage", "lineageDigest"}
        has_any_lineage = bool(fields & lineage_fields)
        if has_any_lineage and not lineage_fields.issubset(fields):
            raise MigrationError("mixed lineage state is never migration eligible")
        base_fields = fields - lineage_fields
        if (
            not LEGACY_EXECUTION_FIELDS.issubset(base_fields)
            or not (base_fields - LEGACY_EXECUTION_FIELDS).issubset(
                LEGACY_EXECUTION_OPTIONAL_FIELDS
            )
        ):
            raise MigrationError("execution is not an exact genuine pre-lineage record")
        installed_target = has_any_lineage
        execution = {
            name: value
            for name, value in observed_execution.items()
            if name not in lineage_fields
        }

        attempt, role = execution.get("attempt"), execution.get("role")
        if (
            type(attempt) is not int
            or attempt < 1
            or not ROLE.fullmatch(str(role or ""))
        ):
            raise MigrationError("legacy execution has an invalid role or attempt")
        if "deliveryProfile" in execution and (
            not isinstance(execution["deliveryProfile"], str)
            or not execution["deliveryProfile"]
        ):
            raise MigrationError("legacy execution has an invalid delivery profile")
        expected_branch = f"agent-task/{request['team']}/{key}"
        if request["branch"] != expected_branch:
            raise MigrationError("migration control has a non-canonical task branch")

        artifacts = open_child_directory_ref(
            workspace_directory, "artifacts", "migration artifacts directory"
        )
        snapshot.adopt(artifacts)
        task_artifacts = open_child_directory_ref(
            artifacts, key, "migration task artifacts directory"
        )
        snapshot.adopt(task_artifacts)
        attempt_artifacts = open_child_directory_ref(
            task_artifacts,
            f"attempt-{attempt}",
            "migration attempt artifacts directory",
        )
        snapshot.adopt(attempt_artifacts)
        expected_packet = attempt_artifacts.path / "task-packet.md"
        expected_packet_json = attempt_artifacts.path / "task-packet.json"
        expected_report = attempt_artifacts.path / "task-report.md"
        expected_worktree = (
            workspace / "worktrees" / f"{role}#{attempt}-{key}"
        )
        expected = {
            "schemaVersion": 1,
            "featureId": request["featureId"],
            "taskId": request["taskId"],
            "taskKey": key,
            "branch": expected_branch,
            "worktree": str(expected_worktree),
            "packetPath": str(expected_packet),
            "packetJsonPath": str(expected_packet_json),
            "reportPath": str(expected_report),
        }
        if any(execution.get(name) != value for name, value in expected.items()):
            raise MigrationError(
                "legacy execution identity differs from the staged control"
            )
        if any(
            request.get(name) != value
            for name, value in {
                "worktree": str(expected_worktree),
                "packetPath": str(expected_packet),
                "packetJsonPath": str(expected_packet_json),
                "reportPath": str(expected_report),
            }.items()
        ):
            raise MigrationError("migration control artifact paths are non-canonical")
        if (
            not installed_target
            and digest(execution_raw) != request["observedExecutionSha256"]
        ):
            raise MigrationError("legacy execution bytes changed after Team Lead staging")
        if digest(claim_raw) != request["observedClaimSha256"]:
            raise MigrationError("legacy claim bytes changed after Team Lead staging")
        if (
            task["revision"] != request["observedTaskRevision"]
            or task["status"] != request["observedTaskStatus"]
        ):
            raise MigrationError(
                "tracker revision/status changed after Team Lead staging"
            )

        worktree = open_directory_ref(expected_worktree, "legacy worktree")
        snapshot.adopt(worktree)
        def validate_worktree() -> None:
            if (
                git_value(
                    expected_worktree,
                    "branch",
                    "--show-current",
                    directory=worktree,
                )
                != execution["branch"]
            ):
                raise MigrationError(
                    "legacy worktree branch changed after Team Lead staging"
                )
            if (
                git_value(
                    expected_worktree, "rev-parse", "HEAD", directory=worktree
                )
                != request["head"]
            ):
                raise MigrationError(
                    "legacy worktree HEAD changed after Team Lead staging"
                )

        validate_worktree()
        snapshot.retain_validator(validate_worktree)

        packet_raw, packet_info = regular_bytes_at(
            attempt_artifacts,
            "task-packet.md",
            "legacy task packet",
            64 * 1024 * 1024,
        )
        packet_json_raw, packet_json_info = regular_bytes_at(
            attempt_artifacts,
            "task-packet.json",
            "legacy task packet JSON",
            64 * 1024 * 1024,
        )
        report_raw, report_info = regular_bytes_at(
            attempt_artifacts,
            "task-report.md",
            "legacy task report",
            64 * 1024 * 1024,
        )
        snapshot.retain(
            attempt_artifacts,
            "task-packet.md",
            "legacy task packet",
            64 * 1024 * 1024,
            packet_raw,
            packet_info,
        )
        snapshot.retain(
            attempt_artifacts,
            "task-packet.json",
            "legacy task packet JSON",
            64 * 1024 * 1024,
            packet_json_raw,
            packet_json_info,
        )
        snapshot.retain(
            attempt_artifacts,
            "task-report.md",
            "legacy task report",
            64 * 1024 * 1024,
            report_raw,
            report_info,
        )
        if digest(packet_raw) != request["packetSha256"]:
            raise MigrationError("legacy task packet changed after Team Lead staging")
        if digest(packet_json_raw) != request["packetJsonSha256"]:
            raise MigrationError(
                "legacy task packet JSON identity changed after Team Lead staging"
            )
        if digest(report_raw) != request["reportSha256"]:
            raise MigrationError(
                "legacy task report changed after Team Lead staging"
            )
        if (
            not isinstance(execution.get("modelProfile"), str)
            or not execution["modelProfile"]
            or not isinstance(execution.get("updatedAt"), str)
            or not execution["updatedAt"]
        ):
            raise MigrationError("legacy execution metadata is invalid")

        lineage = validate_claim(
            claim,
            team=str(request["team"]),
            feature=str(request["featureId"]),
            task=str(request["taskId"]),
            key=key,
            role=str(role),
            execution_attempt=attempt,
        )
        require_historical_claim_receipt(task, claim)
        expected_lineage_digest = digest(canonical(lineage))
        if installed_target and (
            observed_execution.get("claimLineage") != lineage
            or observed_execution.get("lineageDigest") != expected_lineage_digest
        ):
            raise MigrationError(
                "installed lineage target does not match the exact durable claim"
            )
        contract = registered_contract_raw(registry_raw)
        snapshot.validate()
        return execution_raw, execution, claim, {
            "task": task,
            "lineage": lineage,
            "installedTarget": installed_target,
            "contract": contract,
            "snapshot": snapshot,
        }
    except BaseException:
        snapshot.close()
        raise


def published_receipt_digest(
    repository: Path, workspace: Path, entry: dict[str, Any], final_digest: str
) -> dict[str, str]:
    configured = publication_authority(repository)
    if configured is None:
        raise MigrationError("protected publication evidence is required")
    directory, _ = configured
    material = {
        "repository": str(repository), "workspace": str(workspace),
        "team": entry["team"], "featureId": entry["featureId"],
        "taskId": entry["taskId"], "deliveryId": entry["deliveryId"],
    }
    path = directory / (hashlib.sha256(canonical(material)).hexdigest() + ".json")
    raw = regular_bytes(path, "protected publication evidence")
    envelope = decode(raw, "protected publication evidence")
    if not verify_delivery(
        repository, workspace, team=str(entry["team"]),
        feature=str(entry["featureId"]), task=str(entry["taskId"]),
        marker=str(entry["marker"]), delivery=str(entry["deliveryId"]),
        target_status=entry.get("targetStatus"), final_body_digest=final_digest,
    ):
        raise MigrationError("protected publication evidence authentication failed")
    published_at = str((envelope.get("payload") or {}).get("publishedAt") or "")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T.+", published_at):
        raise MigrationError("protected publication evidence has an invalid publishedAt")
    return {"sha256": digest(raw), "publishedDate": published_at[:10]}


def marker_fields(body: str, marker: str) -> tuple[int, str | None]:
    if not re.match(rf"^\[{re.escape(marker)}\](?:\s|$)", body):
        raise MigrationError("published verdict body marker mismatch")
    rounds = re.findall(r"(?m)^round:\s*([1-9][0-9]*)\s*$", body)
    supersedes = re.findall(r"(?m)^supersedes:\s*([^\r\n]+?)\s*$", body)
    if len(rounds) != 1 or len(supersedes) > 1:
        raise MigrationError("published verdict round/supersession metadata is ambiguous")
    if supersedes and not re.fullmatch(r"[a-z][a-z-]*-[1-9][0-9]*", supersedes[0]):
        raise MigrationError("published verdict supersession metadata is non-canonical")
    return int(rounds[0]), supersedes[0] if supersedes else None


def markdown_tracker_body_matches(
    tracker_body: str, published_body: str, marker: str, delivery: str,
    published_date: str,
) -> bool:
    """Accept only the Markdown adapter's exact optional first-line date decoration."""

    trailer = f"\n\ndelivery-id: {delivery}"
    if not tracker_body.endswith(trailer):
        return False
    observed = tracker_body[: -len(trailer)]
    canonical_body = published_body.rstrip("\n")
    if observed == canonical_body:
        return True
    observed_lines = observed.splitlines()
    canonical_lines = canonical_body.splitlines()
    if not (
        observed_lines
        and canonical_lines
        and observed_lines[1:] == canonical_lines[1:]
        and canonical_lines[0] == f"[{marker}]"
    ):
        return False
    decorated = re.fullmatch(
        rf"\[{re.escape(marker)}\] \(([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})\): ",
        observed_lines[0],
    )
    if not decorated:
        return False
    try:
        observed_date = date.fromisoformat(decorated.group(1))
        protected_date = date.fromisoformat(published_date)
    except ValueError:
        return False
    # MarkdownAdapter.comment uses the host-local calendar date while the
    # protected broker receipt records UTC.  A legitimate timezone boundary
    # can therefore differ by one day, but never by two.
    return abs((observed_date - protected_date).days) <= 1


def current_verdicts(
    repository: Path, workspace: Path, request: dict[str, Any], task: dict[str, Any],
    roles: dict[str, str],
    *,
    snapshot: ExactStateSnapshot | None = None,
    authority_locked: bool = False,
) -> list[dict[str, Any]]:
    comments = task.get("comments") or []
    if not isinstance(comments, list):
        raise MigrationError("fresh tracker comments are malformed")
    if len(comments) > MAX_VERDICT_COMMENTS:
        raise MigrationError("fresh tracker verdict history exceeds its bounded limit")
    done = safe_child(workspace, "outbox/done", "published outbox")
    staged = safe_child(workspace, "outbox/staged", "staged published bodies")
    done_ref: DirectoryRef | None = None
    staged_ref: DirectoryRef | None = None
    selections: list[
        tuple[str, str, str, int, list[tuple[int, str, str]]]
    ] = []
    for family, markers, required, protocol in VERDICT_FAMILIES:
        candidates: list[tuple[int, str, str]] = []
        for index, comment in enumerate(comments):
            if not isinstance(comment, dict):
                continue
            text = str(comment.get("body") or "")
            match = re.match(r"^\[([a-z-]+)\](?:\s|$)", text)
            if not match or match.group(1) not in markers:
                continue
            trailer = re.fullmatch(r"(?s)(.+)\n\ndelivery-id: (delivery-[0-9a-f]{32})", text)
            if not trailer:
                raise MigrationError(f"current {family} verdict has malformed broker provenance")
            candidates.append((index, match.group(1), trailer.group(2)))
        if not candidates:
            raise MigrationError(f"current {family} verdict is absent")
        index, marker, delivery = candidates[-1]
        if marker != required:
            raise MigrationError(f"current {family} verdict is a pushback")
        selections.append((family, marker, delivery, index, candidates))

    required_deliveries = {item[2] for item in selections}
    indexed: dict[
        str, list[tuple[Path, dict[str, Any], bytes, os.stat_result]]
    ] = {
        delivery: [] for delivery in required_deliveries
    }
    retained_evidence: list[
        tuple[DirectoryRef, str, str, int, bytes, os.stat_result]
    ] = []
    expected_membership: dict[str, tuple[str, bytes]] = {}
    scanned = 0
    try:
        done_ref = open_directory_ref(done, "published outbox")
        with os.scandir(done_ref.descriptor) as entries:
            for directory_entry in entries:
                if scanned >= MAX_VERDICT_ENTRIES:
                    raise MigrationError(
                        "published verdict history exceeds its bounded lookup limit"
                    )
                scanned += 1
                if not directory_entry.name.endswith(".json"):
                    continue
                try:
                    info = directory_entry.stat(follow_symlinks=False)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or not 0 < info.st_size <= MAX_VERDICT_ENTRY_BYTES
                    ):
                        continue
                    raw, opened = regular_bytes_at(
                        done_ref,
                        directory_entry.name,
                        "published verdict entry",
                        MAX_VERDICT_ENTRY_BYTES,
                    )
                    if (info.st_dev, info.st_ino) != (
                        opened.st_dev,
                        opened.st_ino,
                    ):
                        continue
                    entry = decode(raw, "published verdict entry")
                except (MigrationError, OSError, ValueError):
                    # Untrusted unrelated history cannot deny all required
                    # verdicts merely by being malformed or oversized.
                    continue
                delivery = entry.get("deliveryId")
                if delivery in indexed:
                    indexed[delivery].append(
                        (done_ref.path / directory_entry.name, entry, raw, opened)
                    )
        staged_ref = open_directory_ref(staged, "staged published bodies")
        result = []
        for family, marker, delivery, index, candidates in selections:
            matches = indexed[delivery]
            if len(matches) != 1:
                raise MigrationError(
                    f"current {family} verdict publication is absent or ambiguous"
                )
            path, entry, entry_raw, entry_info = matches[0]
            if (
                entry.get("phase") != "published"
                or entry.get("team") != request["team"]
                or entry.get("featureId") != request["featureId"]
                or entry.get("taskId") != request["authorizationTaskId"]
                or entry.get("marker") != marker
                or entry.get("targetStatus") is not None
            ):
                raise MigrationError(
                    f"current {family} verdict publication is cross-bound"
                )
            body_path = Path(str(entry.get("publishBodyPath") or ""))
            expected_body = safe_child(
                workspace,
                f"outbox/staged/{delivery}.publish.md",
                "published verdict body",
            )
            if body_path != expected_body:
                raise MigrationError(
                    f"current {family} verdict body path is not canonical"
                )
            body_raw, body_info = regular_bytes_at(
                staged_ref,
                body_path.name,
                "published verdict body",
                65536,
            )
            body_digest = digest(body_raw)
            if entry.get("publishBodySha256") != body_digest:
                raise MigrationError(
                    f"current {family} verdict final body digest mismatch"
                )
            comment_body = str(comments[index].get("body") or "")
            try:
                capability = verify_published_entry(
                    str(repository),
                    str(workspace),
                    entry,
                    body_digest,
                    authority_locked=authority_locked,
                )
            except (CapabilityError, OSError, ValueError) as exc:
                raise MigrationError(
                    f"current {family} producer evidence is invalid: {exc}"
                ) from exc
            protocol = next(
                item[3] for item in VERDICT_FAMILIES if item[0] == family
            )
            if (
                capability.get("executionKind") != "gate"
                or capability.get("role") != roles[protocol]
            ):
                raise MigrationError(
                    f"current {family} verdict has the wrong authenticated owner"
                )
            publication = published_receipt_digest(
                repository, workspace, entry, body_digest
            )
            if not markdown_tracker_body_matches(
                comment_body,
                body_raw.decode("utf-8"),
                marker,
                delivery,
                publication["publishedDate"],
            ):
                raise MigrationError(
                    f"current {family} verdict tracker body differs from broker bytes"
                )
            round_number, supersedes = marker_fields(
                body_raw.decode("utf-8"), marker
            )
            if len(candidates) > 1:
                previous_index, previous_marker, _ = candidates[-2]
                previous_comment = str(comments[previous_index].get("body") or "")
                previous_trailer = re.fullmatch(
                    r"(?s)(.+)\n\ndelivery-id: delivery-[0-9a-f]{32}",
                    previous_comment,
                )
                if not previous_trailer:
                    raise MigrationError(
                        f"prior {family} verdict has malformed broker provenance"
                    )
                previous_round, _ = marker_fields(
                    previous_trailer.group(1), previous_marker
                )
                if (
                    supersedes != f"{previous_marker}-{previous_round}"
                    or round_number <= previous_round
                ):
                    raise MigrationError(
                        f"current {family} verdict does not canonically supersede "
                        "the prior verdict"
                    )
            elif supersedes is not None:
                raise MigrationError(
                    f"first {family} verdict cannot supersede absent history"
                )
            result.append({
                "family": family, "marker": marker, "round": round_number,
                "supersedes": supersedes, "deliveryId": delivery,
                "finalBodySha256": body_digest,
                "publicationEvidenceSha256": publication["sha256"],
                "publicationDate": publication["publishedDate"],
                "entrySha256": digest(entry_raw),
            })
            retained_evidence.extend((
                (
                    done_ref,
                    path.name,
                    "published verdict entry",
                    MAX_VERDICT_ENTRY_BYTES,
                    entry_raw,
                    entry_info,
                ),
                (
                    staged_ref,
                    body_path.name,
                    "published verdict body",
                    65536,
                    body_raw,
                    body_info,
                ),
            ))
            expected_membership[delivery] = (path.name, entry_raw)
        assert_directory_binding(done_ref)
        assert_directory_binding(staged_ref)
        if snapshot is not None:
            retained_done_ref = done_ref

            def validate_required_membership(
                done_directory: DirectoryRef = retained_done_ref,
            ) -> None:
                observed: dict[str, list[tuple[str, bytes]]] = {
                    delivery: [] for delivery in required_deliveries
                }
                rescanned = 0
                with os.scandir(done_directory.descriptor) as entries:
                    for directory_entry in entries:
                        if rescanned >= MAX_VERDICT_ENTRIES:
                            raise MigrationError(
                                "published verdict history exceeds its bounded lookup limit"
                            )
                        rescanned += 1
                        if not directory_entry.name.endswith(".json"):
                            continue
                        try:
                            info = directory_entry.stat(follow_symlinks=False)
                            if (
                                not stat.S_ISREG(info.st_mode)
                                or not 0 < info.st_size <= MAX_VERDICT_ENTRY_BYTES
                            ):
                                continue
                            raw, opened = regular_bytes_at(
                                done_directory,
                                directory_entry.name,
                                "published verdict entry",
                                MAX_VERDICT_ENTRY_BYTES,
                            )
                            if (info.st_dev, info.st_ino) != (
                                opened.st_dev,
                                opened.st_ino,
                            ):
                                continue
                            entry = decode(raw, "published verdict entry")
                        except (MigrationError, OSError, ValueError):
                            continue
                        delivery = entry.get("deliveryId")
                        if delivery in observed:
                            observed[delivery].append(
                                (directory_entry.name, raw)
                            )
                for delivery, expected in expected_membership.items():
                    if observed[delivery] != [expected]:
                        raise MigrationError(
                            "current verdict publication membership changed before "
                            "migration commit"
                        )

            snapshot.adopt(done_ref, staged_ref)
            for evidence in retained_evidence:
                snapshot.retain(*evidence)
            snapshot.retain_validator(validate_required_membership)
            done_ref = None
            staged_ref = None
        return result
    finally:
        if staged_ref is not None:
            staged_ref.close()
        if done_ref is not None:
            done_ref.close()


def lifecycle_generation(
    repository: Path, workspace: Path, lifecycle_root: Path,
    request: dict[str, Any], execution: dict[str, Any],
) -> dict[str, Any]:
    instance = f"{execution['role']}--{request['taskKey']}--a{execution['attempt']}"
    completed = subprocess.run(
        [
            sys.executable, str(Path(__file__).resolve().with_name("process-lifecycle.py")),
            "list", "--root", str(lifecycle_root), "--repo", str(repository),
            "--team", str(request["team"]),
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if completed.returncode != 0:
        raise MigrationError("protected lifecycle generation is unavailable")
    rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    matches = [
        row for row in rows
        if row.get("category") == "task" and row.get("instance") == instance
    ]
    if len(matches) != 1:
        raise MigrationError("protected lifecycle generation is absent or ambiguous")
    row = matches[0]
    if row.get("createdAt") != request["observedLifecycleCreatedAt"]:
        raise MigrationError("protected lifecycle generation changed after Team Lead staging")
    return {
        "instance": instance, "createdAt": row["createdAt"], "state": row.get("state"),
        "rowSha256": digest(canonical(row)),
    }


def require_non_live_generation(
    repository: Path,
    workspace: Path,
    lifecycle_root: Path,
    request: dict[str, Any],
    execution: dict[str, Any],
    *,
    expected: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Authenticate one exact dead generation at a transaction boundary."""

    generation = lifecycle_generation(
        repository, workspace, lifecycle_root, request, execution
    )
    if generation.get("state") != "dead":
        raise MigrationError(
            "lineage migration requires the exact lifecycle generation to be non-live"
        )
    if expected is not None and generation != expected:
        raise MigrationError(
            "protected lifecycle generation changed before migration commit"
        )
    return generation


def authority(
    lifecycle_root: Path, repository: Path
) -> tuple[DirectoryRef, DirectoryRef, bytes]:
    info = lifecycle_root.lstat()
    if (
        stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid not in {0, os.geteuid()}
    ):
        raise MigrationError("protected lifecycle root is unsafe")
    if os.path.commonpath((str(lifecycle_root), str(repository))) in {
        str(lifecycle_root), str(repository)
    }:
        raise MigrationError("protected lifecycle root and repository must be disjoint")
    lifecycle = open_directory_ref(lifecycle_root, "protected lifecycle root")
    root: DirectoryRef | None = None
    prepared: DirectoryRef | None = None
    consumed: DirectoryRef | None = None
    try:
        key, key_info = regular_bytes_at(
            lifecycle, "record-auth.key", "protected lifecycle authentication key", 32
        )
        if len(key) != 32 or stat.S_IMODE(key_info.st_mode) != 0o600:
            raise MigrationError("protected lifecycle authentication key is unsafe")
        root = open_child_directory_ref(
            lifecycle,
            "lineage-migrations",
            "lineage migration authority",
            create_private=True,
        )
        prepared = open_child_directory_ref(
            root,
            "prepared",
            "prepared migration receipts",
            create_private=True,
        )
        consumed = open_child_directory_ref(
            root,
            "consumed",
            "consumed migration receipts",
            create_private=True,
        )
        assert_directory_binding(lifecycle)
        return prepared, consumed, key
    except BaseException:
        if consumed is not None:
            consumed.close()
        if prepared is not None:
            prepared.close()
        raise
    finally:
        if root is not None:
            root.close()
        lifecycle.close()


def authenticated(receipt: dict[str, Any], key: bytes) -> bool:
    supplied = str(receipt.get("auth") or "")
    unsigned = dict(receipt)
    unsigned.pop("auth", None)
    expected = "hmac-sha256:" + hmac.new(key, DOMAIN + canonical(unsigned), hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)


def store_receipt(
    path: Path,
    unsigned: dict[str, Any],
    key: bytes,
    *,
    directory: DirectoryRef | None = None,
) -> dict[str, Any]:
    value = dict(unsigned)
    value["auth"] = "hmac-sha256:" + hmac.new(
        key, DOMAIN + canonical(unsigned), hashlib.sha256
    ).hexdigest()
    raw = canonical(value) + b"\n"
    owned_directory = directory is None
    directory = directory or open_directory_ref(
        path.parent, "protected migration receipt directory"
    )
    if path.parent != directory.path:
        if owned_directory:
            directory.close()
        raise MigrationError("protected migration receipt parent is cross-bound")
    temporary_name = f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory.descriptor,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
            try:
                os.link(
                    temporary_name,
                    path.name,
                    src_dir_fd=directory.descriptor,
                    dst_dir_fd=directory.descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                pass
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory.descriptor)
            except FileNotFoundError:
                pass
    except BaseException:
        if owned_directory:
            directory.close()
        raise
    # Persist the final hard-link publication and temporary-name retirement as
    # one durable directory state before any execution/control phase advances.
    try:
        fsync_ref(directory)
        existing_raw, _ = regular_bytes_at(
            directory, path.name, "protected migration receipt"
        )
        existing = decode(existing_raw, "protected migration receipt")
        if existing != value or not authenticated(existing, key):
            raise MigrationError("protected migration receipt identity collision")
        assert_directory_binding(directory)
        return existing
    finally:
        if owned_directory:
            directory.close()


def validate_receipt_binding(
    receipt: dict[str, Any], phase: str, key: bytes, request_raw: bytes,
    request: dict[str, Any], repository: Path, workspace: Path,
) -> None:
    if not authenticated(receipt, key):
        raise MigrationError(f"{phase} migration receipt authentication failed")
    expected = {
        "schemaVersion": 1, "domain": "lineageMigration/v1", "phase": phase,
        "repository": str(repository), "workspace": str(workspace),
        "team": request["team"], "featureId": request["featureId"],
        "taskId": request["taskId"], "taskKey": request["taskKey"],
        "authorizationTaskId": request["authorizationTaskId"],
        "stagedBy": request["actor"],
        "controlId": request["id"], "controlSha256": digest(request_raw),
        "executionBytesSha256": request["observedExecutionSha256"],
        "claimBytesSha256": request["observedClaimSha256"],
        "targetExecutionSha256": receipt.get("targetExecutionSha256"),
    }
    if not DIGEST.fullmatch(str(receipt.get("targetExecutionSha256") or "")):
        raise MigrationError(f"{phase} migration receipt target digest is invalid")
    if any(receipt.get(name) != value for name, value in expected.items()):
        raise MigrationError(f"{phase} migration receipt is cross-bound")


def consume_control(
    source: Path,
    consumed: DirectoryRef,
    rejected: DirectoryRef,
    expected_raw: bytes,
    expected_info: os.stat_result,
    source_directory: DirectoryRef | None = None,
) -> None:
    """Archive authenticated bytes and retire only their exact pending inode."""

    own_source_directory = source_directory is None
    source_directory = source_directory or open_directory_ref(
        source.parent, "pending lineage migration controls"
    )
    if source.parent != source_directory.path:
        if own_source_directory:
            source_directory.close()
        raise MigrationError("pending migration control parent is cross-bound")
    destination = consumed.path / source.name
    if source == destination:
        if own_source_directory:
            source_directory.close()
        return
    # The consumed audit record comes from the bytes authenticated at entry,
    # never from a later occupant of the agent-writable pending pathname.
    store_transaction_artifact(
        destination,
        expected_raw,
        "consumed migration control",
        directory=consumed,
    )

    candidate = rejected.path / (
        f"retiring-{hashlib.sha256(os.fsencode(source.name)).hexdigest()[:32]}-"
        f"{secrets.token_hex(8)}.tombstone"
    )
    try:
        rename_no_replace(
            source,
            candidate,
            "retire pending migration control",
            source_directory=source_directory,
            destination_directory=rejected,
        )
    except MigrationError:
        if not entry_exists(source_directory, source.name):
            fsync_ref(source_directory)
            if entry_exists(rejected, candidate.name):
                fsync_ref(rejected)
                if own_source_directory:
                    source_directory.close()
                raise
            if own_source_directory:
                source_directory.close()
            return
        if own_source_directory:
            source_directory.close()
        raise
    candidate_info = entry_stat(rejected, candidate.name)
    if candidate_info is None:
        if own_source_directory:
            source_directory.close()
        raise MigrationError("retired migration control vanished before comparison")
    exact_source = (
        stat.S_ISREG(candidate_info.st_mode)
        and (candidate_info.st_dev, candidate_info.st_ino)
        == (expected_info.st_dev, expected_info.st_ino)
    )
    try:
        candidate_raw, candidate_opened = regular_bytes_at(
            rejected, candidate.name, "retired migration control"
        )
    except MigrationError:
        candidate_raw = None
        candidate_opened = None
    if exact_source and candidate_raw == expected_raw:
        latest = entry_stat(rejected, candidate.name)
        if (
            candidate_opened is None
            or latest is None
            or (latest.st_dev, latest.st_ino)
            != (candidate_opened.st_dev, candidate_opened.st_ino)
        ):
            if own_source_directory:
                source_directory.close()
            raise MigrationError("retired migration control changed after evacuation")
        # This inode came from an agent-writable directory.  A process may
        # still hold a writable descriptor even after the exact comparison,
        # so retain the random tombstone permanently as non-authoritative
        # evidence instead of creating a final write-then-unlink loss window.
        assert_directory_binding(rejected)
        assert_directory_binding(source_directory)
        if own_source_directory:
            source_directory.close()
        return
    print(
        f"lineage-migration: quarantined raced pending entry {source.name}",
        file=sys.stderr,
    )
    assert_directory_binding(rejected)
    assert_directory_binding(source_directory)
    if own_source_directory:
        source_directory.close()


def rename_no_replace(
    source: Path,
    destination: Path,
    label: str,
    *,
    source_directory: DirectoryRef | None = None,
    destination_directory: DirectoryRef | None = None,
) -> None:
    """Atomically move one name without ever replacing the destination name."""

    libc = ctypes.CDLL(None, use_errno=True)
    own_source = source_directory is None
    own_destination = destination_directory is None
    source_directory = source_directory or open_directory_ref(
        source.parent, f"{label} source directory"
    )
    try:
        destination_directory = destination_directory or open_directory_ref(
            destination.parent, f"{label} destination directory"
        )
    except BaseException:
        if own_source:
            source_directory.close()
        raise
    if (
        source.parent != source_directory.path
        or destination.parent != destination_directory.path
    ):
        if own_destination:
            destination_directory.close()
        if own_source:
            source_directory.close()
        raise MigrationError(f"{label} directory binding is invalid")
    old = os.fsencode(source.name)
    new = os.fsencode(destination.name)
    if sys.platform == "darwin":
        operation = getattr(libc, "renameatx_np", None)
        arguments = (
            source_directory.descriptor,
            old,
            destination_directory.descriptor,
            new,
            0x00000004,
        )  # RENAME_EXCL
        argument_types = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
    elif sys.platform.startswith("linux"):
        operation = getattr(libc, "renameat2", None)
        arguments = (
            source_directory.descriptor,
            old,
            destination_directory.descriptor,
            new,
            1,
        )  # RENAME_NOREPLACE
        argument_types = (
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
            ctypes.c_char_p, ctypes.c_uint,
        )
    else:
        operation = None
        arguments = ()
        argument_types = ()
    try:
        if operation is None:
            raise MigrationError(
                f"{label} requires an atomic no-replace rename primitive"
            )
        operation.argtypes = argument_types
        operation.restype = ctypes.c_int
        if operation(*arguments) != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise MigrationError(f"{label} destination already exists")
            raise MigrationError(f"cannot {label}: {os.strerror(error)}")
        # A successful rename is already a state mutation.  Persist the
        # retained destination first and then the source-directory retirement
        # before any replaceable pathname assertion can abort the caller.
        fsync_ref(destination_directory)
        source_info = os.fstat(source_directory.descriptor)
        destination_info = os.fstat(destination_directory.descriptor)
        if (source_info.st_dev, source_info.st_ino) != (
            destination_info.st_dev,
            destination_info.st_ino,
        ):
            fsync_ref(source_directory)
        assert_directory_binding(source_directory)
        assert_directory_binding(destination_directory)
    finally:
        if own_destination:
            destination_directory.close()
        if own_source:
            source_directory.close()


def store_transaction_artifact(
    path: Path,
    raw: bytes,
    label: str,
    *,
    directory: DirectoryRef | None = None,
) -> None:
    """Durably publish exact transaction bytes at a protected, stable name."""

    owned_directory = directory is None
    directory = directory or open_directory_ref(path.parent, f"{label} directory")
    if path.parent != directory.path:
        if owned_directory:
            directory.close()
        raise MigrationError(f"{label} parent is cross-bound")
    temporary_name = f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory.descriptor,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(
                    temporary_name,
                    path.name,
                    src_dir_fd=directory.descriptor,
                    dst_dir_fd=directory.descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                pass
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory.descriptor)
            except FileNotFoundError:
                pass
    except BaseException:
        if owned_directory:
            directory.close()
        raise
    try:
        fsync_ref(directory)
        existing, _ = regular_bytes_at(directory, path.name, label)
        if existing != raw:
            raise MigrationError(f"{label} identity collision")
        assert_directory_binding(directory)
    finally:
        if owned_directory:
            directory.close()


def retire_transaction_artifact(
    path: Path,
    raw: bytes,
    label: str,
    *,
    directory: DirectoryRef | None = None,
) -> None:
    owned_directory = directory is None
    directory = directory or open_directory_ref(path.parent, f"{label} directory")
    try:
        info = entry_stat(directory, path.name)
        if info is None:
            return
        current, opened = regular_bytes_at(directory, path.name, label)
        if current != raw:
            raise MigrationError(f"{label} changed before retirement")
        latest = entry_stat(directory, path.name)
        if latest is None or (latest.st_dev, latest.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise MigrationError(f"{label} changed before retirement")
        os.unlink(path.name, dir_fd=directory.descriptor)
        fsync_ref(directory)
        assert_directory_binding(directory)
    finally:
        if owned_directory:
            directory.close()


def unlink_exact_entry(
    directory: DirectoryRef, name: str, expected_raw: bytes, label: str
) -> None:
    current, opened = regular_bytes_at(directory, name, label)
    if current != expected_raw:
        raise MigrationError(f"{label} changed before retirement")
    latest = entry_stat(directory, name)
    if latest is None or (latest.st_dev, latest.st_ino) != (
        opened.st_dev,
        opened.st_ino,
    ):
        raise MigrationError(f"{label} changed before retirement")
    os.unlink(name, dir_fd=directory.descriptor)
    fsync_ref(directory)
    assert_directory_binding(directory)


def validate_lock_entry(
    directory: DirectoryRef, name: str, descriptor: int, label: str
) -> None:
    """Bind a held flock to the one safe name in its pinned directory."""

    held = os.fstat(descriptor)
    named = entry_stat(directory, name)
    if (
        named is None
        or not stat.S_ISREG(held.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or stat.S_IMODE(held.st_mode) != 0o600
        or stat.S_IMODE(named.st_mode) != 0o600
        or held.st_uid not in {0, os.geteuid()}
        or named.st_uid != held.st_uid
        or held.st_nlink != 1
        or named.st_nlink != 1
        or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino)
    ):
        raise MigrationError(f"{label} changed identity or is unsafe")
    assert_directory_binding(directory)


def require_same_transaction_device(
    execution: Path,
    protected: Path,
    *,
    execution_directory: DirectoryRef | None = None,
    protected_directory: DirectoryRef | None = None,
) -> None:
    """Fail before prepare when an atomic cross-directory rename is impossible."""

    try:
        execution_parent = (
            os.fstat(execution_directory.descriptor)
            if execution_directory is not None
            else execution.parent.lstat()
        )
        protected_parent = (
            os.fstat(protected_directory.descriptor)
            if protected_directory is not None
            else protected.lstat()
        )
    except OSError as exc:
        raise MigrationError(
            f"cannot verify migration transaction filesystem: {exc}"
        ) from exc
    if execution_parent.st_dev != protected_parent.st_dev:
        raise MigrationError(
            "migration execution and protected recovery storage must share one filesystem"
        )


def install_execution_transaction(
    execution: Path, backup: Path, target_artifact: Path,
    old_raw: bytes, target_raw: bytes,
    before_commit: Callable[[], None] | None = None,
    *,
    execution_directory: DirectoryRef | None = None,
    protected_directory: DirectoryRef | None = None,
) -> None:
    """Install a fresh projection while retaining independent sealed authority."""

    own_execution = execution_directory is None
    own_protected = protected_directory is None
    execution_directory = execution_directory or open_directory_ref(
        execution.parent, "migration execution directory"
    )
    try:
        protected_directory = protected_directory or open_directory_ref(
            backup.parent, "protected migration transaction directory"
        )
    except BaseException:
        if own_execution:
            execution_directory.close()
        raise
    if (
        execution.parent != execution_directory.path
        or backup.parent != protected_directory.path
        or target_artifact.parent != protected_directory.path
    ):
        if own_protected:
            protected_directory.close()
        if own_execution:
            execution_directory.close()
        raise MigrationError("migration transaction directories are cross-bound")
    candidate = protected_directory.path / (
        f".{target_artifact.name}.install.{os.getpid()}.{secrets.token_hex(8)}"
    )
    try:
        require_same_transaction_device(
            execution,
            protected_directory.path,
            execution_directory=execution_directory,
            protected_directory=protected_directory,
        )
        # Both protected names are independent O_EXCL copies.  Neither can be
        # mutated through a descriptor opened on the agent-writable execution.
        store_transaction_artifact(
            target_artifact,
            target_raw,
            "protected migration target artifact",
            directory=protected_directory,
        )
        sealed_target, target_info = regular_bytes_at(
            protected_directory,
            target_artifact.name,
            "protected migration target artifact",
        )
        sealed_old: bytes | None = None
        sealed_old_info: os.stat_result | None = None
        if entry_exists(protected_directory, backup.name):
            sealed_old, sealed_old_info = regular_bytes_at(
                protected_directory,
                backup.name,
                "protected legacy execution backup",
            )
        if (sealed_old is not None and sealed_old != old_raw) or sealed_target != target_raw:
            raise MigrationError("protected migration authority changed before commit")

        current_info = entry_stat(execution_directory, execution.name)
        if current_info is not None:
            current_descriptor, current, opened = open_bound_bytes_at(
                execution_directory,
                execution.name,
                "migration execution destination",
                2 * 1024 * 1024,
            )
            try:
                if current == target_raw:
                    if (opened.st_dev, opened.st_ino) == (
                        target_info.st_dev,
                        target_info.st_ino,
                    ):
                        raise MigrationError(
                            "workspace target must not share protected authority inode"
                        )
                    fsync_ref(execution_directory)
                    assert_directory_binding(execution_directory)
                    return
                if current != old_raw:
                    raise MigrationError(
                        "migration execution destination is occupied; sealed legacy "
                        "bytes were retained"
                    )
                if sealed_old_info is not None and (
                    opened.st_dev,
                    opened.st_ino,
                ) == (sealed_old_info.st_dev, sealed_old_info.st_ino):
                    raise MigrationError(
                        "workspace execution must not share protected backup inode"
                    )
                if before_commit is not None:
                    before_commit()
                if sealed_old is None:
                    store_transaction_artifact(
                        backup,
                        old_raw,
                        "protected legacy execution backup",
                        directory=protected_directory,
                    )
                    sealed_old, sealed_old_info = regular_bytes_at(
                        protected_directory,
                        backup.name,
                        "protected legacy execution backup",
                    )
                    if sealed_old != old_raw:
                        raise MigrationError(
                            "protected legacy execution backup changed before commit"
                        )
                latest = entry_stat(execution_directory, execution.name)
                os.lseek(current_descriptor, 0, os.SEEK_SET)
                confirmed = b""
                while len(confirmed) <= len(old_raw):
                    block = os.read(
                        current_descriptor, len(old_raw) + 1 - len(confirmed)
                    )
                    if not block:
                        break
                    confirmed += block
                after = os.fstat(current_descriptor)
                if (
                    latest is None
                    or (latest.st_dev, latest.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or confirmed != old_raw
                    or after.st_size != opened.st_size
                    or after.st_mtime_ns != opened.st_mtime_ns
                    or after.st_ctime_ns != opened.st_ctime_ns
                ):
                    raise MigrationError(
                        "legacy execution changed before sealed evacuation"
                    )
                tombstone = protected_directory.path / (
                    f".{execution.name}.untrusted-source.{os.getpid()}."
                    f"{secrets.token_hex(8)}.tombstone"
                )
                rename_no_replace(
                    execution,
                    tombstone,
                    "evacuate legacy execution for migration",
                    source_directory=execution_directory,
                    destination_directory=protected_directory,
                )
                # The helper persisted the only remaining name before the
                # writable source directory lost its name.  The moved inode is
                # never recovery authority and is deliberately retained because
                # an attacker may continue writing through an open descriptor.
                evacuated_raw, evacuated_info = regular_bytes_at(
                    protected_directory,
                    tombstone.name,
                    "evacuated legacy migration execution",
                    2 * 1024 * 1024,
                )
                if (
                    (evacuated_info.st_dev, evacuated_info.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or evacuated_raw != old_raw
                ):
                    raise MigrationError(
                        "legacy execution changed during sealed evacuation"
                    )
                assert_directory_binding(protected_directory)
                assert_directory_binding(execution_directory)
            finally:
                os.close(current_descriptor)
        elif sealed_old is None:
            raise MigrationError(
                "migration execution vanished before sealed backup publication"
            )

        if before_commit is not None:
            before_commit()
        store_transaction_artifact(
            candidate,
            target_raw,
            "protected migration install candidate",
            directory=protected_directory,
        )
        rename_no_replace(
            candidate,
            execution,
            "install migration target projection",
            source_directory=protected_directory,
            destination_directory=execution_directory,
        )
        # The no-replace helper persisted destination first, so a crash can
        # never lose the newly installed workspace projection.
        installed, installed_info = regular_bytes_at(
            execution_directory, execution.name, "migration target"
        )
        if installed != target_raw or (
            installed_info.st_dev,
            installed_info.st_ino,
        ) == (target_info.st_dev, target_info.st_ino):
            raise MigrationError(
                "migration target is not an independent exact projection"
            )
        assert_directory_binding(execution_directory)
        assert_directory_binding(protected_directory)
    finally:
        if entry_exists(protected_directory, candidate.name):
            try:
                retire_transaction_artifact(
                    candidate,
                    target_raw,
                    "protected migration install candidate",
                    directory=protected_directory,
                )
            except MigrationError:
                pass
        if own_protected:
            protected_directory.close()
        if own_execution:
            execution_directory.close()


def repair_consumed_projection(
    execution: Path,
    target_artifact: Path,
    target_raw: bytes,
    execution_directory: DirectoryRef,
    protected_directory: DirectoryRef,
) -> None:
    """Converge a consumed transaction from its sealed target authority."""

    current = entry_stat(execution_directory, execution.name)
    if current is not None:
        try:
            current_raw, _ = regular_bytes_at(
                execution_directory, execution.name, "consumed migration target"
            )
        except MigrationError:
            current_raw = None
        if current_raw == target_raw:
            fsync_ref(execution_directory)
            return
    tombstone = protected_directory.path / (
        f".{execution.name}.displaced.{os.getpid()}.{secrets.token_hex(8)}"
    )
    if current is not None:
        rename_no_replace(
            execution,
            tombstone,
            "evacuate corrupt consumed migration projection",
            source_directory=execution_directory,
            destination_directory=protected_directory,
        )
        _, displaced_info = regular_bytes_at(
            protected_directory,
            tombstone.name,
            "displaced consumed migration projection",
            2 * 1024 * 1024,
        )
        if (displaced_info.st_dev, displaced_info.st_ino) != (
            current.st_dev,
            current.st_ino,
        ):
            raise MigrationError(
                "consumed migration projection changed during evacuation"
            )

    candidate = protected_directory.path / (
        f".{target_artifact.name}.repair.{os.getpid()}.{secrets.token_hex(8)}"
    )
    store_transaction_artifact(
        candidate,
        target_raw,
        "protected consumed migration repair candidate",
        directory=protected_directory,
    )
    try:
        rename_no_replace(
            candidate,
            execution,
            "repair consumed migration target projection",
            source_directory=protected_directory,
            destination_directory=execution_directory,
        )
        installed, installed_info = regular_bytes_at(
            execution_directory, execution.name, "repaired consumed migration target"
        )
        sealed, sealed_info = regular_bytes_at(
            protected_directory,
            target_artifact.name,
            "protected migration target artifact",
        )
        if (
            installed != target_raw
            or sealed != target_raw
            or (installed_info.st_dev, installed_info.st_ino)
            == (sealed_info.st_dev, sealed_info.st_ino)
        ):
            raise MigrationError("consumed migration target repair did not converge")
    finally:
        if entry_exists(protected_directory, candidate.name):
            os.unlink(candidate.name, dir_fd=protected_directory.descriptor)
            fsync_ref(protected_directory)
    # Never retire ``tombstone``: it was agent-writable before evacuation and
    # may still be changing through a retained descriptor.  It is evidence,
    # not an input to recovery; only the sealed target artifact is authority.
    assert_directory_binding(execution_directory)
    assert_directory_binding(protected_directory)


def migrate_one(
    repository: Path, workspace: Path, lifecycle_root: Path, tasks: dict[str, Any],
    control_path: Path,
    *,
    queues: tuple[DirectoryRef, DirectoryRef, DirectoryRef] | None = None,
    task_source: tuple[DirectoryRef, str, bytes, os.stat_result] | None = None,
) -> str:
    if os.environ.get("STARTUP_FACTORY_LINEAGE_MIGRATION_BROKER") != "1":
        raise MigrationError("direct invocation is forbidden; deterministic broker authorization is required")
    own_queues = queues is None
    queues = queues or migration_queue_refs(workspace)
    pending_controls, consumed_controls, rejected_controls = queues
    if control_path.parent != pending_controls.path:
        if own_queues:
            for directory in queues:
                directory.close()
        raise MigrationError("lineage migration control parent is cross-bound")
    try:
        control_descriptor, request_raw, control_info = open_bound_bytes_at(
            pending_controls,
            control_path.name,
            "lineage migration control",
            MAX_MIGRATION_REQUEST_BYTES,
        )
    except BaseException:
        if own_queues:
            for directory in queues:
                directory.close()
        raise
    try:
        return migrate_bound_request(
            repository,
            workspace,
            lifecycle_root,
            tasks,
            control_path,
            request_raw,
            control_info,
            queues,
            task_source=task_source,
        )
    finally:
        os.close(control_descriptor)
        if own_queues:
            for directory in queues:
                directory.close()


def migrate_bound_request(
    repository: Path,
    workspace: Path,
    lifecycle_root: Path,
    tasks: dict[str, Any],
    control_path: Path,
    request_raw: bytes,
    control_info: os.stat_result,
    queues: tuple[DirectoryRef, DirectoryRef, DirectoryRef],
    *,
    task_source: tuple[DirectoryRef, str, bytes, os.stat_result] | None = None,
) -> str:
    """Serialize capability state and every migration phase under one broker lock."""

    try:
        with capability_authority_lock(repository):
            return _migrate_bound_request_locked(
                repository,
                workspace,
                lifecycle_root,
                tasks,
                control_path,
                request_raw,
                control_info,
                queues,
                task_source=task_source,
            )
    except CapabilityError as exc:
        raise MigrationError(f"broker authority lock failed: {exc}") from exc


def _migrate_bound_request_locked(
    repository: Path,
    workspace: Path,
    lifecycle_root: Path,
    tasks: dict[str, Any],
    control_path: Path,
    request_raw: bytes,
    control_info: os.stat_result,
    queues: tuple[DirectoryRef, DirectoryRef, DirectoryRef],
    *,
    task_source: tuple[DirectoryRef, str, bytes, os.stat_result] | None = None,
) -> str:
    request = decode(request_raw, "lineage migration control")
    validate_request(request)
    if control_path.name != f"{request['id']}.json":
        raise MigrationError("lineage migration control filename mismatch")
    if request["team"] != tasks.get("team", request["team"]) or request["featureId"] != tasks.get("featureId"):
        raise MigrationError("lineage migration control is cross-bound")
    pending_controls, consumed_controls, rejected_controls = queues
    prepared_ref, consumed_receipts_ref, key = authority(lifecycle_root, repository)
    prepared = prepared_ref.path
    consumed_receipts = consumed_receipts_ref.path
    receipt_name = f"{request['id']}.json"
    prepared_path = prepared / receipt_name
    consumed_path = consumed_receipts / receipt_name
    execution_path = workspace / "executions" / f"{request['taskKey']}.json"
    backup_path = prepared / f".{request['id']}.execution-backup"
    target_artifact_path = prepared / f".{request['id']}.execution-target"
    backup_name = backup_path.name
    target_artifact_name = target_artifact_path.name
    execution_name = execution_path.name
    try:
        has_protected_receipt = (
            entry_exists(prepared_ref, receipt_name)
            or entry_exists(consumed_receipts_ref, receipt_name)
        )
    except BaseException:
        prepared_ref.close()
        consumed_receipts_ref.close()
        raise
    try:
        verifier = verify_published_entry if has_protected_receipt else verify_entry
        capability = verifier(
            str(repository),
            str(workspace),
            request,
            request["controlBodySha256"],
            authority_locked=True,
        )
    except (CapabilityError, OSError, ValueError) as exc:
        failure = (
            MigrationError if has_protected_receipt else RejectedMigration
        )
        prepared_ref.close()
        consumed_receipts_ref.close()
        raise failure(f"Team Lead migration capability rejected: {exc}") from exc
    if capability.get("executionKind") != "gate" or capability.get("role") != request.get("actor"):
        failure = MigrationError if has_protected_receipt else RejectedMigration
        prepared_ref.close()
        consumed_receipts_ref.close()
        raise failure("lineage migration staging lacks an authenticated gate owner")
    if not has_protected_receipt and request["expiresAt"] <= int(time.time()):
        prepared_ref.close()
        consumed_receipts_ref.close()
        raise RejectedMigration("lineage migration control expired")
    lock_name = f".{request['id']}.lock"
    try:
        descriptor = os.open(
            lock_name,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=prepared_ref.descriptor,
        )
    except BaseException:
        prepared_ref.close()
        consumed_receipts_ref.close()
        raise
    execution_descriptor = -1
    execution_ref: DirectoryRef | None = None
    workspace_ref: DirectoryRef | None = None
    own_workspace_ref = False
    state_snapshot: ExactStateSnapshot | None = None
    try:
        lock_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise MigrationError("migration transaction lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        validate_lock_entry(
            prepared_ref, lock_name, descriptor, "migration transaction lock"
        )
        if task_source is not None and task_source[0].path == workspace:
            workspace_ref = task_source[0]
        else:
            workspace_ref = open_directory_ref(
                workspace, "lineage migration workspace"
            )
            own_workspace_ref = True
        execution_ref = open_child_directory_ref(
            workspace_ref, "executions", "migration execution directory"
        )
        execution_directory = execution_ref.path
        execution_lock = execution_directory / f".{request['taskKey']}.transaction.lock"
        execution_descriptor = os.open(
            execution_lock.name,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=execution_ref.descriptor,
        )
        fcntl.flock(execution_descriptor, fcntl.LOCK_EX)
        validate_lock_entry(
            execution_ref,
            execution_lock.name,
            execution_descriptor,
            "execution transaction lock",
        )

        def validate_locks() -> None:
            validate_lock_entry(
                prepared_ref, lock_name, descriptor, "migration transaction lock"
            )
            validate_lock_entry(
                execution_ref,
                execution_lock.name,
                execution_descriptor,
                "execution transaction lock",
            )

        prepared_receipt = None
        if entry_exists(consumed_receipts_ref, receipt_name):
            consumed_receipt_raw, _ = regular_bytes_at(
                consumed_receipts_ref, receipt_name, "consumed migration receipt"
            )
            consumed_receipt = decode(
                consumed_receipt_raw, "consumed migration receipt"
            )
            validate_receipt_binding(
                consumed_receipt, "consumed", key, request_raw, request,
                repository, workspace,
            )
            transaction_artifacts = []
            sealed_target_raw: bytes | None = None
            for artifact, expected, label in (
                (
                    backup_path,
                    consumed_receipt["executionBytesSha256"],
                    "protected legacy execution backup",
                ),
                (
                    target_artifact_path,
                    consumed_receipt["targetExecutionSha256"],
                    "protected migration target artifact",
                ),
            ):
                if entry_exists(prepared_ref, artifact.name):
                    artifact_raw, _ = regular_bytes_at(
                        prepared_ref, artifact.name, label
                    )
                    if digest(artifact_raw) != expected:
                        raise MigrationError(f"{label} is not bound to the consumed receipt")
                    transaction_artifacts.append((artifact, artifact_raw, label))
                    if artifact == target_artifact_path:
                        sealed_target_raw = artifact_raw
            try:
                consumed_execution_raw, _ = regular_bytes_at(
                    execution_ref, execution_name, "consumed migration target"
                )
            except MigrationError:
                consumed_execution_raw = None
            if (
                consumed_execution_raw is None
                or digest(consumed_execution_raw)
                != consumed_receipt["targetExecutionSha256"]
            ):
                if sealed_target_raw is None:
                    raise MigrationError(
                        "consumed migration target changed without sealed recovery authority"
                    )
                repair_consumed_projection(
                    execution_path,
                    target_artifact_path,
                    sealed_target_raw,
                    execution_ref,
                    prepared_ref,
                )
            if entry_exists(prepared_ref, receipt_name):
                stale_prepared_raw, _ = regular_bytes_at(
                    prepared_ref, receipt_name, "stale prepared migration receipt"
                )
                stale_prepared = decode(
                    stale_prepared_raw, "stale prepared migration receipt"
                )
                validate_receipt_binding(
                    stale_prepared, "prepared", key, request_raw, request,
                    repository, workspace,
                )
                if stale_prepared.get("targetExecutionSha256") != consumed_receipt.get("targetExecutionSha256"):
                    raise MigrationError("prepared/consumed receipt target collision")
                unlink_exact_entry(
                    prepared_ref,
                    receipt_name,
                    stale_prepared_raw,
                    "stale prepared migration receipt",
                )
            for artifact, artifact_raw, label in transaction_artifacts:
                retire_transaction_artifact(
                    artifact, artifact_raw, label, directory=prepared_ref
                )
            consume_control(
                control_path,
                consumed_controls,
                rejected_controls,
                request_raw,
                control_info,
                pending_controls,
            )
            return "already-consumed"
        if entry_exists(prepared_ref, receipt_name):
            prepared_receipt_raw, _ = regular_bytes_at(
                prepared_ref, receipt_name, "prepared migration receipt"
            )
            prepared_receipt = decode(
                prepared_receipt_raw, "prepared migration receipt"
            )
            validate_receipt_binding(
                prepared_receipt, "prepared", key, request_raw, request,
                repository, workspace,
            )
            if entry_exists(prepared_ref, backup_name):
                try:
                    protected_raw, _ = regular_bytes_at(
                        prepared_ref,
                        backup_name,
                        "protected legacy execution backup",
                    )
                except MigrationError as exc:
                    raise MigrationError(
                        "protected migration recovery found an unsafe displaced execution"
                    ) from exc
                if digest(protected_raw) != prepared_receipt["executionBytesSha256"]:
                    raise MigrationError(
                        "protected legacy execution backup is not receipt-bound"
                    )
                try:
                    recovery_target, _ = regular_bytes_at(
                        prepared_ref,
                        target_artifact_name,
                        "protected migration target artifact",
                    )
                except MigrationError as exc:
                    raise MigrationError(
                        "prepared migration target artifact is unavailable"
                    ) from exc
                if digest(recovery_target) != prepared_receipt["targetExecutionSha256"]:
                    raise MigrationError(
                        "prepared migration target artifact is not bound to its receipt"
                    )
                recovery_execution = decode(
                    protected_raw, "protected legacy execution backup"
                )
                install_execution_transaction(
                    execution_path, backup_path, target_artifact_path,
                    protected_raw, recovery_target,
                    before_commit=lambda: require_non_live_generation(
                        repository,
                        workspace,
                        lifecycle_root,
                        request,
                        recovery_execution,
                        expected=prepared_receipt["lifecycle"],
                    ),
                    execution_directory=execution_ref,
                    protected_directory=prepared_ref,
                )
                consumed_unsigned = dict(prepared_receipt)
                consumed_unsigned.pop("auth")
                consumed_unsigned["phase"] = "consumed"
                store_receipt(
                    consumed_path,
                    consumed_unsigned,
                    key,
                    directory=consumed_receipts_ref,
                )
                repair_consumed_projection(
                    execution_path,
                    target_artifact_path,
                    recovery_target,
                    execution_ref,
                    prepared_ref,
                )
                retire_transaction_artifact(
                    backup_path,
                    protected_raw,
                    "protected legacy execution backup",
                    directory=prepared_ref,
                )
                retire_transaction_artifact(
                    target_artifact_path,
                    recovery_target,
                    "protected migration target artifact",
                    directory=prepared_ref,
                )
                unlink_exact_entry(
                    prepared_ref,
                    receipt_name,
                    prepared_receipt_raw,
                    "prepared migration receipt",
                )
                consume_control(
                    control_path,
                    consumed_controls,
                    rejected_controls,
                    request_raw,
                    control_info,
                    pending_controls,
                )
                return "consumed"
            current_raw, _ = regular_bytes_at(
                execution_ref, execution_name, "prepared migration execution"
            )
            current_digest = digest(current_raw)
            if current_digest == prepared_receipt["targetExecutionSha256"]:
                fsync_ref(execution_ref)
                target_artifact_raw = None
                if entry_exists(prepared_ref, target_artifact_name):
                    target_artifact_raw, _ = regular_bytes_at(
                        prepared_ref,
                        target_artifact_name,
                        "protected migration target artifact",
                    )
                    if target_artifact_raw != current_raw:
                        raise MigrationError(
                            "protected migration target artifact is not the installed target"
                        )
                consumed_unsigned = dict(prepared_receipt)
                consumed_unsigned.pop("auth")
                consumed_unsigned["phase"] = "consumed"
                store_receipt(
                    consumed_path,
                    consumed_unsigned,
                    key,
                    directory=consumed_receipts_ref,
                )
                if target_artifact_raw is None:
                    raise MigrationError(
                        "installed migration target lacks sealed recovery authority"
                    )
                repair_consumed_projection(
                    execution_path,
                    target_artifact_path,
                    target_artifact_raw,
                    execution_ref,
                    prepared_ref,
                )
                if target_artifact_raw is not None:
                    retire_transaction_artifact(
                        target_artifact_path,
                        target_artifact_raw,
                        "protected migration target artifact",
                        directory=prepared_ref,
                    )
                unlink_exact_entry(
                    prepared_ref,
                    receipt_name,
                    prepared_receipt_raw,
                    "prepared migration receipt",
                )
                consume_control(
                    control_path,
                    consumed_controls,
                    rejected_controls,
                    request_raw,
                    control_info,
                    pending_controls,
                )
                return "consumed"
            if current_digest != prepared_receipt["executionBytesSha256"]:
                raise MigrationError("prepared migration observed neither exact old nor exact target bytes")
            if request["expiresAt"] <= int(time.time()):
                # No execution name has moved yet, so expiry revokes prepare.
                # Retire only receipt-bound protected artifacts, then let the
                # reconciler quarantine the expired request and free its stable
                # pathname for a newly authenticated Team Lead request.
                if entry_exists(prepared_ref, target_artifact_name):
                    target_artifact_raw, _ = regular_bytes_at(
                        prepared_ref,
                        target_artifact_name,
                        "expired prepared migration target artifact",
                    )
                    if digest(target_artifact_raw) != prepared_receipt[
                        "targetExecutionSha256"
                    ]:
                        raise MigrationError(
                            "expired prepared migration target artifact is not receipt-bound"
                        )
                    retire_transaction_artifact(
                        target_artifact_path,
                        target_artifact_raw,
                        "expired prepared migration target artifact",
                        directory=prepared_ref,
                    )
                unlink_exact_entry(
                    prepared_ref,
                    receipt_name,
                    prepared_receipt_raw,
                    "prepared migration receipt",
                )
                raise RejectedMigration(
                    "lineage migration control expired before execution transition"
                )
        # Freshness is authority for prepare/apply only. Once exact target bytes
        # have a protected receipt, the branches above consume/idempotently
        # retire without reinterpreting later tracker, registry, or lifecycle drift.
        authorization_task = task_from_snapshot(
            tasks, str(request["authorizationTaskId"])
        )
        preflight_contract = registered_contract(
            workspace, directory=workspace_ref
        )
        if (
            request["authorizationTaskId"] != preflight_contract["taskId"]
            or request["contractRegistrySha256"]
            != preflight_contract["contractRegistrySha256"]
            or request["contractEntrySha256"]
            != preflight_contract["contractEntrySha256"]
        ):
            raise MigrationError(
                "migration authorization is not bound to the registered contract owner"
            )
        if (
            authorization_task["revision"] != request["authorizationTaskRevision"]
            or authorization_task["status"] != request["authorizationTaskStatus"]
        ):
            raise MigrationError(
                "authorization task revision/status changed after Team Lead staging"
            )
        if authorization_task["status"] != integrated_task_status():
            raise MigrationError(
                "migration authorization task is not an integrated exact package"
            )
        try:
            execution_raw, execution, _, state = exact_state(
                workspace,
                tasks,
                request,
                workspace_directory=workspace_ref,
                execution_directory=execution_ref,
                task_source=task_source,
            )
        except ClaimAuthorityError as exc:
            failure = (
                MigrationError if prepared_receipt is not None else RejectedMigration
            )
            raise failure(str(exc)) from exc
        state_snapshot = state["snapshot"]
        contract = state["contract"]
        roles = protocol_roles(
            repository,
            workspace,
            str(request["team"]),
            str(request["featureId"]),
            workspace_directory=workspace_ref,
            snapshot=state_snapshot,
        )
        if request.get("actor") != roles["TEAM_LEAD"]:
            failure = MigrationError if prepared_receipt is not None else RejectedMigration
            raise failure(
                "only the authenticated configured Team Lead may stage migration"
            )
        if (
            request["authorizationTaskId"] != contract["taskId"]
            or request["contractRegistrySha256"]
            != contract["contractRegistrySha256"]
            or request["contractEntrySha256"] != contract["contractEntrySha256"]
        ):
            raise MigrationError(
                "migration authorization is not bound to the registered contract owner"
            )
        if request["expiresAt"] <= int(time.time()) and not state["installedTarget"]:
            raise RejectedMigration(
                "lineage migration control expired before prepare"
            )
        lineage = state["lineage"]
        target = dict(execution)
        target["claimLineage"] = lineage
        target["lineageDigest"] = digest(canonical(lineage))
        if set(target) - set(execution) != {"claimLineage", "lineageDigest"}:
            raise MigrationError("migration target violates the exact two-field invariant")
        if any(target[name] != execution[name] for name in execution):
            raise MigrationError("migration target changed a pre-existing field")
        target_raw = canonical(target) + b"\n"
        verdicts = current_verdicts(
            repository,
            workspace,
            request,
            authorization_task,
            roles,
            snapshot=state_snapshot,
            authority_locked=True,
        )
        generation = require_non_live_generation(
            repository, workspace, lifecycle_root, request, execution
        )
        validate_locks()
        state_snapshot.validate()
        unsigned = {
            "schemaVersion": 1, "domain": "lineageMigration/v1",
            "phase": "prepared", "repository": str(repository),
            "workspace": str(workspace), "team": request["team"],
            "featureId": request["featureId"], "taskId": request["taskId"],
            "taskKey": request["taskKey"], "role": execution["role"],
            "stagedBy": request["actor"],
            "authorizationTaskId": request["authorizationTaskId"],
            "authorizationTaskRevision": request["authorizationTaskRevision"],
            "authorizationTaskStatus": request["authorizationTaskStatus"],
            "contractRegistrySha256": request["contractRegistrySha256"],
            "contractEntrySha256": request["contractEntrySha256"],
            "controlId": request["id"], "controlSha256": digest(request_raw),
            "claimBytesSha256": request["observedClaimSha256"],
            "executionBytesSha256": request["observedExecutionSha256"],
            "oldCanonicalSha256": digest(canonical(execution)),
            "targetExecutionSha256": digest(target_raw),
            "trackerRevision": request["observedTaskRevision"],
            "trackerStatus": request["observedTaskStatus"],
            "branch": request["branch"], "worktree": request["worktree"],
            "head": request["head"], "packetPath": request["packetPath"],
            "packetSha256": request["packetSha256"],
            "packetJsonPath": request["packetJsonPath"],
            "packetJsonSha256": request["packetJsonSha256"],
            "reportPath": request["reportPath"],
            "reportSha256": request["reportSha256"],
            "lifecycle": generation, "claimLineage": lineage,
            "lineageDigest": target["lineageDigest"], "verdicts": verdicts,
            "expiresAt": request["expiresAt"],
        }
        if prepared_receipt is not None:
            if prepared_receipt != {
                **unsigned,
                "auth": "hmac-sha256:" + hmac.new(
                    key, DOMAIN + canonical(unsigned), hashlib.sha256
                ).hexdigest(),
            } or not authenticated(prepared_receipt, key):
                raise MigrationError(
                    "prepared migration receipt no longer binds exact current evidence"
                )
        else:
            if state["installedTarget"]:
                raise MigrationError("target bytes exist without a protected prepared receipt")
            require_same_transaction_device(
                execution_path,
                prepared,
                execution_directory=execution_ref,
                protected_directory=prepared_ref,
            )
            validate_locks()
            state_snapshot.validate()
            prepared_receipt = store_receipt(
                prepared_path, unsigned, key, directory=prepared_ref
            )
            prepared_receipt_raw, _ = regular_bytes_at(
                prepared_ref, receipt_name, "prepared migration receipt"
            )

        current_raw, _ = regular_bytes_at(
            execution_ref, execution_name, "legacy execution"
        )
        current_digest = digest(current_raw)
        if current_digest == unsigned["executionBytesSha256"]:
            def validate_commit_authority() -> None:
                validate_locks()
                state_snapshot.validate()
                require_non_live_generation(
                    repository,
                    workspace,
                    lifecycle_root,
                    request,
                    execution,
                    expected=generation,
                )

            install_execution_transaction(
                execution_path, backup_path, target_artifact_path,
                execution_raw, target_raw,
                before_commit=validate_commit_authority,
                execution_directory=execution_ref,
                protected_directory=prepared_ref,
            )
        elif current_digest != unsigned["targetExecutionSha256"]:
            raise MigrationError("prepared migration observed neither exact old nor exact target bytes")

        installed_raw, _ = regular_bytes_at(
            execution_ref, execution_name, "migration target"
        )
        if digest(installed_raw) != unsigned["targetExecutionSha256"]:
            raise MigrationError("migration target was not durably installed")
        consumed_unsigned = {**unsigned, "phase": "consumed"}
        store_receipt(
            consumed_path,
            consumed_unsigned,
            key,
            directory=consumed_receipts_ref,
        )
        repair_consumed_projection(
            execution_path,
            target_artifact_path,
            target_raw,
            execution_ref,
            prepared_ref,
        )
        retire_transaction_artifact(
            backup_path,
            execution_raw,
            "protected legacy execution backup",
            directory=prepared_ref,
        )
        retire_transaction_artifact(
            target_artifact_path,
            target_raw,
            "protected migration target artifact",
            directory=prepared_ref,
        )
        unlink_exact_entry(
            prepared_ref,
            receipt_name,
            prepared_receipt_raw,
            "prepared migration receipt",
        )
        consume_control(
            control_path,
            consumed_controls,
            rejected_controls,
            request_raw,
            control_info,
            pending_controls,
        )
        return "consumed"
    finally:
        if state_snapshot is not None:
            state_snapshot.close()
        if execution_descriptor >= 0:
            os.close(execution_descriptor)
        if execution_ref is not None:
            execution_ref.close()
        if workspace_ref is not None and own_workspace_ref:
            workspace_ref.close()
        os.close(descriptor)
        prepared_ref.close()
        consumed_receipts_ref.close()


def bounded_pending_batch(
    pending: DirectoryRef,
) -> tuple[list[tuple[Path, os.stat_result | None]], bool]:
    """Select one bounded pass without materializing an attacker-sized queue."""

    selected: list[tuple[Path, os.stat_result | None]] = []
    retained = False
    with os.scandir(pending.descriptor) as entries:
        for entry in entries:
            if len(selected) >= MAX_MIGRATION_REQUESTS_PER_PASS:
                retained = True
                break
            try:
                info = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                info = None
            selected.append((pending.path / entry.name, info))
    return sorted(selected, key=lambda item: item[0].name), retained


def reject_pending_entry(
    path: Path,
    rejected: DirectoryRef,
    detail: str,
    raw: bytes | None = None,
    expected_info: os.stat_result | None = None,
    source_directory: DirectoryRef | None = None,
) -> Path | None:
    """Durably quarantine one raw untrusted name without following it."""

    own_source = source_directory is None
    source_directory = source_directory or open_directory_ref(
        path.parent, "pending lineage migration controls"
    )
    if path.parent != source_directory.path:
        if own_source:
            source_directory.close()
        raise MigrationError("rejected pending entry parent is cross-bound")
    current = entry_stat(source_directory, path.name)
    if current is None:
        if own_source:
            source_directory.close()
        print(
            f"lineage-migration: raced {path.name}: vanished before rejection",
            file=sys.stderr,
        )
        return None
    if expected_info is not None and (current.st_dev, current.st_ino) != (
        expected_info.st_dev,
        expected_info.st_ino,
    ):
        if own_source:
            source_directory.close()
        print(
            f"lineage-migration: raced {path.name}: replaced before rejection",
            file=sys.stderr,
        )
        return None
    identity = hashlib.sha256()
    identity.update(os.fsencode(path.name))
    identity.update(b"\0")
    if raw is not None:
        identity.update(hashlib.sha256(raw).digest())
    else:
        try:
            info = current
        except OSError as exc:
            if own_source:
                source_directory.close()
            raise MigrationError(
                f"cannot inspect rejected lineage migration entry: {exc}"
            ) from exc
        identity.update(f"{info.st_mode}:{info.st_size}".encode("ascii"))
    stem = f"rejected-{identity.hexdigest()[:32]}"
    destination = rejected.path / f"{stem}.entry"
    if entry_exists(rejected, destination.name):
        destination = rejected.path / f"{stem}-{secrets.token_hex(8)}.entry"
    try:
        rename_no_replace(
            path,
            destination,
            "quarantine lineage migration pending entry",
            source_directory=source_directory,
            destination_directory=rejected,
        )
    except MigrationError as exc:
        if not entry_exists(source_directory, path.name):
            # The descriptor-relative move may have completed before a final
            # pathname-binding check noticed a parent swap.  Persist the safe
            # retained destination before treating that event as a race.
            if entry_exists(rejected, destination.name):
                fsync_ref(rejected)
                fsync_ref(source_directory)
            if own_source:
                source_directory.close()
            print(
                f"lineage-migration: raced {path.name}: vanished during rejection",
                file=sys.stderr,
            )
            return None
        if own_source:
            source_directory.close()
        raise exc
    # The no-replace helper made the destination durable before acknowledging
    # retirement of the attacker-writable pending name.
    moved = entry_stat(rejected, destination.name)
    exact = moved is not None and (
        expected_info is None
        or (moved.st_dev, moved.st_ino)
        == (expected_info.st_dev, expected_info.st_ino)
    )
    if raw is not None:
        try:
            moved_raw, moved_info = regular_bytes_at(
                rejected, destination.name, "rejected lineage migration control"
            )
        except MigrationError:
            moved_raw = None
            moved_info = None
        exact = exact and moved_raw == raw and moved_info is not None
    assert_directory_binding(rejected)
    assert_directory_binding(source_directory)
    print(
        f"lineage-migration: rejected {path.name}: {detail}", file=sys.stderr
    )
    if own_source:
        source_directory.close()
    return destination if exact else None


def validate_pending_request(
    path: Path, raw: bytes, tasks: dict[str, Any]
) -> None:
    request = decode(raw, "lineage migration control")
    validate_request(request)
    if path.name != f"{request['id']}.json":
        raise RejectedMigration("lineage migration control filename mismatch")
    if (
        request["team"] != tasks.get("team", request["team"])
        or request["featureId"] != tasks.get("featureId")
    ):
        raise RejectedMigration("lineage migration control is cross-bound")


def reconcile(args: argparse.Namespace) -> int:
    if os.environ.get("STARTUP_FACTORY_LINEAGE_MIGRATION_BROKER") != "1":
        raise MigrationError("direct invocation is forbidden; deterministic broker authorization is required")
    repository = canonical_directory(args.repo, "canonical repository")
    workspace = canonical_directory(args.workspace, "canonical workspace")
    lifecycle_root = canonical_directory(args.lifecycle_root, "protected lifecycle root")
    if os.path.commonpath((str(repository), str(workspace))) != str(repository):
        raise MigrationError("canonical workspace escapes canonical repository")
    tasks_path = Path(args.tasks)
    expected_tasks = workspace / "tasks.json"
    try:
        tasks_resolved = tasks_path.resolve(strict=True)
    except OSError as exc:
        raise MigrationError(f"fresh task snapshot is unavailable: {exc}") from exc
    if tasks_path != expected_tasks or tasks_resolved != expected_tasks or tasks_path.is_symlink():
        raise MigrationError("fresh task snapshot must be the canonical workspace/tasks.json")
    tasks_directory = open_directory_ref(
        workspace, "fresh task snapshot workspace"
    )
    try:
        tasks_raw, tasks_info = regular_bytes_at(
            tasks_directory,
            tasks_path.name,
            "fresh task snapshot",
            64 * 1024 * 1024,
        )
        tasks = decode(tasks_raw, "fresh task snapshot")
    except BaseException:
        tasks_directory.close()
        raise
    if tasks.get("featureId") != args.feature or tasks.get("team") not in {None, args.team}:
        tasks_directory.close()
        raise MigrationError("fresh task snapshot is cross-bound")
    pending_path = workspace / "lineage-migration-outbox" / "pending"
    if not pending_path.exists() and not pending_path.is_symlink():
        tasks_directory.close()
        return 0
    try:
        queues = migration_queue_refs(workspace)
    except BaseException:
        tasks_directory.close()
        raise
    pending, consumed, rejected = queues
    try:
        paths, retained = bounded_pending_batch(pending)
        for path, selected_info in paths:
            raw: bytes | None = None
            opened_info: os.stat_result | None = None
            control_descriptor = -1
            try:
                if not re.fullmatch(r"control-[0-9a-f]{32}[.]json", path.name):
                    raise RejectedMigration(
                        "lineage migration pending queue contains an unexpected entry"
                    )
                control_descriptor, raw, opened_info = open_bound_bytes_at(
                    pending,
                    path.name,
                    "lineage migration control",
                    MAX_MIGRATION_REQUEST_BYTES,
                )
                if selected_info is None or (
                    selected_info.st_dev,
                    selected_info.st_ino,
                ) != (opened_info.st_dev, opened_info.st_ino):
                    retained = True
                    print(
                        f"lineage-migration: raced {path.name}: replaced before read",
                        file=sys.stderr,
                    )
                    os.close(control_descriptor)
                    control_descriptor = -1
                    continue
                validate_pending_request(path, raw, tasks)
            except MigrationError as exc:
                if control_descriptor >= 0:
                    os.close(control_descriptor)
                    control_descriptor = -1
                if reject_pending_entry(
                    path,
                    rejected,
                    str(exc),
                    raw,
                    opened_info or selected_info,
                    pending,
                ) is None:
                    retained = True
                continue
            try:
                outcome = migrate_bound_request(
                    repository,
                    workspace,
                    lifecycle_root,
                    tasks,
                    path,
                    raw,
                    opened_info,
                    queues,
                    task_source=(
                        tasks_directory,
                        tasks_path.name,
                        tasks_raw,
                        tasks_info,
                    ),
                )
            except RejectedMigration as exc:
                if reject_pending_entry(
                    path,
                    rejected,
                    str(exc),
                    raw,
                    opened_info,
                    pending,
                ) is None:
                    retained = True
                continue
            except (
                MigrationError,
                OSError,
                subprocess.SubprocessError,
                ValueError,
            ) as exc:
                retained = True
                print(
                    f"lineage-migration: deferred {path.name}: {exc}",
                    file=sys.stderr,
                )
                continue
            finally:
                if control_descriptor >= 0:
                    os.close(control_descriptor)
            print(f"{path.name}: {outcome}")
    finally:
        for directory in queues:
            directory.close()
        tasks_directory.close()
    if retained:
        print("lineage-migration: bounded pending entries retained", file=sys.stderr)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    command = sub.add_parser("reconcile")
    command.add_argument("--repo", required=True)
    command.add_argument("--workspace", required=True)
    command.add_argument("--team", required=True)
    command.add_argument("--feature", required=True)
    command.add_argument("--tasks", required=True)
    command.add_argument("--lifecycle-root", required=True)
    command.set_defaults(func=reconcile)
    return result


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MigrationError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"lineage-migration: {exc}", file=sys.stderr)
        raise SystemExit(1)
