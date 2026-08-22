#!/usr/bin/env python3
"""Run exact standalone validation through the manifest-bound protected runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


COMMIT = re.compile(r"[0-9a-f]{40,64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
VALIDATION_KEYS = (
    "VALIDATE_SCRIPT",
    "VALIDATE_BUILD",
    "VALIDATE_TEST",
    "VALIDATE_LINT",
    "VALIDATE_FORMAT",
)


class ValidationError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 120,
    strip: bool = True,
) -> str:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError("protected validation command was unavailable") from exc
    if result.returncode:
        safe_detail = ""
        for line in reversed(result.stderr.splitlines()):
            if line.startswith(("startup-factory-runner:", "runtime-static-verify:", "standalone-workspace:")):
                safe_detail = ": " + line[:512]
                break
        raise ValidationError("protected validation command failed closed" + safe_detail)
    return result.stdout.strip() if strip else result.stdout


def git(repository: Path, *argv: str) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    return run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(repository), *argv],
        env=environment,
    )


def read_regular(path: Path, label: str, maximum: int = 2 * 1024 * 1024) -> bytes:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ValidationError(f"{label} path is not canonical")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ValidationError(f"{label} is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ValidationError(f"{label} path contains a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > maximum:
            raise ValidationError(f"{label} must be a bounded single-link regular file")
        content = bytearray()
        while len(content) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > maximum:
            raise ValidationError(f"{label} exceeds its size limit")
        return bytes(content)
    finally:
        os.close(descriptor)


def read_config(path: Path) -> dict[str, str]:
    content = read_regular(path.resolve(strict=True), "team configuration").decode("utf-8")
    wanted = set(VALIDATION_KEYS) | {"AGENT_SANDBOX_ENFORCED", "TASK_WORKTREE_MODE"}
    values: dict[str, str] = {}
    for line in content.splitlines():
        if "=" not in line:
            continue
        name, raw = line.split("=", 1)
        if name not in wanted:
            continue
        if name in values:
            raise ValidationError(f"duplicate validation configuration key: {name}")
        value = raw.split(" #", 1)[0].strip()
        if value.startswith('"'):
            if value.count('"') < 2:
                raise ValidationError(f"malformed quoted validation configuration: {name}")
            value = value[1 : value.rfind('"')]
        if value == "null":
            value = ""
        values[name] = value
    if set(values) != wanted:
        raise ValidationError("validation/runtime configuration is incomplete")
    if values["AGENT_SANDBOX_ENFORCED"] != "true" or values["TASK_WORKTREE_MODE"] != "standalone-clone":
        raise ValidationError("governed validation requires enforced standalone runtime mode")
    return values


def changed_files(repository: Path, base: str, source_ref: str) -> list[str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    raw = run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(repository),
         "diff", "--name-only", "-z", f"{base}..{source_ref}"],
        env=environment,
        strip=False,
    )
    values = raw.split("\0") if raw else []
    result: list[str] = []
    for value in values:
        if not value:
            continue
        path = PurePosixPath(value)
        if (
            len(value.encode()) > 4096
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValidationError("changed-file list contains an unsafe path")
        result.append(value)
    if not result or len(result) > 10000 or len(result) != len(set(result)):
        raise ValidationError("changed-file list is empty, duplicated, or oversized")
    return result


def script_argv(clone: Path, configured: str, files: list[str]) -> list[str]:
    path = PurePosixPath(configured)
    if (
        not configured
        or len(configured.encode()) > 4096
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 33 or ord(character) == 127 for character in configured)
    ):
        raise ValidationError("VALIDATE_SCRIPT must be one safe repository-relative executable path")
    candidate = clone.joinpath(*path.parts)
    current = clone
    for part in path.parts:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ValidationError("VALIDATE_SCRIPT is unavailable in the validation clone") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ValidationError("VALIDATE_SCRIPT contains a symlink")
    info = candidate.lstat()
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ValidationError("VALIDATE_SCRIPT is not an executable regular file")
    return [str(candidate), *files]


def write_evidence(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or read_regular(path, "validation evidence") != content:
            raise ValidationError("existing validation evidence does not match the exact result")
        return
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def validate(args: argparse.Namespace) -> dict[str, Any]:
    skill_root = Path(__file__).resolve().parent.parent
    repository = Path(args.repo).resolve(strict=True)
    workspace = Path(args.workspace).resolve(strict=True)
    execution_path = Path(args.execution).resolve(strict=True)
    if not COMMIT.fullmatch(args.base) or not COMMIT.fullmatch(args.head):
        raise ValidationError("validation base/head is not a full commit identity")
    changed_base = args.changed_base or args.base
    changed_ref = args.changed_ref or args.source_ref
    if not COMMIT.fullmatch(changed_base):
        raise ValidationError("validation changed-file base is not a full commit identity")
    if git(repository, "rev-parse", "--verify", f"{args.source_ref}^{{commit}}") != args.head:
        raise ValidationError("quarantine ref no longer resolves to the imported head")
    changed_head = git(repository, "rev-parse", "--verify", f"{changed_ref}^{{commit}}")
    if not COMMIT.fullmatch(changed_head):
        raise ValidationError("changed-file source does not resolve to a full commit identity")
    imported_tree = git(repository, "rev-parse", f"{args.source_ref}^{{tree}}")
    if not COMMIT.fullmatch(imported_tree):
        raise ValidationError("imported tree identity is invalid")
    execution = json.loads(read_regular(execution_path, "execution record").decode("utf-8"))
    expected_execution = {
        "schemaVersion": 1,
        "taskId": args.task,
        "taskKey": args.task_key,
        "attempt": args.attempt,
        "worktreeMode": "standalone-clone",
        "baseCommit": args.base,
    }
    if not isinstance(execution, dict) or any(execution.get(key) != value for key, value in expected_execution.items()):
        raise ValidationError("execution record does not bind the governed validation request")
    runtime_digest = execution.get("runtimeManifestDigest") if isinstance(execution, dict) else None
    if not isinstance(runtime_digest, str) or not DIGEST.fullmatch(runtime_digest):
        raise ValidationError("execution record lacks a runtime manifest digest")
    config = read_config(skill_root / "config/team.config.md")
    verified = json.loads(run([sys.executable, str(skill_root / "bin/runtime-static-verify.py"), "--target", str(skill_root)]))
    if verified.get("manifestDigest") != runtime_digest:
        raise ValidationError("execution/runtime manifest digest mismatch")
    runner = Path(str(verified.get("runner") or ""))
    clone_root = Path(str(verified.get("cloneRoot") or ""))
    if not runner.is_absolute() or not clone_root.is_absolute():
        raise ValidationError("runtime verifier returned incomplete protected paths")
    files = changed_files(repository, changed_base, changed_ref)
    validation_config = {name: config[name] for name in VALIDATION_KEYS}
    config_digest = digest(canonical(validation_config))
    evidence_name = (
        f"governed-validation-{args.stage}-{args.head}-{runtime_digest[7:23]}-"
        f"{config_digest[7:23]}.json"
    )
    evidence_path = workspace / "artifacts" / args.task_key / evidence_name
    result_rows: list[dict[str, str]] = []
    selected = [(name, validation_config[name]) for name in VALIDATION_KEYS if validation_config[name]]
    if validation_config["VALIDATE_SCRIPT"]:
        selected = [("VALIDATE_SCRIPT", validation_config["VALIDATE_SCRIPT"])]
    if not selected:
        raise ValidationError("governed integration has no configured validation command")
    record = {
        "schemaVersion": 1,
        "authority": "governed-standalone-validation",
        "validationStage": args.stage,
        "team": args.team,
        "taskId": args.task,
        "taskKey": args.task_key,
        "attempt": args.attempt,
        "quarantineRef": args.source_ref,
        "importedCommit": args.head,
        "importedTree": imported_tree,
        "runtimeManifestSha256": runtime_digest,
        "runtimeProfile": verified.get("profile"),
        "runtimeImage": verified.get("image"),
        "validationConfigSha256": config_digest,
        "changedFilesSha256": digest(canonical(files)),
        "changedFilesCount": len(files),
        "network": "none",
        "mounts": ["validation-clone-rw", "skill-root-ro"],
        "scopedCapabilities": [],
        "canonicalRepositoryMounted": False,
        "producerCloneMounted": False,
        "results": [
            {"name": name, "commandSha256": digest(value.encode()), "status": "passed"}
            for name, value in selected
        ],
    }
    evidence_content = canonical(record)
    if evidence_path.exists():
        write_evidence(evidence_path, evidence_content)
        return {"path": str(evidence_path), "sha256": digest(evidence_content), "record": record, "reused": True}

    validation_key = f"{args.task_key[:64]}-{args.stage}-validation-{args.head[:16]}"
    validation_branch = f"startup-factory-validation/{args.head[:32]}"
    helper = skill_root / "bin/standalone_workspace.py"
    created = json.loads(
        run(
            [
                sys.executable,
                str(helper),
                "create",
                "--repo",
                str(repository),
                "--root",
                str(clone_root),
                "--team",
                args.team,
                "--role",
                "integration-validator",
                "--attempt",
                str(args.attempt),
                "--task-key",
                validation_key,
                "--branch",
                validation_branch,
                "--base-ref",
                args.head,
            ]
        )
    )
    clone = Path(str(created.get("path") or ""))
    if created.get("headCommit") != args.head or created.get("tree") != imported_tree:
        raise ValidationError("disposable validation clone does not bind the imported head/tree")
    host_environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "AWS_EC2_METADATA_DISABLED": "true",
        "STARTUP_FACTORY_AGENT_WORKTREE": str(clone),
        "STARTUP_FACTORY_TASK_WORKTREE": str(clone),
        "STARTUP_FACTORY_SKILL_ROOT": str(skill_root),
        "STARTUP_FACTORY_ROLE": "integrator",
        "STARTUP_FACTORY_TEAM": args.team,
        "STARTUP_FACTORY_EXECUTION_KIND": "validation",
        "STARTUP_FACTORY_TASK_ID": args.task,
        "STARTUP_FACTORY_ATTEMPT": str(args.attempt),
    }
    command_prefix = [
        str(runner),
        "--workdir",
        str(clone),
        "--",
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "HOME=/home/agent",
        "AWS_EC2_METADATA_DISABLED=true",
    ]
    clone_verified = False
    try:
        for name, value in selected:
            if name == "VALIDATE_SCRIPT":
                command = script_argv(clone, value, files)
            else:
                command = ["/bin/bash", "-c", value]
            try:
                run(command_prefix + command, cwd=clone, env=host_environment, timeout=1800)
            except ValidationError:
                raise
        observed = json.loads(
            run(
                [
                    sys.executable,
                    str(helper),
                    "validate",
                    "--clone",
                    str(clone),
                    "--branch",
                    validation_branch,
                    "--base",
                    args.head,
                ]
            )
        )
        if observed.get("headCommit") != args.head or observed.get("tree") != imported_tree:
            raise ValidationError("validation clone moved away from the imported head/tree")
        clone_verified = True
        if git(repository, "rev-parse", "--verify", f"{args.source_ref}^{{commit}}") != args.head:
            raise ValidationError("quarantine ref moved during protected validation")
        if git(repository, "rev-parse", f"{args.source_ref}^{{tree}}") != imported_tree:
            raise ValidationError("quarantine tree moved during protected validation")
        write_evidence(evidence_path, evidence_content)
    finally:
        if clone_verified:
            run(
                [
                    sys.executable,
                    str(helper),
                    "retire",
                    "--repo",
                    str(repository),
                    "--root",
                    str(clone_root),
                    "--clone",
                    str(clone),
                    "--branch",
                    validation_branch,
                ]
            )
    return {"path": str(evidence_path), "sha256": digest(evidence_content), "record": record, "reused": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--execution", required=True)
    parser.add_argument("--team", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--task-key", required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--stage", choices=("task-head", "merged-feature"), default="task-head")
    parser.add_argument("--changed-base")
    parser.add_argument("--changed-ref")
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args), sort_keys=True))
    except (OSError, UnicodeError, ValueError, ValidationError) as exc:
        print(f"governed-validation: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
