#!/usr/bin/env python3
"""Validate the optional Claude/Superpowers planning boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

SKILL_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = SKILL_DIR / "config" / "planning.config.md"
DEFAULTS = {
    "USE_SUPERPOWERS": "true",
    "SUPERPOWERS_PLUGIN_ID": "superpowers@claude-plugins-official",
    "SUPERPOWERS_SPEC_ROOT": "docs/superpowers/specs",
    "SUPERPOWERS_PLAN_ROOT": "docs/superpowers/plans",
}
ALLOWED_KEYS = frozenset(DEFAULTS)
BLOCKED_EXECUTION_SKILLS = (
    "superpowers:using-git-worktrees",
    "superpowers:subagent-driven-development",
    "superpowers:executing-plans",
    "superpowers:finishing-a-development-branch",
)
TEAM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
PLUGIN_RE = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


class PlanningError(RuntimeError):
    """Safe user-facing planning configuration or handoff failure."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanningError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def parse_config(path: Path) -> dict[str, str]:
    values = dict(DEFAULTS)
    if not path.exists():
        return values
    if path.is_symlink() or not path.is_file():
        raise PlanningError(f"planning config is not a regular file: {path}")
    seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PlanningError(f"cannot read planning config: {exc}") from exc
    for raw_line in lines:
        match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", raw_line)
        if not match:
            continue
        key, raw_value = match.groups()
        if key not in ALLOWED_KEYS:
            raise PlanningError(f"unknown planning configuration key: {key}")
        if key in seen:
            raise PlanningError(f"duplicate planning configuration key: {key}")
        seen.add(key)
        value = raw_value.strip()
        if value.startswith('"'):
            closing = value.find('"', 1)
            if closing < 0:
                raise PlanningError(f"unterminated quoted value for {key}")
            trailing = value[closing + 1 :].strip()
            if trailing and not trailing.startswith("#"):
                raise PlanningError(f"unexpected text after quoted value for {key}")
            value = value[1:closing]
        else:
            value = value.split("#", 1)[0].strip()
        values[key] = value
    if values["USE_SUPERPOWERS"] not in {"true", "false"}:
        raise PlanningError("USE_SUPERPOWERS must be exactly true or false")
    if not PLUGIN_RE.fullmatch(values["SUPERPOWERS_PLUGIN_ID"]):
        raise PlanningError("SUPERPOWERS_PLUGIN_ID must be a plugin@marketplace id")
    for key in ("SUPERPOWERS_SPEC_ROOT", "SUPERPOWERS_PLAN_ROOT"):
        values[key] = safe_relative_directory(values[key], key)
    return values


def safe_relative_directory(value: str, label: str) -> str:
    if not value or "\\" in value or any(ord(char) < 32 for char in value):
        raise PlanningError(
            f"{label} must be a normalized repository-relative directory"
        )
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PlanningError(
            f"{label} must be a normalized repository-relative directory"
        )
    normalized = path.as_posix()
    if normalized != value:
        raise PlanningError(
            f"{label} must be a normalized repository-relative directory"
        )
    return normalized


def load_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        raise PlanningError(f"{label} is not a regular file: {path}")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except PlanningError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanningError(f"{label} is not valid UTF-8 JSON: {exc}") from exc


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def run(arguments: list[str], *, cwd: Path | None = None, timeout: int = 30) -> str:
    try:
        process = subprocess.run(
            arguments,
            cwd=os.fspath(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanningError(f"cannot run {' '.join(arguments)}: {exc}") from exc
    if process.returncode:
        detail = process.stderr.strip() or process.stdout.strip() or "unknown error"
        raise PlanningError(f"{' '.join(arguments)} failed: {detail}")
    return process.stdout


def git(repo: Path, *arguments: str) -> str:
    return run(["git", "-C", os.fspath(repo), *arguments], timeout=30).strip()


def canonical_repo(raw: str) -> Path:
    path = Path(raw).expanduser()
    try:
        repo = path.resolve(strict=True)
    except OSError as exc:
        raise PlanningError(f"cannot resolve repository: {exc}") from exc
    if not repo.is_dir():
        raise PlanningError(f"repository is not a directory: {repo}")
    top = Path(git(repo, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if top != repo:
        raise PlanningError(f"--repo must name the repository root: {top}")
    return repo


def repo_file(repo: Path, raw: str, root: str, label: str) -> tuple[Path, str]:
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        if ".." in candidate.parts:
            raise PlanningError(f"{label} must not contain '..'")
        candidate = repo / candidate
    if candidate.is_symlink():
        raise PlanningError(f"{label} must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PlanningError(f"cannot resolve {label}: {exc}") from exc
    try:
        relative = resolved.relative_to(repo).as_posix()
    except ValueError as exc:
        raise PlanningError(f"{label} must remain inside the repository") from exc
    if not resolved.is_file():
        raise PlanningError(f"{label} is not a regular file")
    prefix = root + "/"
    if relative == root or not relative.startswith(prefix):
        raise PlanningError(f"{label} must be below {root}/")
    return resolved, relative


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise PlanningError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def require_committed(repo: Path, relative_paths: list[str]) -> None:
    for relative in relative_paths:
        git(repo, "ls-files", "--error-unmatch", "--", relative)
    dirty = git(repo, "status", "--porcelain=v1", "--", *relative_paths)
    if dirty:
        raise PlanningError("specification and plan must be committed and unmodified")


def plugin_list(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.plugin_list_json:
        payload = load_json(Path(args.plugin_list_json), "Claude plugin list")
    else:
        command = args.claude_command
        if not command or any(char.isspace() for char in command):
            raise PlanningError("--claude-command must be one executable path or name")
        try:
            payload = json.loads(
                run([command, "plugin", "list", "--json"], timeout=30),
                object_pairs_hook=strict_object,
            )
        except json.JSONDecodeError as exc:
            raise PlanningError(f"Claude plugin list is not valid JSON: {exc}") from exc
    if not isinstance(payload, list) or any(
        not isinstance(item, dict) for item in payload
    ):
        raise PlanningError("Claude plugin list must be an array of objects")
    return payload


def command_show_config(args: argparse.Namespace) -> dict[str, Any]:
    config = parse_config(Path(args.config))
    return {
        "enabled": config["USE_SUPERPOWERS"] == "true",
        "pluginId": config["SUPERPOWERS_PLUGIN_ID"],
        "specRoot": config["SUPERPOWERS_SPEC_ROOT"],
        "planRoot": config["SUPERPOWERS_PLAN_ROOT"],
    }


def command_preflight(args: argparse.Namespace) -> dict[str, Any]:
    config = parse_config(Path(args.config))
    if config["USE_SUPERPOWERS"] == "false":
        return {"enabled": False, "runtime": args.runtime, "status": "disabled"}
    if args.runtime != "claude":
        return {"enabled": True, "runtime": args.runtime, "status": "not-applicable"}
    expected = config["SUPERPOWERS_PLUGIN_ID"]
    matches = [item for item in plugin_list(args) if item.get("id") == expected]
    if len(matches) != 1:
        raise PlanningError(
            f"required Claude plugin is not installed exactly once: {expected}"
        )
    plugin = matches[0]
    if plugin.get("enabled") is not True:
        raise PlanningError(f"required Claude plugin is disabled: {expected}")
    version = plugin.get("version")
    if not isinstance(version, str) or not version:
        raise PlanningError(f"required Claude plugin has no version: {expected}")
    return {
        "enabled": True,
        "runtime": "claude",
        "status": "ready",
        "pluginId": expected,
        "version": version,
    }


def command_create_handoff(args: argparse.Namespace) -> dict[str, Any]:
    config = parse_config(Path(args.config))
    if config["USE_SUPERPOWERS"] != "true":
        raise PlanningError("Superpowers planning is disabled by USE_SUPERPOWERS=false")
    if not TEAM_RE.fullmatch(args.team) or args.team in {".", ".."}:
        raise PlanningError("team must use letters, digits, dot, underscore, or hyphen")
    repo = canonical_repo(args.repo)
    spec_path, spec_relative = repo_file(
        repo, args.spec, config["SUPERPOWERS_SPEC_ROOT"], "specification"
    )
    plan_path, plan_relative = repo_file(
        repo, args.plan, config["SUPERPOWERS_PLAN_ROOT"], "plan"
    )
    require_committed(repo, [spec_relative, plan_relative])
    source_commit = git(repo, "rev-parse", "HEAD").lower()
    if not COMMIT_RE.fullmatch(source_commit):
        raise PlanningError("Git returned an invalid source commit")
    manifest = {
        "schemaVersion": 1,
        "backend": "claude-superpowers",
        "pluginId": config["SUPERPOWERS_PLUGIN_ID"],
        "executionOwner": "startup-factory",
        "blockedExecutionSkills": list(BLOCKED_EXECUTION_SKILLS),
        "sourceCommit": source_commit,
        "team": args.team,
        "spec": {"path": spec_relative, "sha256": sha256(spec_path)},
        "plan": {"path": plan_relative, "sha256": sha256(plan_path)},
    }
    output = Path(args.output).expanduser()
    if not output.is_absolute():
        if ".." in output.parts:
            raise PlanningError("handoff output must not contain '..'")
        output = repo / output
    if output.is_symlink():
        raise PlanningError("handoff output must not be a symlink")
    output = output.resolve(strict=False)
    try:
        output.relative_to(repo)
    except ValueError as exc:
        raise PlanningError("handoff output must remain inside the repository") from exc
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise PlanningError("handoff output exists and is not a regular file")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink():
        raise PlanningError("handoff output parent must not be a symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".superpowers-handoff.", dir=os.fspath(output.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(manifest))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, output)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return {"handoff": os.fspath(output), "manifest": manifest}


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise PlanningError(f"{label} has invalid fields")


def validate_artifact(repo: Path, value: Any, root: str, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise PlanningError(f"{label} must be an object")
    require_exact_keys(value, {"path", "sha256"}, label)
    path_value = value["path"]
    digest = value["sha256"]
    if (
        not isinstance(path_value, str)
        or not isinstance(digest, str)
        or not HEX_RE.fullmatch(digest)
    ):
        raise PlanningError(f"{label} has invalid path or digest")
    path, relative = repo_file(repo, path_value, root, label)
    if relative != path_value:
        raise PlanningError(f"{label} path is not canonical")
    if sha256(path) != digest:
        raise PlanningError(f"{label} digest does not match the current file")
    return {"path": relative, "sha256": digest}


def command_validate_handoff(args: argparse.Namespace) -> dict[str, Any]:
    config = parse_config(Path(args.config))
    repo = canonical_repo(args.repo)
    manifest = load_json(Path(args.handoff), "planning handoff")
    if not isinstance(manifest, dict):
        raise PlanningError("planning handoff must be an object")
    require_exact_keys(
        manifest,
        {
            "schemaVersion",
            "backend",
            "pluginId",
            "executionOwner",
            "blockedExecutionSkills",
            "sourceCommit",
            "team",
            "spec",
            "plan",
        },
        "planning handoff",
    )
    if manifest["schemaVersion"] != 1 or isinstance(manifest["schemaVersion"], bool):
        raise PlanningError("unsupported planning handoff schema")
    if manifest["backend"] != "claude-superpowers":
        raise PlanningError("planning handoff has the wrong backend")
    if manifest["pluginId"] != config["SUPERPOWERS_PLUGIN_ID"]:
        raise PlanningError("planning handoff plugin id does not match configuration")
    if manifest["executionOwner"] != "startup-factory":
        raise PlanningError(
            "planning handoff does not assign execution to Startup Factory"
        )
    if manifest["blockedExecutionSkills"] != list(BLOCKED_EXECUTION_SKILLS):
        raise PlanningError("planning handoff has an invalid execution-skill boundary")
    team = manifest["team"]
    if not isinstance(team, str) or not TEAM_RE.fullmatch(team) or team in {".", ".."}:
        raise PlanningError("planning handoff has an unsafe team id")
    source_commit = manifest["sourceCommit"]
    if not isinstance(source_commit, str) or not COMMIT_RE.fullmatch(source_commit):
        raise PlanningError("planning handoff has an invalid source commit")
    if args.team and args.team != team:
        raise PlanningError("planning handoff belongs to a different team")
    try:
        run(
            [
                "git",
                "-C",
                os.fspath(repo),
                "merge-base",
                "--is-ancestor",
                source_commit,
                "HEAD",
            ],
            timeout=30,
        )
    except PlanningError as exc:
        raise PlanningError(
            "planning handoff source commit is not an ancestor of the current HEAD"
        ) from exc
    spec = validate_artifact(
        repo, manifest["spec"], config["SUPERPOWERS_SPEC_ROOT"], "specification"
    )
    plan = validate_artifact(
        repo, manifest["plan"], config["SUPERPOWERS_PLAN_ROOT"], "plan"
    )
    require_committed(repo, [spec["path"], plan["path"]])
    if args.require_head and git(repo, "rev-parse", "HEAD").lower() != source_commit:
        raise PlanningError("planning handoff source commit is not the current HEAD")
    return {
        "valid": True,
        "team": team,
        "sourceCommit": source_commit,
        "spec": spec,
        "plan": plan,
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--config", default=os.fspath(DEFAULT_CONFIG))
    commands = root.add_subparsers(dest="command", required=True)

    show = commands.add_parser("show-config")
    show.set_defaults(handler=command_show_config)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--runtime", choices=("claude", "other"), required=True)
    preflight.add_argument("--claude-command", default="claude")
    preflight.add_argument("--plugin-list-json")
    preflight.set_defaults(handler=command_preflight)

    create = commands.add_parser("create-handoff")
    create.add_argument("--repo", required=True)
    create.add_argument("--team", required=True)
    create.add_argument("--spec", required=True)
    create.add_argument("--plan", required=True)
    create.add_argument("--output", required=True)
    create.set_defaults(handler=command_create_handoff)

    validate = commands.add_parser("validate-handoff")
    validate.add_argument("--repo", required=True)
    validate.add_argument("--handoff", required=True)
    validate.add_argument("--team")
    validate.add_argument("--require-head", action="store_true")
    validate.set_defaults(handler=command_validate_handoff)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        result = args.handler(args)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except PlanningError as exc:
        print(f"superpowers-planning: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
