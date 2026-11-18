#!/usr/bin/env python3
"""Select planning providers and bind their documents to Factory execution."""

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
sys.dont_write_bytecode = True
sys.path.insert(0, str(SKILL_DIR / "src"))

from startup_factory_cli.config_values import (  # noqa: E402
    ConfigValueError,
    read_config_file,
    value_for,
)

DEFAULT_CONFIG = SKILL_DIR / "config" / "planning.config.md"
DEFAULTS = {
    "PLANNING_PROVIDER": "auto",
    "USE_SUPERPOWERS": "true",
    "SUPERPOWERS_PLUGIN_ID": "superpowers@claude-plugins-official",
    "SUPERPOWERS_SPEC_ROOT": "docs/superpowers/specs",
    "SUPERPOWERS_PLAN_ROOT": "docs/superpowers/plans",
    "NATIVE_SPEC_ROOT": "docs/specs",
    "NATIVE_PLAN_ROOT": "docs/plans",
    "EGM_SPEC_ROOT": "docs/egm/specs",
    "EGM_PLAN_ROOT": "docs/egm/plans",
    "EGM_PLUGIN_ROOT": "",
}
ALLOWED_KEYS = frozenset(DEFAULTS)
BLOCKED_EXECUTION_SKILLS = (
    "superpowers:using-git-worktrees",
    "superpowers:subagent-driven-development",
    "superpowers:executing-plans",
    "superpowers:finishing-a-development-branch",
)
PLANNING_INTAKES = ("brainstormed", "spec-provided")
TEAM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
PLUGIN_RE = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
RUNTIMES_RE = TEAM_RE
PROVIDERS = ("auto", "native", "superpowers", "egm")
EGM_ANCHORS = (
    "plugin.json",
    "skills/egm-brainstorm/SKILL.md",
    "skills/egm-draft/SKILL.md",
    "skills/egm-review/SKILL.md",
    "skills/egm-review-loop/SKILL.md",
    "skills/egm-resolve/SKILL.md",
    "skills/egm-draft/references/design_doc.md",
    "agents/bootstrap_orchestrator.md",
    "agents/codebase_details.md",
    "agents/comprehension.md",
    "agents/design_critic.md",
    "agents/implementation_readiness.md",
    "agents/inventive_catalyst.md",
    "agents/structural.md",
    "agents/style.md",
    "agents/synthesizer.md",
    "agents/zoom_out.md",
    "resources/README.md",
    "resources/document_standards/feature-spec-standard.md",
    "resources/document_standards/heilmeier-standard.md",
    "resources/document_standards/implementation-readiness-standard.md",
    "resources/document_standards/re-implementation-standard.md",
    "resources/document_standards/zoom-out-standard.md",
    "resources/execution_instructions.md",
    "docs/claude.md",
    "docs/codex.md",
    "docs/harnesses.md",
)
EGM_REQUIRED_FILES = EGM_ANCHORS
EGM_RESOURCE_DIRS = ("skills", "agents", "resources", "docs")


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
    try:
        path.lstat()
    except FileNotFoundError:
        return values
    except OSError as exc:
        raise PlanningError(f"cannot inspect planning config: {exc}") from exc
    try:
        parsed = read_config_file(path, "planning config")
    except ConfigValueError as exc:
        raise PlanningError(str(exc)) from exc
    unknown = sorted(set(parsed) - ALLOWED_KEYS)
    if unknown:
        raise PlanningError(f"unknown planning configuration key: {unknown[0]}")
    for key in parsed:
        value = value_for(parsed, key)
        if value is None and key == "EGM_PLUGIN_ROOT":
            values[key] = ""
            continue
        if value is None:
            raise PlanningError(f"planning configuration key must not be null: {key}")
        values[key] = value
    if values["USE_SUPERPOWERS"] not in {"true", "false"}:
        raise PlanningError("USE_SUPERPOWERS must be exactly true or false")
    if not PLUGIN_RE.fullmatch(values["SUPERPOWERS_PLUGIN_ID"]):
        raise PlanningError("SUPERPOWERS_PLUGIN_ID must be a plugin@marketplace id")
    if values["PLANNING_PROVIDER"] not in PROVIDERS:
        raise PlanningError("PLANNING_PROVIDER must be auto, native, superpowers, or egm")
    for key in (
        "SUPERPOWERS_SPEC_ROOT", "SUPERPOWERS_PLAN_ROOT",
        "NATIVE_SPEC_ROOT", "NATIVE_PLAN_ROOT", "EGM_SPEC_ROOT", "EGM_PLAN_ROOT",
    ):
        values[key] = safe_relative_directory(values[key], key)
    if any(ord(char) < 32 for char in values["EGM_PLUGIN_ROOT"]):
        raise PlanningError("EGM_PLUGIN_ROOT must not contain control characters")
    return values


def runtime_name(value: str) -> str:
    if not isinstance(value, str) or not RUNTIMES_RE.fullmatch(value):
        raise PlanningError("runtime must be a safe runtime identifier")
    return value


def is_claude(runtime: str) -> bool:
    return runtime in {"claude", "claude-code"}


def selected_provider(config: dict[str, str], runtime: str) -> str:
    runtime_name(runtime)
    provider = config["PLANNING_PROVIDER"]
    if provider == "auto":
        return (
            "superpowers" if is_claude(runtime) and config["USE_SUPERPOWERS"] == "true"
            else "native"
        )
    return provider


def roots(config: dict[str, str], provider: str) -> tuple[str, str]:
    prefix = provider.upper()
    return config[prefix + "_SPEC_ROOT"], config[prefix + "_PLAN_ROOT"]


def configured_provider_allows(config: dict[str, str], provider: str) -> bool:
    configured = config["PLANNING_PROVIDER"]
    if configured != "auto":
        return configured == provider
    return provider == "native" or (
        provider == "superpowers" and config["USE_SUPERPOWERS"] == "true"
    )


def egm_bundle(config: dict[str, str], repo: Path) -> dict[str, Any]:
    raw = config["EGM_PLUGIN_ROOT"]
    if not raw:
        raise PlanningError("EGM_PLUGIN_ROOT must point to the complete EGM plugin bundle")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = repo / candidate
    if candidate.is_symlink():
        raise PlanningError("EGM_PLUGIN_ROOT must not be a symlink")
    try:
        root = candidate.resolve(strict=True)
    except OSError as exc:
        raise PlanningError(f"cannot resolve EGM_PLUGIN_ROOT: {exc}") from exc
    if not root.is_dir():
        raise PlanningError("EGM_PLUGIN_ROOT must be a directory")

    files: dict[str, Path] = {}
    entries_seen = 0

    def walk_error(error: OSError) -> None:
        raise PlanningError(f"cannot enumerate EGM resources: {error}") from error

    for directory in EGM_RESOURCE_DIRS:
        start = root / directory
        if start.is_symlink() or not start.is_dir():
            raise PlanningError(f"EGM bundle is missing a regular {directory}/ directory")
        for current, directories, filenames in os.walk(
            start, followlinks=False, onerror=walk_error
        ):
            entries_seen += len(directories) + len(filenames)
            if entries_seen > 10000:
                raise PlanningError("EGM resource bundle exceeds 10000 entries")
            current_path = Path(current)
            for name in directories:
                if (current_path / name).is_symlink():
                    raise PlanningError("EGM bundle must not contain resource symlinks")
            for name in filenames:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    raise PlanningError("EGM bundle resources must be regular files")
                files[path.relative_to(root).as_posix()] = path
                if len(files) > 10000:
                    raise PlanningError("EGM resource bundle exceeds 10000 files")
    files["plugin.json"] = root / "plugin.json"
    total_bytes = 0
    for path in files.values():
        try:
            total_bytes += path.stat().st_size
        except OSError as exc:
            raise PlanningError(f"cannot inspect EGM resource: {exc}") from exc
        if total_bytes > 64 * 1024 * 1024:
            raise PlanningError("EGM resource bundle exceeds 64 MiB")
    for relative in EGM_ANCHORS:
        path = root / relative
        if relative not in files or path.is_symlink() or not path.is_file():
            raise PlanningError(f"EGM bundle is missing required resource: {relative}")
        try:
            if not path.read_text(encoding="utf-8").strip():
                raise PlanningError(f"EGM bundle resource is empty: {relative}")
        except (OSError, UnicodeError) as exc:
            raise PlanningError(f"cannot read EGM resource {relative}: {exc}") from exc
    manifest = load_json(root / "plugin.json", "EGM plugin manifest")
    if not isinstance(manifest, dict) or manifest.get("name") != "egm":
        raise PlanningError("EGM plugin manifest must identify name egm")
    version = manifest.get("version")
    if not isinstance(version, str) or not version.strip():
        raise PlanningError("EGM plugin manifest must contain a version")

    entries = []
    for relative, path in sorted(files.items()):
        entries.append({"path": relative, "sha256": sha256(path)})
    return {
        "egmRoot": os.fspath(root), "version": version,
        "resourceDigest": hashlib.sha256(canonical_json(entries)).hexdigest(),
        "resourceFiles": [entry["path"] for entry in entries],
    }


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
    provider = selected_provider(config, args.runtime)
    spec_root, plan_root = roots(config, provider)
    return {
        "provider": config["PLANNING_PROVIDER"],
        "selectedProvider": provider,
        "enabled": (
            config["USE_SUPERPOWERS"] == "true"
            if args.legacy and config["PLANNING_PROVIDER"] == "auto"
            else provider != "native"
        ),
        "superpowersEnabled": config["USE_SUPERPOWERS"] == "true",
        "pluginId": config["SUPERPOWERS_PLUGIN_ID"] if provider == "superpowers" else None,
        "specRoot": spec_root,
        "planRoot": plan_root,
        "egmRoot": config["EGM_PLUGIN_ROOT"] or None,
    }


def command_preflight(args: argparse.Namespace) -> dict[str, Any]:
    config = parse_config(Path(args.config))
    provider = selected_provider(config, args.runtime)
    result = {"provider": provider, "runtime": args.runtime, "enabled": provider != "native"}
    if args.legacy and config["PLANNING_PROVIDER"] == "auto":
        if config["USE_SUPERPOWERS"] == "false":
            return {**result, "status": "disabled"}
        if not is_claude(args.runtime):
            return {**result, "enabled": True, "status": "not-applicable"}
    if provider == "native":
        return {**result, "status": "ready"}
    if provider == "egm":
        repo = Path(args.repo).expanduser().resolve(strict=True)
        return {**result, "status": "ready", **egm_bundle(config, repo)}
    if not is_claude(args.runtime):
        raise PlanningError("Superpowers planning intake requires the Claude runtime")
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
        **result,
        "status": "ready",
        "pluginId": expected,
        "version": version,
    }


def command_create_handoff(args: argparse.Namespace) -> dict[str, Any]:
    config = parse_config(Path(args.config))
    provider = selected_provider(config, args.runtime)
    if args.legacy and provider == "native":
        raise PlanningError("Superpowers planning is disabled by USE_SUPERPOWERS=false")
    if provider == "superpowers" and not is_claude(args.runtime):
        raise PlanningError("Superpowers planning intake requires the Claude runtime")
    if not TEAM_RE.fullmatch(args.team) or args.team in {".", ".."}:
        raise PlanningError("team must use letters, digits, dot, underscore, or hyphen")
    repo = canonical_repo(args.repo)
    spec_root, plan_root = roots(config, provider)
    spec_path, spec_relative = repo_file(
        repo, args.spec, spec_root, "specification"
    )
    plan_path, plan_relative = repo_file(
        repo, args.plan, plan_root, "plan"
    )
    require_committed(repo, [spec_relative, plan_relative])
    source_commit = git(repo, "rev-parse", "HEAD").lower()
    if not COMMIT_RE.fullmatch(source_commit):
        raise PlanningError("Git returned an invalid source commit")
    manifest = {
        "intake": args.intake,
        "executionOwner": "startup-factory",
        "sourceCommit": source_commit,
        "team": args.team,
        "spec": {"path": spec_relative, "sha256": sha256(spec_path)},
        "plan": {"path": plan_relative, "sha256": sha256(plan_path)},
    }
    if provider == "superpowers":
        manifest.update({
            "schemaVersion": 2,
            "backend": "claude-superpowers",
            "pluginId": config["SUPERPOWERS_PLUGIN_ID"],
            "blockedExecutionSkills": list(BLOCKED_EXECUTION_SKILLS),
        })
    else:
        provenance: dict[str, str] = {"kind": "builtin", "revision": "1"}
        if provider == "egm":
            bundle = egm_bundle(config, repo)
            provenance = {
                "kind": "egm-bundle", "version": bundle["version"],
                "sha256": bundle["resourceDigest"],
            }
        manifest.update({
            "schemaVersion": 3, "provider": provider,
            "runtime": args.runtime, "provenance": provenance,
        })
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
        prefix=".planning-handoff.", dir=os.fspath(output.parent)
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
    if type(manifest.get("schemaVersion")) is not int:
        raise PlanningError("unsupported planning handoff schema")
    if manifest["schemaVersion"] == 3:
        return validate_provider_handoff(args, config, repo, manifest)
    if not configured_provider_allows(config, "superpowers"):
        raise PlanningError("planning handoff provider does not match configuration")
    require_exact_keys(
        manifest,
        {
            "schemaVersion",
            "backend",
            "pluginId",
            "intake",
            "executionOwner",
            "blockedExecutionSkills",
            "sourceCommit",
            "team",
            "spec",
            "plan",
        },
        "planning handoff",
    )
    if manifest["schemaVersion"] != 2:
        raise PlanningError("unsupported planning handoff schema")
    if manifest["backend"] != "claude-superpowers":
        raise PlanningError("planning handoff has the wrong backend")
    if manifest["pluginId"] != config["SUPERPOWERS_PLUGIN_ID"]:
        raise PlanningError("planning handoff plugin id does not match configuration")
    if manifest["intake"] not in PLANNING_INTAKES:
        raise PlanningError("planning handoff has an invalid intake mode")
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
        "provider": "superpowers",
        "team": team,
        "intake": manifest["intake"],
        "sourceCommit": source_commit,
        "spec": spec,
        "plan": plan,
    }


def source_blob_digest(repo: Path, commit: str, relative: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repo), "show", f"{commit}:{relative}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanningError(f"cannot read planning artifact at source commit: {exc}") from exc
    if result.returncode:
        raise PlanningError("planning artifact does not exist at the recorded source commit")
    return hashlib.sha256(result.stdout).hexdigest()


def validate_provider_handoff(
    args: argparse.Namespace, config: dict[str, str], repo: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    require_exact_keys(manifest, {
        "schemaVersion", "provider", "runtime", "provenance", "intake",
        "executionOwner", "sourceCommit", "team", "spec", "plan",
    }, "planning handoff")
    provider = manifest["provider"]
    if not isinstance(provider, str) or provider not in {"native", "egm"}:
        raise PlanningError("planning handoff has an invalid provider")
    if not configured_provider_allows(config, provider):
        raise PlanningError("planning handoff provider does not match configuration")
    runtime_name(manifest["runtime"])
    provenance = manifest["provenance"]
    if not isinstance(provenance, dict):
        raise PlanningError("planning handoff provenance must be an object")
    expected_provenance: dict[str, str] = {"kind": "builtin", "revision": "1"}
    if provider == "egm":
        bundle = egm_bundle(config, repo)
        expected_provenance = {
            "kind": "egm-bundle", "version": bundle["version"],
            "sha256": bundle["resourceDigest"],
        }
    if provenance != expected_provenance:
        raise PlanningError("planning handoff provider resource provenance does not match")
    if not isinstance(manifest["intake"], str) or manifest["intake"] not in PLANNING_INTAKES:
        raise PlanningError("planning handoff has an invalid intake mode")
    if manifest["executionOwner"] != "startup-factory":
        raise PlanningError("planning handoff does not assign execution to Startup Factory")
    team = manifest["team"]
    if not isinstance(team, str) or not TEAM_RE.fullmatch(team) or team in {".", ".."}:
        raise PlanningError("planning handoff has an unsafe team id")
    if args.team and args.team != team:
        raise PlanningError("planning handoff belongs to a different team")
    commit = manifest["sourceCommit"]
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise PlanningError("planning handoff has an invalid source commit")
    try:
        git(repo, "merge-base", "--is-ancestor", commit, "HEAD")
    except PlanningError as exc:
        raise PlanningError("planning handoff source commit is not an ancestor of the current HEAD") from exc
    spec_root, plan_root = roots(config, provider)
    spec = validate_artifact(repo, manifest["spec"], spec_root, "specification")
    plan = validate_artifact(repo, manifest["plan"], plan_root, "plan")
    require_committed(repo, [spec["path"], plan["path"]])
    for artifact in (spec, plan):
        if source_blob_digest(repo, commit, artifact["path"]) != artifact["sha256"]:
            raise PlanningError("planning artifact digest does not match the recorded source commit")
    if args.require_head and git(repo, "rev-parse", "HEAD").lower() != commit:
        raise PlanningError("planning handoff source commit is not the current HEAD")
    return {
        "valid": True, "provider": provider, "runtime": manifest["runtime"],
        "team": team, "intake": manifest["intake"], "sourceCommit": commit,
        "provenance": provenance, "spec": spec, "plan": plan,
    }


def parser(*, legacy: bool = False) -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--config", default=os.fspath(DEFAULT_CONFIG))
    root.set_defaults(legacy=legacy)
    commands = root.add_subparsers(dest="command", required=True)

    show = commands.add_parser("show-config")
    show.add_argument("--runtime", default="claude" if legacy else "other")
    show.set_defaults(handler=command_show_config)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--runtime", required=True)
    preflight.add_argument("--repo", default=os.fspath(Path.cwd()))
    preflight.add_argument("--claude-command", default="claude")
    preflight.add_argument("--plugin-list-json")
    preflight.set_defaults(handler=command_preflight)

    create = commands.add_parser("create-handoff")
    create.add_argument("--repo", required=True)
    create.add_argument("--team", required=True)
    create.add_argument("--spec", required=True)
    create.add_argument("--plan", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--runtime", default="claude" if legacy else "other")
    create.add_argument("--intake", choices=PLANNING_INTAKES, default="brainstormed")
    create.set_defaults(handler=command_create_handoff)

    validate = commands.add_parser("validate-handoff")
    validate.add_argument("--repo", required=True)
    validate.add_argument("--handoff", required=True)
    validate.add_argument("--team")
    validate.add_argument("--require-head", action="store_true")
    validate.set_defaults(handler=command_validate_handoff)
    return root


def main(*, legacy: bool = False) -> int:
    try:
        args = parser(legacy=legacy).parse_args()
        result = args.handler(args)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (PlanningError, OSError) as exc:
        prefix = "superpowers-planning" if legacy else "planning"
        print(f"{prefix}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
