"""Command-line interface for project-scoped Startup Factory installation."""

from __future__ import annotations

import argparse
import contextlib
import importlib.resources
import json
import sys
from pathlib import Path
from typing import Iterator, Sequence

from . import __version__
from .installer import (
    InstallerError,
    OperationResult,
    install_or_update,
    resolve_target,
    validate_bundle,
    verify_installation,
)
from .integration_packs import (
    IntegrationPack,
    apply_pack_plan,
    doctor_pack,
    list_packs,
    load_plan,
    preview_pack,
)
from .readiness import MODES, diagnose, initialize


AGENTS = ("codex", "aider", "claude", "claude-code", "deepseek-harness")


def _target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent", choices=AGENTS, help="select the agent-native project skill path")
    parser.add_argument(
        "--project",
        type=Path,
        default=Path.cwd(),
        help="target project root (default: current directory)",
    )
    parser.add_argument(
        "--install-dir",
        type=Path,
        help="explicit skill directory; relative paths are resolved below --project",
    )
    parser.add_argument("--json", action="store_true", help="emit one machine-readable JSON result")


def _mutation_arguments(parser: argparse.ArgumentParser) -> None:
    _target_arguments(parser)
    parser.add_argument(
        "--bundle",
        type=Path,
        help="validated local bundle archive (default: bundle embedded in this package)",
    )
    parser.add_argument("--dry-run", action="store_true", help="plan changes without writing files")
    parser.add_argument(
        "--overwrite-config",
        action="store_true",
        help="replace the seven project configuration files with bundled defaults",
    )


def _pack_target_arguments(parser: argparse.ArgumentParser) -> None:
    _target_arguments(parser)


def _pack_selection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("pack", help="validated reference or project integration-pack id")
    _pack_target_arguments(parser)


def _pack_opt_in_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--allow-experimental",
        action="store_true",
        help="explicitly allow an experimental pack for this operation",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="startup-factory",
        description=(
            "Install, initialize, verify, and configure a project-scoped "
            "Startup Factory skill bundle."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    install = subparsers.add_parser("install", help="install a new bundle or repair a SKILL.md-only copy")
    _mutation_arguments(install)
    update = subparsers.add_parser("update", help="safely update an existing installation")
    _mutation_arguments(update)
    update.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="write the selected bundle even when it is older than the installed version",
    )
    verify = subparsers.add_parser("verify", help="verify installed runtime files and provenance")
    _target_arguments(verify)
    initialize_parser = subparsers.add_parser(
        "init", help="preview or apply safe project initialization"
    )
    _target_arguments(initialize_parser)
    initialize_parser.add_argument("--mode", choices=MODES, required=True)
    initialize_parser.add_argument(
        "--product-management-tool",
        metavar="ADAPTER",
        help="optional adapter name to set with TEAM_MODE",
    )
    initialize_parser.add_argument(
        "--apply",
        action="store_true",
        help="atomically apply the preview (solo and team modes only)",
    )
    doctor = subparsers.add_parser("doctor", help="inspect offline readiness without mutation")
    _target_arguments(doctor)
    doctor.add_argument("--mode", choices=MODES, required=True)
    integration_pack = subparsers.add_parser(
        "integration-pack",
        help="list, validate, preview, apply, and diagnose data-only integration packs",
    )
    pack_commands = integration_pack.add_subparsers(dest="pack_command", required=True)
    pack_list = pack_commands.add_parser("list", help="list validated reference and project packs")
    _pack_target_arguments(pack_list)
    pack_validate = pack_commands.add_parser("validate", help="validate one selected pack")
    _pack_selection_arguments(pack_validate)
    pack_preview = pack_commands.add_parser(
        "preview", help="preview one digest-bound single-target setup plan"
    )
    _pack_selection_arguments(pack_preview)
    _pack_opt_in_argument(pack_preview)
    pack_apply = pack_commands.add_parser("apply", help="apply one exact saved preview plan")
    pack_apply.add_argument("plan", type=Path, help="plan JSON emitted by preview --json")
    _pack_target_arguments(pack_apply)
    pack_doctor = pack_commands.add_parser(
        "doctor", help="diagnose configured, detected, and proved readiness"
    )
    _pack_selection_arguments(pack_doctor)
    _pack_opt_in_argument(pack_doctor)
    version = subparsers.add_parser("version", help="print the installer package version")
    version.add_argument("--json", action="store_true", help="emit one machine-readable JSON result")
    return parser


def _parse_sidecar(data: bytes, archive_name: str) -> str:
    try:
        line = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise InstallerError("bundle SHA-256 sidecar is not ASCII") from exc
    expected_suffix = f"  {archive_name}\n"
    if not line.endswith(expected_suffix) or len(line) != 64 + len(expected_suffix):
        raise InstallerError("bundle SHA-256 sidecar has an invalid format")
    digest = line[:64]
    if any(character not in "0123456789abcdef" for character in digest):
        raise InstallerError("bundle SHA-256 sidecar has an invalid digest")
    return digest


@contextlib.contextmanager
def _bundle_path(explicit: Path | None) -> Iterator[tuple[Path, str | None]]:
    if explicit is not None:
        explicit = explicit.expanduser()
        sidecar = Path(str(explicit) + ".sha256")
        try:
            digest = _parse_sidecar(sidecar.read_bytes(), explicit.name) if sidecar.is_file() else None
        except OSError as exc:
            raise InstallerError(f"cannot read bundle SHA-256 sidecar: {sidecar}: {exc}") from exc
        yield explicit, digest
        return
    resources = importlib.resources.files("startup_factory_cli").joinpath("resources")
    resource = resources.joinpath("startup-factory.tar.gz")
    sidecar = resources.joinpath("startup-factory.tar.gz.sha256")
    if not resource.is_file():
        raise InstallerError(
            "this installer package does not contain resources/startup-factory.tar.gz; "
            "pass --bundle for an explicit local archive"
        )
    if not sidecar.is_file():
        raise InstallerError("this installer package is missing the bundle SHA-256 sidecar")
    try:
        digest = _parse_sidecar(sidecar.read_bytes(), "startup-factory.tar.gz")
    except OSError as exc:
        raise InstallerError("cannot read the embedded bundle SHA-256 sidecar") from exc
    with importlib.resources.as_file(resource) as local_path:
        yield local_path, digest


def _print_result(result: OperationResult, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
        return
    if result.action == "verify":
        print(
            f"Verified Startup Factory {result.version} at {result.target} "
            f"({result.verified_files} immutable files)."
        )
        print("Project configuration is present but intentionally not content-pinned.")
        return
    verb = "Previewed" if result.dry_run else ("Installed" if result.action == "install" else "Updated")
    print(f"{verb} Startup Factory {result.version} at: {result.target}")
    if result.plan is not None:
        print(
            f"Changes: {len(result.plan.writes)} writes, {len(result.plan.deletes)} deletions, "
            f"{len(result.plan.preserved_configs)} preserved configs, "
            f"{len(result.plan.preserved_extensions)} preserved extensions."
        )
        for diagnostic in result.migration_diagnostics:
            print(f"WARNING [{diagnostic.diagnostic_id}]: {diagnostic.message}")
            print(f"  Remediation: {diagnostic.remediation}")
    if result.dry_run:
        print("Dry run complete; no files were written.")


def _print_init_result(result: object, *, as_json: bool) -> None:
    data = result.as_dict()  # type: ignore[attr-defined]
    if as_json:
        print(json.dumps(data, sort_keys=True, separators=(",", ":")))
        return
    verb = "Applied" if data["applied"] else "Previewed"
    print(f"{verb} Startup Factory {data['mode']} initialization at: {data['target']}")
    if data["changes"]:
        for change in data["changes"]:
            print(f"  {change['key']}: {change['before']} -> {change['after']}")
    else:
        print("  No configuration changes.")
    print(data["message"])


def _print_doctor_report(report: object, *, as_json: bool) -> None:
    data = report.as_dict()  # type: ignore[attr-defined]
    if as_json:
        print(json.dumps(data, sort_keys=True, separators=(",", ":")))
        return
    print(
        f"Startup Factory doctor: {data['overall']} ({data['mode']}) at {data['target']}"
    )
    for check in data["checks"]:
        print(f"  [{check['status']}] {check['level']} {check['id']}: {check['message']}")
        if "remediation" in check:
            print(f"    {check['remediation']}")


def _pack_catalog(target: Path, project: Path) -> tuple[IntegrationPack, ...]:
    verify_installation(target)
    return list_packs(
        target / "extensions" / "integration-packs",
        project_root=project,
    )


def _select_pack(pack_id: str, target: Path, project: Path) -> IntegrationPack:
    matches = [pack for pack in _pack_catalog(target, project) if pack.pack_id == pack_id]
    if len(matches) != 1:
        raise InstallerError(f"integration pack id is unknown or ambiguous: {pack_id}")
    return matches[0]


def _print_pack_result(action: str, value: object, *, as_json: bool) -> None:
    if action == "list":
        packs = value  # type: ignore[assignment]
        data = {
            "schemaVersion": 1,
            "packs": [pack.as_dict() for pack in packs],  # type: ignore[union-attr]
        }
    elif action == "validate":
        pack = value  # type: ignore[assignment]
        data = {"valid": True, "pack": pack.as_dict()}  # type: ignore[union-attr]
    else:
        data = value.as_dict()  # type: ignore[union-attr]
    if as_json:
        print(json.dumps(data, sort_keys=True, separators=(",", ":")))
        return

    if action == "list":
        print(f"Available integration packs: {len(data['packs'])}")
        for pack in data["packs"]:
            compatibility = pack["compatibility"]
            print(
                f"  {pack['id']} [{pack['kind']}] - {pack['displayName']} "
                f"({compatibility['state']}; {', '.join(compatibility['platforms'])})"
            )
        print("Next: validate a pack, then preview it before applying any change.")
        return
    if action == "validate":
        pack = data["pack"]
        print(f"Validated integration pack: {pack['id']} [{pack['kind']}]")
        print(f"  {pack['displayName']}: {pack['summary']}")
        print(f"  Source digest: {pack['sourceDigest']}")
        print("Next: preview the pack against the target project.")
        return
    if action == "preview":
        print(f"Previewed integration pack: {data['packId']} [{data['kind']}]")
        print(f"  Operation: {data['operation']}")
        print(f"  Target: {data['targetRoot']}:{data['target']}")
        print(f"  Plan digest: {data['planDigest']}")
        print("No files were changed. Re-run with --json to save the exact plan before apply.")
        return
    if action == "apply":
        outcome = "Applied" if data["applied"] else "Already configured"
        print(f"{outcome} integration pack: {data['packId']} [{data['kind']}]")
        print(f"  Target: {data['target']}")
        print(f"  Output digest: {data['outputDigest']}")
        print("Next: run integration-pack doctor; external proof remains separate.")
        return
    if action == "doctor":
        print(
            f"Integration-pack doctor: {data['overall']} "
            f"({data['packId']} [{data['kind']}])"
        )
        print(f"  [compatibility] {data['compatibility']['status']}")
        for level in ("configured", "detected", "proved"):
            check = data[level]
            print(f"  [{level}] {check['status']}: {check['message']}")
        credentials = data["credentials"]
        print(f"  [credentials] {credentials['status']}: {credentials['message']}")
        if credentials["missing"]:
            print("    Missing names: " + ", ".join(credentials["missing"]))
        print("Operator actions:")
        for operator_action in data["operatorActions"]:
            print(f"  - {operator_action}")
        return
    raise InstallerError(f"unknown integration-pack operation: {action}")


def _run_pack_command(args: argparse.Namespace, target: Path) -> int:
    project = args.project
    action = args.pack_command
    if action == "list":
        result: object = _pack_catalog(target, project)
    elif action == "validate":
        result = _select_pack(args.pack, target, project)
    elif action == "preview":
        result = preview_pack(
            _select_pack(args.pack, target, project),
            project,
            runtime_root=target,
            allow_experimental=bool(args.allow_experimental),
        )
    elif action == "apply":
        verify_installation(target)
        result = apply_pack_plan(
            load_plan(args.plan),
            project_root=project,
            runtime_root=target,
        )
    elif action == "doctor":
        result = doctor_pack(
            _select_pack(args.pack, target, project),
            project,
            runtime_root=target,
            allow_experimental=bool(args.allow_experimental),
        )
    else:  # pragma: no cover - argparse owns the command enum.
        raise InstallerError(f"unknown integration-pack operation: {action}")
    _print_pack_result(action, result, as_json=bool(args.json))
    if action == "doctor":
        return 0 if result.ready else 1  # type: ignore[union-attr]
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "version":
        if args.json:
            print(json.dumps({"ok": True, "version": __version__}, sort_keys=True, separators=(",", ":")))
        else:
            print(__version__)
        return 0
    json_output = bool(args.json)
    try:
        target = resolve_target(
            project=args.project,
            install_dir=args.install_dir,
            agent=args.agent,
            command=args.command,
        )
        if args.command == "integration-pack":
            return _run_pack_command(args, target)
        if args.command == "verify":
            result = verify_installation(target)
        elif args.command == "init":
            init_result = initialize(
                target,
                mode=args.mode,
                product_management_tool=args.product_management_tool,
                apply=bool(args.apply),
            )
            _print_init_result(init_result, as_json=json_output)
            return 0
        elif args.command == "doctor":
            report = diagnose(args.project, target, mode=args.mode)
            _print_doctor_report(report, as_json=json_output)
            return 0 if report.ready else 1
        else:
            with _bundle_path(args.bundle) as (bundle_path, expected_digest):
                bundle = validate_bundle(bundle_path, expected_sha256=expected_digest)
                result = install_or_update(
                    bundle,
                    target,
                    command=args.command,
                    overwrite_config=bool(args.overwrite_config),
                    dry_run=bool(args.dry_run),
                    allow_downgrade=bool(getattr(args, "allow_downgrade", False)),
                    project=args.project.expanduser().resolve(strict=True),
                )
        _print_result(result, as_json=json_output)
        return 0
    except InstallerError as exc:
        if json_output:
            print(
                json.dumps({"ok": False, "error": str(exc)}, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )
        else:
            print(f"startup-factory: {exc}", file=sys.stderr)
        return 1
