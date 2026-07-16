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


AGENTS = ("codex", "aider", "claude", "claude-code")


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="startup-factory",
        description="Install and verify a project-scoped Startup Factory skill bundle.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    install = subparsers.add_parser("install", help="install a new bundle or repair a SKILL.md-only copy")
    _mutation_arguments(install)
    update = subparsers.add_parser("update", help="safely update an existing installation")
    _mutation_arguments(update)
    verify = subparsers.add_parser("verify", help="verify installed runtime files and provenance")
    _target_arguments(verify)
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
    if result.dry_run:
        print("Dry run complete; no files were written.")


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
        if args.command == "verify":
            result = verify_installation(target)
        else:
            with _bundle_path(args.bundle) as (bundle_path, expected_digest):
                bundle = validate_bundle(bundle_path, expected_sha256=expected_digest)
                result = install_or_update(
                    bundle,
                    target,
                    command=args.command,
                    overwrite_config=bool(args.overwrite_config),
                    dry_run=bool(args.dry_run),
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
