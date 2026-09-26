#!/usr/bin/env python3
"""Thin repository entry point for governed integration-pack operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from startup_factory_cli.integration_packs import (  # noqa: E402
    IntegrationPack,
    IntegrationPackError,
    apply_pack_plan,
    doctor_pack,
    list_packs,
    load_plan,
    preview_pack,
    validate_pack,
)


DEFAULT_REFERENCE_ROOT = REPOSITORY_ROOT / "extensions" / "integration-packs"


def _json(value: object) -> None:
    print(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False))


def _select_pack(args: argparse.Namespace) -> IntegrationPack:
    requested = args.pack
    candidate = Path(requested)
    if candidate.exists() or "/" in requested or "\\" in requested or requested.endswith(".json"):
        return validate_pack(candidate, root=args.source_root)
    matches = [
        pack
        for pack in list_packs(args.reference_root, project_root=args.project_root)
        if pack.pack_id == requested
    ]
    if len(matches) != 1:
        raise IntegrationPackError(f"integration pack id is unknown or ambiguous: {requested}")
    return matches[0]


def _add_catalog_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--reference-root",
        type=Path,
        default=DEFAULT_REFERENCE_ROOT,
        help="reference pack directory (defaults to the repository catalog)",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        help="project root, also enabling project-local pack discovery",
    )


def _add_pack_arguments(parser: argparse.ArgumentParser, *, project_required: bool) -> None:
    parser.add_argument("pack", help="validated pack id or JSON path")
    parser.add_argument("--source-root", type=Path, help="trust root for a pack path")
    parser.add_argument(
        "--reference-root",
        type=Path,
        default=DEFAULT_REFERENCE_ROOT,
        help="reference pack directory used when PACK is an id",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        required=project_required,
        help="target project root",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and apply data-only Startup Factory integration packs."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    list_parser = commands.add_parser("list", help="list all validated packs")
    _add_catalog_arguments(list_parser)

    validate_parser = commands.add_parser("validate", help="validate one pack")
    _add_pack_arguments(validate_parser, project_required=False)

    preview_parser = commands.add_parser("preview", help="emit a digest-bound plan")
    _add_pack_arguments(preview_parser, project_required=True)
    preview_parser.add_argument(
        "--allow-experimental",
        action="store_true",
        help="explicitly allow an experimental pack in this digest-bound preview",
    )

    apply_parser = commands.add_parser("apply", help="apply one exact saved plan")
    apply_parser.add_argument("plan", type=Path, help="plan JSON emitted by preview")
    apply_parser.add_argument(
        "--project-root",
        type=Path,
        required=True,
        help="exact target project root",
    )

    doctor_parser = commands.add_parser("doctor", help="report setup readiness safely")
    _add_pack_arguments(doctor_parser, project_required=True)
    doctor_parser.add_argument(
        "--allow-experimental",
        action="store_true",
        help="report experimental compatibility as opted in",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "list":
            packs = list_packs(args.reference_root, project_root=args.project_root)
            _json({"schemaVersion": 1, "packs": [pack.as_dict() for pack in packs]})
            return 0
        if args.command == "validate":
            _json({"valid": True, "pack": _select_pack(args).as_dict()})
            return 0
        if args.command == "preview":
            pack = _select_pack(args)
            _json(
                preview_pack(
                    pack,
                    args.project_root,
                    runtime_root=REPOSITORY_ROOT,
                    allow_experimental=args.allow_experimental,
                ).as_dict()
            )
            return 0
        if args.command == "apply":
            plan = load_plan(args.plan)
            _json(
                apply_pack_plan(
                    plan,
                    project_root=args.project_root,
                    runtime_root=REPOSITORY_ROOT,
                ).as_dict()
            )
            return 0
        if args.command == "doctor":
            pack = _select_pack(args)
            report = doctor_pack(
                pack,
                args.project_root,
                runtime_root=REPOSITORY_ROOT,
                allow_experimental=args.allow_experimental,
            )
            _json(report.as_dict())
            return 0 if report.ready else 1
        raise IntegrationPackError("unknown integration-pack operation")
    except IntegrationPackError as exc:
        print(f"integration-pack error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
