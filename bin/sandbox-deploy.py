#!/usr/bin/env python3
"""Prepare/install a reviewed dedicated Docker Sandbox deployment, without enabling it."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from startup_factory_cli.execution_backend import parse_profile
from startup_factory_cli.sandbox_deployment import Deployment, DeploymentError, digest_bytes, preparation_plan
from startup_factory_cli.sandbox_deployment_installer import _bounded_input, install_prepared_bundle, prepare_bundle_pins, prepare_runtime_pins


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "prepare-runtime", "prepare-bundle", "install"))
    parser.add_argument("--deployment", type=Path, required=True, help="reviewed candidate JSON, never a guest job request")
    parser.add_argument("--destination", type=Path, required=True, help="final root-protected deployment JSON path")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--bundle-sha256")
    parser.add_argument("--expected-deployment-digest")
    args = parser.parse_args()
    try:
        raw = _bounded_input(args.deployment.absolute(), 256 * 1024)
        selected = Deployment(args.destination, raw)
        if args.action == "plan":
            result = preparation_plan(selected)
        else:
            if args.profile is None:
                parser.error("runtime/bundle/install preparation requires --profile")
            profile = parse_profile(_bounded_input(args.profile.absolute(), 64 * 1024))
            if args.action == "prepare-runtime":
                result = prepare_runtime_pins(selected, profile)
            elif args.bundle is None or args.bundle_sha256 is None:
                parser.error("prepare-bundle/install require --profile, --bundle and --bundle-sha256")
            elif args.action == "prepare-bundle":
                result = prepare_bundle_pins(selected, profile, args.bundle.absolute(), archive_sha256=args.bundle_sha256)
            else:
                if args.expected_deployment_digest != digest_bytes(raw):
                    parser.error("install requires --expected-deployment-digest matching the reviewed exact candidate bytes")
                result = install_prepared_bundle(selected, profile, args.bundle.absolute(), archive_sha256=args.bundle_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        report = {"ok": False, "qualified": False, "productionBackendAllowed": False, "error": type(exc).__name__}
        if isinstance(exc, DeploymentError):
            report["reason"] = str(exc)[:512]
        print(json.dumps(report), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
