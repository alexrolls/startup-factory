#!/usr/bin/env python3
"""Review live dedicated-host evidence; issuance requires root and every real gate."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from startup_factory_cli.sandbox_deployment import DeploymentError, load_deployment
from startup_factory_cli.sandbox_enrollment import EnrollmentError
from startup_factory_cli.sandbox_qualification_evidence import issue_enrollment, qualification_inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inventory", "issue"))
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--install", action="store_true", help="root-only: install receipt and its profile pin after full verification")
    parser.add_argument("--validity-seconds", type=int, default=3600)
    args = parser.parse_args()
    try:
        selected = load_deployment(args.deployment)
        if args.action == "inventory":
            if args.install:
                parser.error("inventory cannot install authority")
            result = qualification_inventory(selected)
        else:
            result = issue_enrollment(selected, install=args.install, validity_seconds=args.validity_seconds)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        report = {"ok": False, "qualified": False, "productionBackendAllowed": False, "error": type(exc).__name__}
        if isinstance(exc, (DeploymentError, EnrollmentError)):
            report["reason"] = str(exc)[:512]
        print(json.dumps(report), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
