#!/usr/bin/env python3
"""Small CLI facade over the shared inert configuration parser."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True
SKILL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "src"))

from startup_factory_cli.config_values import (  # noqa: E402
    ConfigValueError,
    read_config_file,
    state_for,
    value_for,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--label", default="team config")
    parser.add_argument("--prefix", default="config-value")
    parser.add_argument("mode", choices=("validate", "value", "state"))
    parser.add_argument("key", nargs="?")
    args = parser.parse_args()
    if args.mode != "validate" and args.key is None:
        parser.error("value and state modes require KEY")
    try:
        values = read_config_file(args.config, args.label)
    except ConfigValueError as exc:
        print(f"{args.prefix}: {exc}", file=sys.stderr)
        return 1
    if args.mode == "validate":
        return 0
    if args.mode == "state":
        sys.stdout.write(state_for(values, args.key))
    else:
        sys.stdout.write(value_for(values, args.key) or "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
