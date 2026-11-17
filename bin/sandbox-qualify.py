#!/usr/bin/env python3
"""Repository entry point for the Docker Sandbox qualification prerequisite report."""

from __future__ import annotations

import sys
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from startup_factory_cli.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(["sandbox", "qualify", *sys.argv[1:]]))
