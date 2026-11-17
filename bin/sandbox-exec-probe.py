#!/usr/bin/env python3
"""Operator-only fixed exec experiment; never a production execution backend."""

from __future__ import annotations

import sys
from pathlib import Path


sys.dont_write_bytecode = True
SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from startup_factory_cli.sandbox_exec_probe import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
