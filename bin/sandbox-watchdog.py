#!/usr/bin/env python3
"""Fixed protected entry point for the independent sandbox watchdog."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from startup_factory_cli.sandbox_watchdog import main

if __name__ == "__main__":
    raise SystemExit(main())
