#!/usr/bin/env python3
"""Report bounded progress for the host-fixed assignment; carries no identity."""
import argparse
import os
import sys
import uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_guest_client import submit

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("starting", "working", "waiting", "validating", "completed", "failed"))
    parser.add_argument("message", nargs="?", default="")
    args = parser.parse_args()
    try:
        result = submit(os.environ["STARTUP_FACTORY_GUEST_SOCKET"],
            {"schemaVersion": 1, "id": uuid.uuid4().hex, "operation": "progress.report",
             "stage": args.stage, "message": args.message})
        if result.get("status") != "recorded":
            raise ValueError("progress denied")
    except (OSError, ValueError, KeyError):
        print("guest progress report failed", file=sys.stderr)
        raise SystemExit(1)
