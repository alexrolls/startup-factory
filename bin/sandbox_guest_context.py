#!/usr/bin/env python3
"""Read only the host-approved context for this guest assignment."""
import json
import os
import sys
import uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_guest_client import submit

if __name__ == "__main__":
    try:
        if len(sys.argv) != 1:
            raise ValueError("context selectors are forbidden")
        result = submit(os.environ["STARTUP_FACTORY_GUEST_SOCKET"],
            {"schemaVersion": 1, "id": uuid.uuid4().hex, "operation": "context.read"})
        if result.get("status") != "ok":
            raise ValueError("context denied")
        print(json.dumps(result["context"], sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, KeyError):
        print("guest context unavailable", file=sys.stderr)
        raise SystemExit(1)
