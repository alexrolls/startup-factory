#!/usr/bin/env python3
"""Native artifact relay; enrollment and launcher enablement remain separate."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time


# This process is a native publication-supervisor child, not the guest agent.
# Its complete authority context is the protected file, never ambient worker
# identity, SSH sockets, provider keys, Git helpers, or shell configuration.
os.environ.clear()
os.environ.update({
    "PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
})
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_transport import (  # noqa: E402
    ArtifactRelay, RelayContext, RelayError, TransportDeadline, _write_all,
    serve_framed,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=Path, help="protected host-only relay context file")
    args = parser.parse_args()
    try:
        context = RelayContext.from_file(args.context)
        with ArtifactRelay(context) as relay:
            return serve_framed(relay.handle, context.limits)
    except (Exception, TransportDeadline):
        # Diagnostics are fixed and bounded; exceptions can contain protected
        # paths or verifier details and must never be printed to this process's
        # guest-visible streams.
        original = None
        try:
            original = os.get_blocking(2)
            os.set_blocking(2, False)
            _write_all(2, b"sandbox-relay: relay session denied\n", deadline=time.monotonic() + 0.1)
        except (OSError, RelayError, TransportDeadline):
            pass
        finally:
            if original is not None:
                os.set_blocking(2, original)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
