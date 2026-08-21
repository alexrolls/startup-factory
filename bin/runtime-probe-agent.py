#!/usr/bin/env python3
"""Fixed, non-promoting controls executed inside the governed agent runtime."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
from pathlib import Path


def inaccessible(path: Path) -> bool:
    try:
        path.lstat()
    except OSError:
        return True
    return False


def connect_denied(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return False
    except OSError:
        return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--host-sentinel", required=True)
    parser.add_argument("--canonical-repo", required=True)
    parser.add_argument("--broker-state", required=True)
    parser.add_argument("--lifecycle-state", required=True)
    parser.add_argument("--sibling-workspace", required=True)
    args = parser.parse_args()
    workdir = Path(args.workdir)
    if Path.cwd() != workdir or os.environ.get("STARTUP_FACTORY_AGENT_WORKTREE") != str(workdir):
        raise SystemExit("runtime probe identity mismatch")
    marker = workdir / ".runtime-boundary-probe"
    marker.write_text("fixed probe\n", encoding="utf-8")
    subprocess.run(["git", "add", marker.name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(
        ["git", "-c", "user.name=Startup Factory Probe", "-c", "user.email=probe@startup-factory.invalid", "commit", "-qm", "fixed runtime probe"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    result = {
        "schemaVersion": 1,
        "worktreeWrite": marker.is_file(),
        "standaloneGitCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "denials": {
            "hostSentinel": inaccessible(Path(args.host_sentinel)),
            "canonicalRepo": inaccessible(Path(args.canonical_repo)),
            "brokerState": inaccessible(Path(args.broker_state)),
            "lifecycleState": inaccessible(Path(args.lifecycle_state)),
            "siblingWorkspace": inaccessible(Path(args.sibling_workspace)),
            "loopbackNetwork": connect_denied("127.0.0.1", 1),
            "metadataNetwork": connect_denied("169.254.169.254", 80),
        },
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["worktreeWrite"] and all(result["denials"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
