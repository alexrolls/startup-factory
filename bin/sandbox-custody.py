#!/usr/bin/env python3
"""Dedicated-account Docker Sandbox job service and native launch client."""
from __future__ import annotations
import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "bin")]
from startup_factory_cli.sandbox_deployment import load_deployment
from sandbox_service import JobServer, NativeJobExecutor, ServiceError
from sandbox_client import run_client


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--deployment", required=True, type=Path)
    client = commands.add_parser("client")
    client.add_argument("--deployment", required=True, type=Path)
    client.add_argument("--request", required=True, type=Path)
    client.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        deployment = load_deployment(args.deployment)
        if args.command == "client":
            result = run_client(deployment, args.request)
            if args.json:
                print(json.dumps(result, sort_keys=True))
            return result["exitCode"]
        executor = NativeJobExecutor(deployment)
        server = JobServer(deployment, executor)
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, lambda *_: server.stop())
        try:
            server.serve()
        finally:
            server.close()
        return 0
    except Exception:
        print("sandbox-custody: refused or uncertain; inspect protected deployment, qualification, job and watchdog state", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
