#!/usr/bin/env python3
"""Guest-only artifact client. A local socket and request ID carry no authority.

Copy this file into the VM alongside sandbox_guest_bridge.py. Never point it at
the host publication-supervisor socket. The host constructs every envelope and
rechecks the protected assignment independently of this helper.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time

MAX_REQUEST = 192 * 1024
MAX_RESPONSE = 16 * 1024
MAX_BODY = 64 * 1024


class GuestProtocolError(ValueError):
    pass


def decode(raw: bytes) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise GuestProtocolError("duplicate protocol field")
            value[key] = item
        return value

    def invalid(_value):
        raise GuestProtocolError("invalid protocol number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
        def bounded(item, depth=0):
            if depth > 8:
                raise GuestProtocolError("protocol nesting exceeds limit")
            if type(item) is float and not math.isfinite(item):
                raise GuestProtocolError("invalid protocol number")
            if type(item) in (dict, list):
                for child in (item.values() if type(item) is dict else item):
                    bounded(child, depth + 1)
        bounded(value)
        if type(value) is not dict:
            raise GuestProtocolError("expected protocol object")
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise GuestProtocolError("invalid protocol response") from exc


def _receive(connection: socket.socket, count: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GuestProtocolError("guest request timed out")
        connection.settimeout(remaining)
        chunk = connection.recv(min(8192, count - len(result)))
        if not chunk:
            raise GuestProtocolError("guest channel closed")
        result.extend(chunk)
    return bytes(result)


def submit(socket_path: str, request: dict, *, timeout: float = 15) -> dict:
    if type(timeout) not in (int, float) or not 0 < timeout <= 60:
        raise GuestProtocolError("invalid guest timeout")
    raw = json.dumps(request, separators=(",", ":"), allow_nan=False).encode()
    if not 0 < len(raw) <= MAX_REQUEST:
        raise GuestProtocolError("guest request exceeds frame limit")
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(socket_path)
        # socket.sendall applies one total timeout, rather than resetting it
        # for every successful short write.
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.sendall(struct.pack("!I", len(raw)) + raw)
        size = struct.unpack("!I", _receive(connection, 4, deadline))[0]
        if not 0 < size <= MAX_RESPONSE:
            raise GuestProtocolError("invalid guest response size")
        response = decode(_receive(connection, size, deadline))
    if request.get("operation") not in {"artifact.submit", "context.read", "progress.report"} or response.get("id") != request.get("id") or response.get("operation") != request.get("operation") or type(response.get("schemaVersion")) is not int or response["schemaVersion"] != 1:
        raise GuestProtocolError("guest response binding mismatch")
    return response


def body_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BODY:
            raise GuestProtocolError("artifact body must be a bounded regular file")
        raw = bytearray()
        while len(raw) <= MAX_BODY:
            chunk = os.read(descriptor, min(8192, MAX_BODY + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if not 0 < len(raw) <= MAX_BODY:
            raise GuestProtocolError("artifact body exceeds its limit")
        return bytes(raw)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=os.environ.get("STARTUP_FACTORY_GUEST_SOCKET"))
    parser.add_argument("--request-id", default=None, help="Reuse the same ID and bytes for an uncertain retry")
    parser.add_argument("--marker", required=True)
    parser.add_argument("--body", required=True, type=Path)
    parser.add_argument("--target-status", default=None)
    args = parser.parse_args()
    try:
        if not args.socket:
            raise GuestProtocolError("guest channel is unavailable")
        request = {"schemaVersion": 1, "operation": "artifact.submit", "marker": args.marker,
                   "bodyHex": body_bytes(args.body).hex(), "targetStatus": args.target_status}
        # Identical default CLI retries within this host-bound generation must
        # retain their identity even if the first acknowledgment is lost. An
        # explicit caller ID supports distinct identical publication intents.
        request["id"] = args.request_id or hashlib.sha256(json.dumps(
            request, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode()).hexdigest()
        response = submit(args.socket, request)
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0 if response.get("status") == "admitted" else 1
    except (OSError, ValueError, TypeError):
        print("guest artifact request failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
