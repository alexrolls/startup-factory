#!/usr/bin/env python3
"""Bounded, non-TTY exec-channel fixture; never a production agent transport.

Each frame is a four-byte unsigned network-order length followed by UTF-8 JSON.
Requests have exactly schemaVersion, id, operation, and payloadHex. Responses
echo those fields and add fixtureVersion. Supported operations are ping (empty
payload), echo (arbitrary bytes), stderr (empty payload; emits a fixed marker),
and exit (one byte in 0..125; acknowledges before exiting with that status).

This fixture has no filesystem, command-execution, or network operations. Its
successful execution establishes only the measured exec-channel behavior, not
microVM containment, process cleanup, credentials, or resource isolation.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import select
import struct
import sys
import time
from typing import Any


FIXTURE_VERSION = 1
MAX_FRAME_BYTES = 64 * 1024
MAX_JSON_DEPTH = 8
MAX_REQUESTS = 64
MAX_SESSION_SECONDS = 30.0
STDERR_MARKER = b"SF_QUALIFICATION_STDERR\n"
REQUEST_FIELDS = {"schemaVersion", "id", "operation", "payloadHex"}
REQUEST_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
HEX_PAYLOAD = re.compile(r"[0-9a-f]*\Z")

EXIT_PROTOCOL_ERROR = 64
EXIT_IO_ERROR = 74
EXIT_TIMEOUT = 124


class ProtocolError(Exception):
    """A bounded input violated the fixture protocol."""


class DeadlineExpired(Exception):
    """A frame or the session exceeded its monotonic deadline."""


def _wait(descriptor: int, *, write: bool, deadline: float) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired
        try:
            readable, writable, _ = select.select(
                [] if write else [descriptor],
                [descriptor] if write else [],
                [],
                remaining,
            )
        except InterruptedError:
            continue
        ready = writable if write else readable
        if ready:
            return


def _read_exact(
    descriptor: int, size: int, *, deadline: float, clean_eof: bool = False
) -> bytes | None:
    result = bytearray()
    while len(result) < size:
        _wait(descriptor, write=False, deadline=deadline)
        try:
            chunk = os.read(descriptor, size - len(result))
        except (BlockingIOError, InterruptedError):
            continue
        if not chunk:
            if clean_eof and not result:
                return None
            raise ProtocolError("truncated frame")
        result.extend(chunk)
    return bytes(result)


def _write_all(descriptor: int, payload: bytes, *, deadline: float) -> None:
    offset = 0
    while offset < len(payload):
        _wait(descriptor, write=True, deadline=deadline)
        try:
            written = os.write(descriptor, payload[offset:])
        except (BlockingIOError, InterruptedError):
            continue
        if written <= 0:
            raise OSError("closed fixture output")
        offset += written


def _check_nesting(raw: bytes) -> None:
    """Reject excessive nesting before invoking the JSON decoder."""
    depth = 0
    quoted = False
    escaped = False
    for value in raw:
        if quoted:
            if escaped:
                escaped = False
            elif value == 0x5C:
                escaped = True
            elif value == 0x22:
                quoted = False
        elif value == 0x22:
            quoted = True
        elif value in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ProtocolError("JSON nesting limit exceeded")
        elif value in (0x5D, 0x7D):
            depth -= 1
            if depth < 0:
                raise ProtocolError("invalid JSON")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ProtocolError("duplicate JSON key")
        result[name] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ProtocolError("non-finite JSON number")


def _decode_request(raw: bytes) -> tuple[dict[str, Any], bytes]:
    _check_nesting(raw)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
        raise ProtocolError("invalid request fields")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        raise ProtocolError("unsupported request schema")
    identifier = value["id"]
    if not isinstance(identifier, str) or not REQUEST_ID.fullmatch(identifier):
        raise ProtocolError("invalid request id")
    operation = value["operation"]
    if not isinstance(operation, str) or operation not in {
        "ping", "echo", "stderr", "exit"
    }:
        raise ProtocolError("unsupported operation")
    payload_hex = value["payloadHex"]
    if (
        not isinstance(payload_hex, str)
        or len(payload_hex) % 2
        or not HEX_PAYLOAD.fullmatch(payload_hex)
    ):
        raise ProtocolError("invalid payload encoding")
    payload = bytes.fromhex(payload_hex)
    if operation in {"ping", "stderr"} and payload:
        raise ProtocolError("operation requires an empty payload")
    if operation == "exit" and (len(payload) != 1 or payload[0] > 125):
        raise ProtocolError("invalid exit payload")
    return value, payload


def _response_frame(request: dict[str, Any]) -> bytes:
    raw = json.dumps(
        {**request, "fixtureVersion": FIXTURE_VERSION},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_FRAME_BYTES:
        raise ProtocolError("response frame limit exceeded")
    return struct.pack("!I", len(raw)) + raw


def serve(*, frame_timeout: float, maximum_requests: int) -> int:
    if os.isatty(0) or os.isatty(1):
        raise ProtocolError("fixture requires non-TTY stdin and stdout")
    # Nonblocking writes are necessary: select followed by a blocking write of
    # a whole frame can otherwise hang when the reader stops draining the pipe.
    for descriptor in (0, 1, 2):
        os.set_blocking(descriptor, False)
    session_deadline = time.monotonic() + MAX_SESSION_SECONDS
    for _ in range(maximum_requests):
        deadline = min(time.monotonic() + frame_timeout, session_deadline)
        header = _read_exact(0, 4, deadline=deadline, clean_eof=True)
        if header is None:
            return 0
        size = struct.unpack("!I", header)[0]
        if size == 0 or size > MAX_FRAME_BYTES:
            raise ProtocolError("invalid frame size")
        raw = _read_exact(0, size, deadline=deadline)
        assert raw is not None
        request, payload = _decode_request(raw)
        response = _response_frame(request)
        if request["operation"] == "stderr":
            _write_all(2, STDERR_MARKER, deadline=deadline)
        _write_all(1, response, deadline=deadline)
        if request["operation"] == "exit":
            return payload[0]
    return 0


def _timeout_argument(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected finite seconds") from exc
    if not math.isfinite(value) or not 0.05 <= value <= 10.0:
        raise argparse.ArgumentTypeError("timeout must be between 0.05 and 10 seconds")
    return value


def _requests_argument(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a request count") from exc
    if not 1 <= value <= MAX_REQUESTS:
        raise argparse.ArgumentTypeError("request count must be between 1 and 64")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frame-timeout", type=_timeout_argument, default=3.0)
    parser.add_argument("--max-requests", type=_requests_argument, default=16)
    args = parser.parse_args()
    try:
        return serve(
            frame_timeout=args.frame_timeout, maximum_requests=args.max_requests
        )
    except ProtocolError as exc:
        message = "protocol rejected: %s\n" % exc
        status = EXIT_PROTOCOL_ERROR
    except DeadlineExpired:
        message = "fixture deadline exceeded\n"
        status = EXIT_TIMEOUT
    except OSError:
        message = "fixture I/O failed\n"
        status = EXIT_IO_ERROR
    try:
        _write_all(2, message.encode("ascii"), deadline=time.monotonic() + 0.1)
    except (OSError, DeadlineExpired):
        pass
    return status


if __name__ == "__main__":
    raise SystemExit(main())
