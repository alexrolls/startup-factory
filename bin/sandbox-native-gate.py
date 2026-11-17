#!/usr/bin/env python3
"""Protected standalone pre-exec gate. No guest-facing command-line surface.

The parent supplies private pipe descriptors. EOF before an explicit release
byte exits without executing the pinned native command. No project imports,
host configuration loading, shell, or journal authority lives in this child.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import signal
import struct
import time

MAX_COMMAND_BYTES = 128 * 1024
DEADLINE_SECONDS = 5.0


def exact(fd: int, count: int, deadline: float) -> bytes:
    output = bytearray()
    while len(output) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError("gate deadline")
        chunk = os.read(fd, count - len(output))
        if not chunk:
            raise ValueError("gate EOF")
        output.extend(chunk)
    return bytes(output)


def unique(items):
    value = {}
    for key, child in items:
        if key in value:
            raise ValueError("duplicate gate field")
        value[key] = child
    return value


def invalid_constant(_value):
    raise ValueError("nonfinite gate field")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate-fd", type=int, required=True)
    parser.add_argument("--status-fd", type=int, required=True)
    parser.add_argument("--command-fd", type=int, required=True)
    args = parser.parse_args()
    try:
        if len({args.gate_fd, args.status_fd, args.command_fd}) != 3 or min(args.gate_fd, args.status_fd, args.command_fd) < 3:
            raise ValueError("invalid descriptors")
        deadline = time.monotonic() + DEADLINE_SECONDS
        count = struct.unpack("!I", exact(args.command_fd, 4, deadline))[0]
        if not 0 < count <= MAX_COMMAND_BYTES:
            raise ValueError("gate size")
        raw = exact(args.command_fd, count, deadline)
        # Only one object and one argv array are accepted. Bound nesting before
        # decoding, so malformed input cannot recurse through the JSON parser.
        depth, quoted, escaped = 0, False, False
        for byte in raw:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte in (91, 123):
                depth += 1
                if depth > 2:
                    raise ValueError("gate nesting")
            elif byte in (93, 125):
                depth -= 1
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant)
        if type(value) is not dict or set(value) != {"schemaVersion", "argv"} or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
            raise ValueError("gate schema")
        argv = value["argv"]
        if type(argv) is not list or not 1 <= len(argv) <= 256 or any(type(arg) is not str or len(arg) > 4096 or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in arg) for arg in argv) or not argv[0].startswith("/"):
            raise ValueError("gate command")
        os.close(args.command_fd)
        if os.write(args.status_fd, b"R") != 1:
            raise ValueError("gate status")
        if exact(args.gate_fd, 1, time.monotonic() + DEADLINE_SECONDS) != b"G":
            raise ValueError("gate not released")
        os.close(args.gate_fd)
        os.set_inheritable(args.status_fd, False)
        for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
            number = getattr(signal, name, None)
            if number is not None:
                signal.signal(number, signal.SIG_DFL)
        os.execve(argv[0], argv, dict(os.environ))
    except BaseException:
        try:
            os.write(args.status_fd, b"F")
        except OSError:
            pass
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
