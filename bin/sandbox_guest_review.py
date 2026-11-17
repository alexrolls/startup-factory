#!/usr/bin/env python3
"""Bind a guest draft to the fixed host-approved review request; no authority."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_guest_client import body_bytes, submit

FIELDS = ("Review-Request-SHA256", "Task-Branch-Head", "Review-Package-SHA256")


def bind_review(body: bytes, binding: dict) -> bytes:
    if type(binding) is not dict or not {"requestDigest", "head", "package"} <= set(binding) or set(binding) - {"requestDigest", "head", "package", "base", "reviewGates"}:
        raise ValueError("invalid approved review binding")
    for key in ("requestDigest", "package"):
        if type(binding[key]) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", binding[key]):
            raise ValueError("invalid approved review digest")
    if type(binding["head"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", binding["head"]):
        raise ValueError("invalid approved review head")
    text = body.decode("utf-8", errors="strict").replace("\r\n", "\n").replace("\r", "\n")
    if not any(text.startswith("[" + marker + "]") for marker in ("team-lead-approval", "architecture-approval", "sceptical-architecture-approval", "review-approval", "security-approval")):
        raise ValueError("draft must be an approval marker")
    text = "\n".join(line for line in text.rstrip().splitlines() if not any(line.startswith(name + ":") for name in FIELDS)).rstrip()
    result = (text + "\n\n" + "\n".join(name + ": " + binding[key] for name, key in zip(FIELDS, ("requestDigest", "head", "package"))) + "\n").encode()
    if not 0 < len(result) <= 65536:
        raise ValueError("bound draft exceeds its limit")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body", type=Path, required=True)
    args = parser.parse_args()
    try:
        response = submit(os.environ["STARTUP_FACTORY_GUEST_SOCKET"],
            {"schemaVersion": 1, "id": uuid.uuid4().hex, "operation": "context.read"})
        body = bind_review(body_bytes(args.body), response["context"]["reviewBinding"])
        descriptor = os.open(args.body, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("draft is not a private regular file")
            os.ftruncate(descriptor, 0)
            view = memoryview(body)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise ValueError("draft write failed")
                view = view[count:]
        finally:
            os.close(descriptor)
        return 0
    except (OSError, ValueError, KeyError):
        print("guest review binding failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
