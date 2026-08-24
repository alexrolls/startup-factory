#!/usr/bin/env python3
"""Classify one protected worker record against its workspace heartbeat."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


MAX_HEARTBEAT_BYTES = 4096


class HeartbeatError(RuntimeError):
    pass


def parse_time(raw: Any, label: str) -> datetime:
    if not isinstance(raw, str) or not raw.strip():
        raise HeartbeatError(f"{label} must be an ISO-8601 timestamp")
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HeartbeatError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise HeartbeatError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def read_heartbeat(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise HeartbeatError(f"cannot inspect heartbeat: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise HeartbeatError("heartbeat must be a non-symlink regular file")
    if info.st_size > MAX_HEARTBEAT_BYTES:
        raise HeartbeatError("heartbeat exceeds the 4096-byte limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HeartbeatError(f"cannot open heartbeat safely: {exc}") from exc
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
            info.st_dev,
            info.st_ino,
        ):
            raise HeartbeatError("heartbeat changed identity while being read")
        chunks: list[bytes] = []
        remaining = MAX_HEARTBEAT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_HEARTBEAT_BYTES:
            raise HeartbeatError("heartbeat exceeds the 4096-byte limit")
        try:
            text = raw.decode("utf-8").strip()
            if any(ord(char) < 32 for char in text):
                raise HeartbeatError("heartbeat must be exactly one printable line")
            return text
        except UnicodeDecodeError as exc:
            raise HeartbeatError("heartbeat is not UTF-8") from exc
    finally:
        os.close(descriptor)


def classify(
    record: dict[str, Any], heartbeat: str | None, now: datetime, ttl: timedelta
) -> dict[str, str]:
    state = record.get("state")
    if state == "dead":
        return {
            "verdict": "exited",
            "nextActionBy": "-",
            "heartbeat": heartbeat or "-",
        }
    if state == "identity-mismatch":
        return {
            "verdict": "identity-mismatch",
            "nextActionBy": "-",
            "heartbeat": heartbeat or "-",
        }
    if state != "live":
        raise HeartbeatError(f"unsupported lifecycle state {state!r}")

    if not heartbeat:
        created = parse_time(record.get("createdAt"), "lifecycle createdAt")
        deadline = created + ttl
        verdict = "starting" if now <= deadline else "stalled:no-heartbeat"
        return {
            "verdict": verdict,
            "nextActionBy": iso(deadline),
            "heartbeat": "-",
        }

    parts = [part.strip() for part in heartbeat.split("|")]
    if len(parts) not in (3, 4) or not all(parts[:3]):
        return {
            "verdict": "stalled:malformed-heartbeat",
            "nextActionBy": "-",
            "heartbeat": heartbeat,
        }
    try:
        observed_at = parse_time(parts[0], "heartbeat timestamp")
        ttl_deadline = observed_at + ttl
        if len(parts) == 4:
            requested_deadline = parse_time(parts[3], "heartbeat next-action-by")
            if requested_deadline < observed_at:
                raise HeartbeatError("heartbeat next-action-by precedes its timestamp")
            deadline = min(requested_deadline, ttl_deadline)
        else:
            deadline = ttl_deadline
    except HeartbeatError:
        return {
            "verdict": "stalled:malformed-heartbeat",
            "nextActionBy": "-",
            "heartbeat": heartbeat,
        }

    if now <= deadline:
        verdict = "active"
    else:
        target = parts[1]
        activity = parts[2].casefold()
        idle_words = ("idle", "unassigned", "no assignment", "awaiting assignment", "ready")
        gate_words = ("gate", "review", "approval", "blocked", "waiting")
        if target == "-" and any(word in activity for word in idle_words):
            verdict = "stalled:idle-no-assignment"
        elif any(word in activity for word in gate_words):
            verdict = "stalled:waiting-on-gate"
        else:
            verdict = "stalled:no-progress"
    return {
        "verdict": verdict,
        "nextActionBy": iso(deadline),
        "heartbeat": heartbeat,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--heartbeat", required=True)
    result.add_argument("--stuck-minutes", required=True, type=int)
    result.add_argument("--now", help="fixed ISO-8601 time for deterministic tests")
    return result


def main() -> int:
    args = parser().parse_args()
    if not 1 <= args.stuck_minutes <= 24 * 60:
        raise HeartbeatError("stuck minutes must be from 1 to 1440")
    try:
        record = json.loads(sys.stdin.read())
    except ValueError as exc:
        raise HeartbeatError("lifecycle record is not valid JSON") from exc
    if not isinstance(record, dict):
        raise HeartbeatError("lifecycle record must be a JSON object")
    now = parse_time(args.now, "now") if args.now else datetime.now(timezone.utc)
    try:
        heartbeat = read_heartbeat(Path(args.heartbeat))
    except HeartbeatError as exc:
        result = {
            "verdict": "stalled:invalid-heartbeat",
            "nextActionBy": "-",
            "heartbeat": "-",
            "detail": str(exc),
        }
    else:
        result = classify(
            record,
            heartbeat,
            now,
            timedelta(minutes=args.stuck_minutes),
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HeartbeatError as exc:
        print(f"heartbeat-status: {exc}", file=sys.stderr)
        raise SystemExit(1)
