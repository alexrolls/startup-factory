#!/usr/bin/env python3
"""Classify one protected worker record against its workspace heartbeat."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


MAX_HEARTBEAT_BYTES = 4096
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60
TASK_INSTANCE_RE = re.compile(
    r"^(?P<role>[a-z0-9-]+)--(?P<task_key>.+)--a(?P<attempt>[1-9][0-9]*)$"
)


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
        except UnicodeDecodeError as exc:
            raise HeartbeatError("heartbeat is not UTF-8") from exc
        if any(ord(char) < 32 for char in text):
            raise HeartbeatError("heartbeat must be exactly one printable line")
        return text
    finally:
        os.close(descriptor)


def stalled(verdict: str, heartbeat: str | None, detail: str) -> dict[str, str]:
    return {
        "verdict": verdict,
        "nextActionBy": "-",
        "heartbeat": heartbeat or "-",
        "detail": detail,
    }


def record_binding_error(
    record: dict[str, Any],
    *,
    expected_role: str | None,
    expected_attempt: int | None,
    expected_instance: str | None,
) -> str | None:
    """Bind caller expectations to the authenticated lifecycle identity.

    Task heartbeats carry the opaque task identity directly. Role and attempt are
    already encoded in the protected lifecycle instance, so validating them here
    avoids widening the agent-writable heartbeat format merely to duplicate
    authenticated fields.
    """

    instance = record.get("instance")
    if expected_instance is not None:
        if not isinstance(instance, str) or instance != expected_instance:
            return "protected lifecycle instance does not match the expected instance"
    if expected_role is None and expected_attempt is None:
        return None
    if not isinstance(instance, str):
        return "protected lifecycle record has no instance for role/attempt binding"

    category = record.get("category")
    if category == "gate":
        if expected_attempt is not None:
            return "gate lifecycle identity cannot satisfy an expected task attempt"
        actual_role = instance
        actual_attempt = None
    else:
        match = TASK_INSTANCE_RE.fullmatch(instance)
        if match is None:
            return "protected lifecycle instance is not a task-instance identity"
        actual_role = match.group("role")
        actual_attempt = int(match.group("attempt"))

    if expected_role is not None and actual_role != expected_role:
        return "protected lifecycle role does not match the expected role"
    if expected_attempt is not None and actual_attempt != expected_attempt:
        return "protected lifecycle attempt does not match the expected attempt"
    return None


def classify(
    record: dict[str, Any],
    heartbeat: str | None,
    now: datetime,
    ttl: timedelta,
    *,
    expected_task: str | None = None,
    expected_role: str | None = None,
    expected_attempt: int | None = None,
    expected_instance: str | None = None,
    start_grace: timedelta | None = None,
    max_clock_skew: timedelta = timedelta(seconds=DEFAULT_MAX_CLOCK_SKEW_SECONDS),
) -> dict[str, str]:
    if max_clock_skew < timedelta(0):
        raise HeartbeatError("maximum clock skew must not be negative")
    if expected_attempt is not None and expected_attempt < 1:
        raise HeartbeatError("expected attempt must be a positive integer")

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

    binding_error = record_binding_error(
        record,
        expected_role=expected_role,
        expected_attempt=expected_attempt,
        expected_instance=expected_instance,
    )
    if binding_error:
        return stalled("stalled:binding-mismatch", heartbeat, binding_error)

    created = parse_time(record.get("createdAt"), "lifecycle createdAt")
    if not heartbeat:
        deadline = created + (start_grace if start_grace is not None else ttl)
        verdict = "starting" if now <= deadline else "stalled:no-heartbeat"
        return {
            "verdict": verdict,
            "nextActionBy": iso(deadline),
            "heartbeat": "-",
        }

    parts = [part.strip() for part in heartbeat.split("|")]
    if len(parts) not in (3, 4) or not all(parts[:3]):
        return stalled(
            "stalled:malformed-heartbeat",
            heartbeat,
            "heartbeat must contain timestamp, task, state, and optional deadline",
        )
    if expected_task is not None and parts[1] != expected_task:
        return stalled(
            "stalled:binding-mismatch",
            heartbeat,
            "heartbeat task does not match the expected task",
        )

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
    except HeartbeatError as exc:
        return stalled("stalled:malformed-heartbeat", heartbeat, str(exc))

    if observed_at > now + max_clock_skew:
        return stalled(
            "stalled:future-heartbeat",
            heartbeat,
            "heartbeat timestamp is ahead of the trusted clock-skew window",
        )
    if observed_at < created - max_clock_skew:
        return stalled(
            "stalled:replayed-heartbeat",
            heartbeat,
            "heartbeat timestamp predates the protected lifecycle instance",
        )

    if parts[2].casefold() == "starting":
        verdict = "starting" if now <= deadline else "stalled:no-heartbeat"
    elif now <= deadline:
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
    result.add_argument("--expected-task")
    result.add_argument("--expected-role")
    result.add_argument("--expected-attempt", type=int)
    result.add_argument("--expected-instance")
    result.add_argument("--start-grace-seconds", type=int)
    result.add_argument(
        "--max-clock-skew-seconds",
        type=int,
        default=DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    )
    return result


def main() -> int:
    args = parser().parse_args()
    if not 1 <= args.stuck_minutes <= 24 * 60:
        raise HeartbeatError("stuck minutes must be from 1 to 1440")
    if not 0 <= args.max_clock_skew_seconds <= 60 * 60:
        raise HeartbeatError("maximum clock skew must be from 0 to 3600 seconds")
    if args.expected_attempt is not None and args.expected_attempt < 1:
        raise HeartbeatError("expected attempt must be a positive integer")
    if args.start_grace_seconds is not None and not 1 <= args.start_grace_seconds <= 86400:
        raise HeartbeatError("start grace must be from 1 to 86400 seconds")
    try:
        record = json.loads(sys.stdin.read())
    except ValueError as exc:
        raise HeartbeatError("lifecycle record is not valid JSON") from exc
    if not isinstance(record, dict):
        raise HeartbeatError("lifecycle record must be a JSON object")
    now = parse_time(args.now, "now") if args.now else datetime.now(timezone.utc)
    if record.get("state") in {"dead", "identity-mismatch"}:
        # Authenticated process state outranks an agent-controlled heartbeat.
        result = classify(record, None, now, timedelta(minutes=args.stuck_minutes))
    else:
        try:
            heartbeat = read_heartbeat(Path(args.heartbeat))
        except HeartbeatError as exc:
            result = stalled("stalled:invalid-heartbeat", None, str(exc))
        else:
            result = classify(
                record,
                heartbeat,
                now,
                timedelta(minutes=args.stuck_minutes),
                expected_task=args.expected_task,
                expected_role=args.expected_role,
                expected_attempt=args.expected_attempt,
                expected_instance=args.expected_instance,
                start_grace=(
                    timedelta(seconds=args.start_grace_seconds)
                    if args.start_grace_seconds is not None
                    else None
                ),
                max_clock_skew=timedelta(seconds=args.max_clock_skew_seconds),
            )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HeartbeatError as exc:
        print(f"heartbeat-status: {exc}", file=sys.stderr)
        raise SystemExit(1)
