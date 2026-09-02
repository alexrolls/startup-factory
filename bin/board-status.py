#!/usr/bin/env python3
"""Summarize whether a team board is progressing, idle, or stalled.

Every role reaching `exited` is the normal end of a dispatch pass, so per-role
health cannot distinguish "finished cleanly" from "stalled with work
outstanding".  This module answers the board-level question instead: is there
work waiting, is anything alive to do it, and when did a dispatch pass last run.

Presentation only.  Nothing here controls lifecycle, scheduling, review,
integration, or release.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "board-status-v1"
DEFAULT_IDLE_MINUTES = 15
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


class BoardStatusError(RuntimeError):
    pass


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    """Read a file that must be a plain, owner-readable, non-symlink file."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise BoardStatusError("cannot inspect %s: %s" % (label, exc)) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BoardStatusError("%s must be a non-symlink regular file" % label)
    if info.st_size > maximum:
        raise BoardStatusError("%s is larger than its allowed size" % label)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BoardStatusError("cannot read %s: %s" % (label, exc)) from exc
    try:
        return os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)


def status_names(board: dict[str, Any]) -> dict[str, str]:
    """Map task status kinds to their configured names."""
    try:
        statuses = board["tasks"]["statuses"]
    except (KeyError, TypeError) as exc:
        raise BoardStatusError("status configuration has no task statuses") from exc
    by_kind = {
        status.get("kind"): status.get("name")
        for status in statuses
        if isinstance(status, dict) and status.get("kind") and status.get("name")
    }
    return {
        "queued": by_kind.get("queued", "Planned"),
        "working": by_kind.get("working", "Active"),
        "review": by_kind.get("review", "Review"),
        "blocked": by_kind.get("blocked", "Blocked"),
    }


def count_tasks(snapshot: Any, names: dict[str, str]) -> dict[str, int]:
    """Count tasks per status kind in an exported feature snapshot."""
    tasks = snapshot.get("tasks") if isinstance(snapshot, dict) else None
    if not isinstance(tasks, list):
        return {kind: 0 for kind in names}
    counts = {kind: 0 for kind in names}
    inverted = {value: key for key, value in names.items()}
    for task in tasks:
        if not isinstance(task, dict):
            continue
        kind = inverted.get(task.get("status"))
        if kind is not None:
            counts[kind] += 1
    return counts


def count_pending(workspace: Path) -> int:
    """Count artifacts enqueued to the outbox and not yet drained."""
    pending = workspace / "outbox" / "pending"
    try:
        info = pending.lstat()
    except FileNotFoundError:
        return 0
    except OSError as exc:
        raise BoardStatusError("cannot inspect the outbox: %s" % exc) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BoardStatusError("the outbox pending directory is not a directory")
    total = 0
    try:
        for child in pending.iterdir():
            child_info = child.lstat()
            if stat.S_ISREG(child_info.st_mode) and not child.name.startswith("."):
                total += 1
    except OSError as exc:
        raise BoardStatusError("cannot enumerate the outbox: %s" % exc) from exc
    return total


def last_pass_at(workspace: Path) -> datetime | None:
    """Read the timestamp the last completed dispatch pass recorded."""
    raw = _read_regular(workspace / "dispatch.last-pass", "dispatch pass marker", 256)
    if not raw:
        return None
    try:
        text = raw.decode("ascii", errors="strict").strip()
    except UnicodeError:
        raise BoardStatusError("dispatch pass marker is not ASCII") from None
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise BoardStatusError("dispatch pass marker is not an ISO-8601 instant") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def summarize(
    *,
    counts: dict[str, int],
    pending: int,
    last_pass: datetime | None,
    live_agents: int,
    now: datetime,
    idle_minutes: int = DEFAULT_IDLE_MINUTES,
) -> dict[str, Any]:
    """Classify a board as working, idle, or stalled.

    STALLED is the state the operator cannot see today: work is waiting, no
    agent is alive to take it, and no dispatch pass has run recently.  IDLE is
    the same shape without the elapsed-time evidence, so it is reported without
    claiming a pass was missed.
    """
    if idle_minutes < 1:
        raise BoardStatusError("idle minutes must be at least 1")
    outstanding = counts.get("queued", 0) + counts.get("review", 0)
    since_pass = None
    if last_pass is not None:
        since_pass = max(0, int((now - last_pass).total_seconds()))
    stale_pass = since_pass is None or since_pass >= idle_minutes * 60

    if live_agents > 0:
        verdict = "WORKING"
    elif outstanding == 0 and pending == 0:
        verdict = "DRAINED"
    elif stale_pass:
        verdict = "STALLED"
    else:
        verdict = "IDLE"
    return {
        "schemaVersion": SCHEMA,
        "verdict": verdict,
        "queued": counts.get("queued", 0),
        "working": counts.get("working", 0),
        "review": counts.get("review", 0),
        "blocked": counts.get("blocked", 0),
        "outstanding": outstanding,
        "undrainedArtifacts": pending,
        "liveAgents": live_agents,
        "lastPassAt": last_pass.isoformat(timespec="seconds").replace("+00:00", "Z")
        if last_pass is not None
        else None,
        "secondsSinceLastPass": since_pass,
        "idleMinutes": idle_minutes,
        "presentationOnly": True,
    }


def human_duration(seconds: int) -> str:
    if seconds < 60:
        return "%ds" % seconds
    minutes = seconds // 60
    if minutes < 60:
        return "%dm" % minutes
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return "%dh%02dm" % (hours, minutes)
    days, hours = divmod(hours, 24)
    return "%dd%02dh" % (days, hours)


def board_line(summary: dict[str, Any]) -> str:
    """One operator-facing line describing the whole board."""
    parts: list[str] = []
    if summary["queued"]:
        parts.append("%d queued task%s" % (summary["queued"], "" if summary["queued"] == 1 else "s"))
    if summary["review"]:
        parts.append("%d in review" % summary["review"])
    if summary["working"]:
        parts.append("%d active" % summary["working"])
    if summary["blocked"]:
        parts.append("%d blocked" % summary["blocked"])
    if summary["undrainedArtifacts"]:
        parts.append(
            "%d undrained artifact%s"
            % (
                summary["undrainedArtifacts"],
                "" if summary["undrainedArtifacts"] == 1 else "s",
            )
        )
    if summary["secondsSinceLastPass"] is None:
        parts.append("no dispatch pass recorded")
    else:
        parts.append("last pass %s ago" % human_duration(summary["secondsSinceLastPass"]))
    if not parts:
        return summary["verdict"]
    return "%s — %s" % (summary["verdict"], ", ".join(parts))


def collect(
    *,
    workspace: Path,
    board: dict[str, Any],
    live_agents: int,
    now: datetime,
    idle_minutes: int = DEFAULT_IDLE_MINUTES,
) -> dict[str, Any]:
    names = status_names(board)
    raw = _read_regular(workspace / "tasks.json", "feature snapshot", MAX_SNAPSHOT_BYTES)
    if raw:
        try:
            snapshot = json.loads(raw)
        except ValueError:
            raise BoardStatusError("feature snapshot is not valid JSON") from None
    else:
        snapshot = {}
    return summarize(
        counts=count_tasks(snapshot, names),
        pending=count_pending(workspace),
        last_pass=last_pass_at(workspace),
        live_agents=live_agents,
        now=now,
        idle_minutes=idle_minutes,
    )


def parser() -> argparse.ArgumentParser:
    parsed = argparse.ArgumentParser(
        description="Report whether a team board is progressing, idle, or stalled."
    )
    parsed.add_argument("--workspace", required=True)
    parsed.add_argument("--status-config", required=True)
    parsed.add_argument("--live-agents", type=int, default=0)
    parsed.add_argument("--idle-minutes", type=int, default=DEFAULT_IDLE_MINUTES)
    parsed.add_argument("--json", action="store_true")
    return parsed


def main() -> int:
    args = parser().parse_args()
    try:
        board = json.loads(Path(args.status_config).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("board-status: cannot read status configuration: %s" % exc, file=sys.stderr)
        return 2
    try:
        summary = collect(
            workspace=Path(args.workspace),
            board=board,
            live_agents=args.live_agents,
            now=datetime.now(timezone.utc),
            idle_minutes=args.idle_minutes,
        )
    except BoardStatusError as exc:
        print("board-status: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(board_line(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
