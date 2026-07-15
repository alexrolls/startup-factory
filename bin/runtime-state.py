#!/usr/bin/env python3
"""Durable event, projection, and task-packet primitives for Startup Factory."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
from task_metadata import is_fast_task, parse_task_metadata


MARKER_RE = re.compile(r"^\s*\[([\w-]+)\]")
CURRENT_MARKERS = {
    "resume-review",
    "resume-plan",
    "dependency-hold",
    "design-note",
    "design-approved",
    "design-pushback",
    "sceptical-design-approved",
    "sceptical-design-pushback",
    "product-approval",
    "product-pushback",
    "review-request",
    "review-findings",
    "review-approval",
    "architecture-approval",
    "sceptical-architecture-approval",
    "handoff",
    "andon",
    "escalation",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_key(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()[:32] or "task"
    digest = hashlib.sha256(value.encode()).hexdigest()[:10]
    return f"{slug}-{digest}"


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    os.replace(temp, path)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(value)
    os.replace(temp, path)


def event_path(workspace: Path) -> Path:
    return workspace / "events.ndjson"


def append_event(workspace: Path, event: dict) -> dict:
    workspace.mkdir(parents=True, exist_ok=True)
    event = {
        "eventId": str(uuid.uuid4()),
        "timestamp": utc_now(),
        **event,
    }
    path = event_path(workspace)
    with path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return event


def marker_positions(task: dict) -> dict[str, int]:
    positions: dict[str, int] = {}
    for index, comment in enumerate(task.get("comments") or []):
        match = MARKER_RE.match(str(comment.get("body") or ""))
        if match:
            positions[match.group(1)] = index
    return positions


def derive_stage(task: dict, terminal: set[str]) -> tuple[str, str]:
    status = task.get("status") or "Unknown"
    markers = marker_positions(task)
    request = markers.get("review-request", -1)
    findings = markers.get("review-findings", -1)
    design_note = markers.get("design-note", -1)
    design_approved = markers.get("design-approved", -1)
    design_pushback = markers.get("design-pushback", -1)
    sceptical_design_approved = markers.get("sceptical-design-approved", -1)
    sceptical_design_pushback = markers.get("sceptical-design-pushback", -1)
    review_approved = markers.get("review-approval", -1)
    architecture_approved = markers.get("architecture-approval", -1)
    sceptical_architecture_approved = markers.get(
        "sceptical-architecture-approval", -1
    )

    if status in terminal:
        return "integrated", "committed and terminal"
    if status == "Blocked":
        return "blocked", "waiting for blocker resolution"
    if status == "Planned":
        if design_note < 0:
            return "planned", "awaiting design note"
        if (
            design_pushback > design_approved
            or sceptical_design_pushback > sceptical_design_approved
        ):
            return "design-rework", "design pushback open"
        if design_approved > design_note and sceptical_design_approved > design_note:
            return "ready", "independent design approvals present; ready for dispatch"
        return "design-review", "design note awaiting verdict"
    if status == "Active":
        if (
            design_pushback > design_approved
            or sceptical_design_pushback > sceptical_design_approved
        ):
            return "design-rework", "design pushback open"
        if design_note >= 0 and (
            design_approved <= design_note
            or sceptical_design_approved <= design_note
        ):
            return "design-review", "design note awaiting verdict"
        if findings > request:
            return "rework", "review findings require a new review request"
        return "implementing", "implementation in progress"
    if status == "Review":
        if request < 0:
            return "review-anomaly", "Review status has no review request"
        if (
            review_approved > request
            and architecture_approved > request
            and sceptical_architecture_approved > request
        ):
            return "integrating", "all approvals present"
        waiting = []
        if review_approved <= request:
            waiting.append("QA/reviewer")
        if architecture_approved <= request:
            waiting.append("architecture")
        if sceptical_architecture_approved <= request:
            waiting.append("independent architecture challenge")
        return "review", "waiting for " + " and ".join(waiting)
    return status.lower().replace(" ", "-"), "tracker status: %s" % status


def execution_for(workspace: Path, task_id: str) -> dict:
    return read_json(workspace / "executions" / (safe_key(task_id) + ".json"), {})


def progress_body(task_id: str, stage: str, actor: str, attempt: int, summary: str) -> str:
    return "\n".join(
        [
            "[progress]",
            "task: %s" % task_id,
            "stage: %s" % stage,
            "actor: %s" % (actor or "unassigned"),
            "attempt: %s" % attempt,
            "updated-at: %s" % utc_now(),
            "summary: %s" % summary,
        ]
    )


def run_tracker(tracker_ops: str, *args: str) -> None:
    result = subprocess.run([tracker_ops, *args], text=True, capture_output=True)
    if result.returncode:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)


def cmd_emit(args) -> None:
    workspace = Path(args.workspace)
    event = append_event(
        workspace,
        {
            "team": args.team,
            "featureId": args.feature,
            "taskId": None if args.task == "-" else args.task,
            "attempt": args.attempt,
            "actor": args.actor,
            "type": args.type,
            "stage": args.stage,
            "summary": args.summary,
            "artifact": args.artifact,
        },
    )
    if args.tracker_ops and args.task != "-":
        body_dir = workspace / "pm"
        body_dir.mkdir(parents=True, exist_ok=True)
        body_file = body_dir / (safe_key(args.task) + "-progress.md")
        body_file.write_text(progress_body(args.task, args.stage, args.actor, args.attempt, args.summary) + "\n")
        run_tracker(args.tracker_ops, "upsert-progress", args.task, str(body_file))
    print(json.dumps(event, ensure_ascii=False))


def cmd_count(args) -> None:
    path = event_path(Path(args.workspace))
    print(path.stat().st_size if path.exists() else 0)


def cmd_key(args) -> None:
    print(safe_key(args.value))


def cmd_wait(args) -> None:
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        path = event_path(Path(args.workspace))
        cursor = path.stat().st_size if path.exists() else 0
        if cursor != args.count:
            print(cursor)
            return
        time.sleep(0.25)
    print(args.count)


def cmd_sync(args) -> None:
    workspace = Path(args.workspace)
    payload = read_json(Path(args.tasks), {})
    tasks = payload.get("tasks") or []
    try:
        ignored_raw = json.loads(args.ignored_labels_json)
    except ValueError as exc:
        raise SystemExit("runtime-state: ignored labels must be valid JSON") from exc
    if not isinstance(ignored_raw, list) or any(
        not isinstance(item, str) for item in ignored_raw
    ):
        raise SystemExit("runtime-state: ignored labels must be a JSON string array")
    ignored = {item.strip().casefold() for item in ignored_raw}
    if any(not item for item in ignored) or len(ignored) != len(ignored_raw):
        raise SystemExit("runtime-state: ignored labels contain an empty or duplicate name")
    held_statuses = set(args.held_status)
    automated_tasks, human_tasks, held_tasks = [], [], []
    for task in tasks:
        labels = task.get("labels") or []
        if not isinstance(labels, list) or any(not isinstance(item, str) for item in labels):
            raise SystemExit("runtime-state: task labels must be a string array")
        if ignored.intersection(item.strip().casefold() for item in labels):
            target = human_tasks
        elif task.get("status") in held_statuses:
            # A blocked ticket is a hard write fence.  Even managed progress
            # comments would be automated work on the ticket after the human
            # hold was raised, so retain it only in the feature digest.
            target = held_tasks
        else:
            target = automated_tasks
        target.append(task)
    terminal = set(args.terminal)
    projection_path = workspace / "pm-projection.json"
    projection = read_json(projection_path, {"tasks": {}, "digest": None})
    next_projection = json.loads(json.dumps(projection))

    for task in human_tasks + held_tasks:
        next_projection.setdefault("tasks", {}).pop(str(task["taskId"]), None)

    for task in automated_tasks:
        task_id = str(task["taskId"])
        stage, summary = derive_stage(task, terminal)
        execution = execution_for(workspace, task_id)
        actor = task.get("assignee") or execution.get("role") or "unassigned"
        attempt = int(execution.get("attempt") or 1)
        current = {"stage": stage, "summary": summary, "actor": actor, "attempt": attempt}
        if projection.get("tasks", {}).get(task_id) == current:
            continue
        body_dir = workspace / "pm"
        body_dir.mkdir(parents=True, exist_ok=True)
        body_file = body_dir / (safe_key(task_id) + "-progress.md")
        body_file.write_text(progress_body(task_id, stage, actor, attempt, summary) + "\n")
        run_tracker(args.tracker_ops, "upsert-progress", task_id, str(body_file))
        append_event(
            workspace,
            {
                "team": args.team,
                "featureId": args.feature,
                "taskId": task_id,
                "attempt": attempt,
                "actor": actor,
                "type": "task.stage.changed",
                "stage": stage,
                "summary": summary,
                "artifact": str(body_file),
            },
        )
        next_projection.setdefault("tasks", {})[task_id] = current

    digest_lines = ["[digest]", "updated-at: %s" % utc_now()]
    for task in tasks:
        task_id = str(task["taskId"])
        if task in human_tasks:
            digest_lines.append(
                "%s %s - [%s] / human-owned (automation ignored)"
                % (task_id, task.get("title") or "", task.get("status"))
            )
            continue
        stage, summary = derive_stage(task, terminal)
        suffix = " (%s)" % summary if stage in {"blocked", "design-rework", "review-anomaly"} else ""
        digest_lines.append("%s %s - [%s] / %s%s" % (task_id, task.get("title") or "", task.get("status"), stage, suffix))
    digest = "\n".join(digest_lines)
    digest_fingerprint = hashlib.sha256("\n".join(digest_lines[2:]).encode()).hexdigest()
    if projection.get("digest") != digest_fingerprint:
        body_dir = workspace / "pm"
        body_dir.mkdir(parents=True, exist_ok=True)
        digest_file = body_dir / "feature-digest.md"
        digest_file.write_text(digest + "\n")
        run_tracker(args.tracker_ops, "upsert-digest", args.feature, str(digest_file))
        append_event(
            workspace,
            {
                "team": args.team,
                "featureId": args.feature,
                "taskId": None,
                "attempt": 0,
                "actor": "dispatcher",
                "type": "feature.digest.updated",
                "stage": "sync",
                "summary": "feature digest synchronized",
                "artifact": str(digest_file),
            },
        )
        next_projection["digest"] = digest_fingerprint

    write_json(projection_path, next_projection)


def model_profile(task: dict, metadata: dict) -> str:
    explicit = metadata.get("modelProfile")
    if explicit in {"fast", "standard", "strong"}:
        return explicit
    text = "%s\n%s" % (task.get("title") or "", task.get("description") or "")
    if re.search(
        r"\b(?:auth\w*|security|permissions?|tenant|migrations?|schemas?|concurren\w*|races?|crypt\w*|contracts?|public\s+api)\b",
        text,
        re.I,
    ):
        return "strong"
    if is_fast_task(task, metadata):
        return "fast"
    return "standard"


def read_config(path: Path) -> dict:
    result = {}
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        match = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
        if match:
            raw = match.group(2).strip()
            if raw.startswith('"'):
                value = raw[1:].split('"', 1)[0]
            else:
                value = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
            result[match.group(1)] = None if value == "null" else value
    return result


def current_comments(task: dict) -> list[str]:
    latest = {}
    additive = []
    for comment in task.get("comments") or []:
        body = str(comment.get("body") or "").strip()
        match = MARKER_RE.match(body)
        if not match:
            continue
        marker = match.group(1)
        if marker == "divergence":
            additive.append(body)
        elif marker in CURRENT_MARKERS:
            latest[marker] = body
    ordered = [latest[key] for key in sorted(latest)]
    return ordered + additive


def resume_context(workspace: Path, task_id: str) -> dict | None:
    path = workspace / "task-holds.json"
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise SystemExit("runtime-state: task hold registry must be a non-symlink regular file")
    registry = read_json(path, None)
    if (
        not isinstance(registry, dict)
        or registry.get("schemaVersion") != 1
        or not isinstance(registry.get("tasks"), dict)
    ):
        raise SystemExit("runtime-state: task hold registry has an unsupported schema")
    entry = registry["tasks"].get(safe_key(task_id))
    if entry is None:
        return None
    if not isinstance(entry, dict) or entry.get("taskId") != task_id:
        raise SystemExit("runtime-state: task hold registry identity mismatch")
    if entry.get("state") != "resumed":
        return None
    required = (
        "holdId",
        "generation",
        "blockedSnapshotPath",
        "blockedSnapshotDigest",
        "resumeSnapshotPath",
        "resumeSnapshotDigest",
        "resumeRequestPath",
        "resumeCommunicationDigest",
        "resumeVerdict",
        "clearedAt",
    )
    if any(entry.get(name) in (None, "") for name in required):
        raise SystemExit("runtime-state: resumed hold lacks its review evidence")
    return {name: entry[name] for name in required}


def deterministic_claim_id(
    team: str, feature: str, task: str, role: str, attempt: int, target: str
) -> str:
    material = "\0".join((team, feature, task, role, str(attempt), target)).encode()
    return "dispatch-" + hashlib.sha256(material).hexdigest()[:32]


def cmd_claim(args) -> None:
    if args.attempt < 1:
        raise SystemExit("runtime-state: claim attempt must be positive")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,63}", args.team):
        raise SystemExit("runtime-state: unsafe claim team")
    if not re.fullmatch(r"[a-z0-9-]{1,63}", args.role):
        raise SystemExit("runtime-state: unsafe claim role")
    expected_id = deterministic_claim_id(
        args.team, args.feature, args.task, args.role, args.attempt, args.target
    )
    if args.claim_id != expected_id:
        raise SystemExit("runtime-state: claim id does not match its immutable identity")
    workspace = Path(args.workspace).resolve()
    key = safe_key(args.task)
    identity = {
        "schemaVersion": 1,
        "team": args.team,
        "featureId": args.feature,
        "taskId": args.task,
        "taskKey": key,
        "attempt": args.attempt,
        "role": args.role,
        "claimId": args.claim_id,
        "targetStatus": args.target,
    }
    digest = "sha256:" + hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    record = {**identity, "claimDigest": digest, "recordedAt": utc_now()}
    path = workspace / "claims" / (key + ".json")
    if path.is_symlink():
        raise SystemExit("runtime-state: claim record must not be a symlink")
    existing = read_json(path, {})
    if existing:
        if any(existing.get(name) != value for name, value in record.items() if name != "recordedAt"):
            raise SystemExit("runtime-state: task already has a different durable claim identity")
        print(json.dumps(existing, ensure_ascii=False))
        return
    write_json(path, record)
    print(json.dumps(record, ensure_ascii=False))


def cmd_packet(args) -> None:
    workspace = Path(args.workspace)
    payload = read_json(Path(args.tasks), {})
    task = next((item for item in payload.get("tasks") or [] if str(item.get("taskId")) == args.task), None)
    if not task:
        raise SystemExit("runtime-state: task '%s' not present in %s" % (args.task, args.tasks))

    metadata = parse_task_metadata(task.get("description"), task.get("title"))
    profile = model_profile(task, metadata)
    key = safe_key(args.task)
    artifact_dir = workspace / "artifacts" / key / ("attempt-%s" % args.attempt)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    packet_json = artifact_dir / "task-packet.json"
    packet_md = artifact_dir / "task-packet.md"
    report_md = artifact_dir / "task-report.md"
    execution_path = workspace / "executions" / (key + ".json")
    existing = read_json(execution_path, {})
    if existing:
        previous_attempt = int(existing.get("attempt") or 0)
        if previous_attempt > args.attempt:
            raise SystemExit("runtime-state: refusing stale attempt %s; latest is %s" % (args.attempt, previous_attempt))
        if previous_attempt == args.attempt:
            expected = {
                "role": args.role,
                "branch": args.branch,
                "worktree": args.worktree,
            }
            if any(existing.get(name) != value for name, value in expected.items()):
                raise SystemExit("runtime-state: attempt %s already has a different execution identity" % args.attempt)
            if packet_json.exists() and packet_md.exists() and report_md.exists():
                print(json.dumps(existing, ensure_ascii=False))
                return
    config = read_config(Path(args.config))
    contracts = Path(args.contracts).read_text() if Path(args.contracts).exists() else "No registered contracts."
    baseline = Path(args.baseline).read_text() if Path(args.baseline).exists() else "No baseline manifest exists; report this as a concern."
    comments = current_comments(task)
    resumed = resume_context(workspace, args.task)
    packet = {
        "schemaVersion": 1,
        "featureId": args.feature,
        "taskId": args.task,
        "attempt": args.attempt,
        "role": args.role,
        "title": task.get("title"),
        "status": task.get("status"),
        "description": task.get("description"),
        "dependencies": task.get("blockedBy") or [],
        "metadata": metadata,
        "modelProfile": profile,
        "currentArtifacts": comments,
        "resumeReview": resumed,
        "validation": {key: value for key, value in config.items() if key.startswith("VALIDATE_") and value},
        "workspace": args.worktree,
        "reportPath": str(report_md),
    }
    write_json(packet_json, packet)

    lines = [
        "# Task Packet: %s" % args.task,
        "",
        "- Feature: `%s`" % args.feature,
        "- Role: `%s`" % args.role,
        "- Attempt: `%s`" % args.attempt,
        "- Model profile: `%s`" % profile,
        "- Working copy: `%s`" % args.worktree,
        "- Report: `%s`" % report_md,
        "",
        "## Requirement",
        "",
        task.get("description") or "No description supplied.",
        "",
        "## Dependencies",
        "",
        "\n".join("- `%s`" % item for item in (task.get("blockedBy") or [])) or "- None",
        "",
        "## Current Binding Artifacts",
        "",
        "\n\n".join(comments) or "None.",
        "",
        "## Blocked Resume Evidence",
        "",
        (
            "This is a fresh post-Blocked attempt. Read the complete blocked and resume snapshots, "
            "the delta request, and the binding review artifacts before changing code.\n\n"
            "- Hold: `%s`\n- Blocked snapshot: `%s`\n- Resume snapshot: `%s`\n"
            "- Resume review request: `%s`\n- Verdict: `%s`"
            % (
                resumed["holdId"],
                resumed["blockedSnapshotPath"],
                resumed["resumeSnapshotPath"],
                resumed["resumeRequestPath"],
                resumed["resumeVerdict"],
            )
            if resumed
            else "Not a post-Blocked resume attempt."
        ),
        "",
        "## Contract Registry",
        "",
        contracts.strip(),
        "",
        "## Baseline",
        "",
        baseline.strip(),
        "",
        "## Validation",
        "",
    ]
    validations = packet["validation"]
    lines.extend(["- `%s`: `%s`" % item for item in validations.items()] or ["- No validation commands configured; report every skip."])
    lines.extend(
        [
            "",
            "## Output Contract",
            "",
            "Write the complete report to the report path. Return only:",
            "",
            "- `Status: DONE | DONE_WITH_CONCERNS | BLOCKED | NEEDS_CONTEXT`",
            "- task-branch checkpoint commits",
            "- one-line test summary",
            "- concerns",
            "- report path",
        ]
    )
    write_text(packet_md, "\n".join(lines).rstrip() + "\n")
    if not report_md.exists():
        write_text(report_md, "# Task Report\n\nStatus: IN_PROGRESS\n")

    execution = {
        **existing,
        "schemaVersion": 1,
        "featureId": args.feature,
        "taskId": args.task,
        "taskKey": key,
        "attempt": args.attempt,
        "role": args.role,
        "branch": args.branch,
        "worktree": args.worktree,
        "packetPath": str(packet_md),
        "packetJsonPath": str(packet_json),
        "reportPath": str(report_md),
        "modelProfile": profile,
        "updatedAt": utc_now(),
    }
    write_json(execution_path, execution)
    print(json.dumps(execution, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    emit = sub.add_parser("emit")
    emit.add_argument("--workspace", required=True)
    emit.add_argument("--team", required=True)
    emit.add_argument("--feature", required=True)
    emit.add_argument("--task", required=True)
    emit.add_argument("--attempt", type=int, default=1)
    emit.add_argument("--actor", required=True)
    emit.add_argument("--type", required=True)
    emit.add_argument("--stage", required=True)
    emit.add_argument("--summary", default="")
    emit.add_argument("--artifact")
    emit.add_argument("--tracker-ops")
    emit.set_defaults(func=cmd_emit)

    count = sub.add_parser("count")
    count.add_argument("--workspace", required=True)
    count.set_defaults(func=cmd_count)

    key = sub.add_parser("key")
    key.add_argument("value")
    key.set_defaults(func=cmd_key)

    wait = sub.add_parser("wait")
    wait.add_argument("--workspace", required=True)
    wait.add_argument("--count", type=int, required=True)
    wait.add_argument("--timeout", type=float, required=True)
    wait.set_defaults(func=cmd_wait)

    sync = sub.add_parser("sync")
    sync.add_argument("--workspace", required=True)
    sync.add_argument("--team", required=True)
    sync.add_argument("--feature", required=True)
    sync.add_argument("--tasks", required=True)
    sync.add_argument("--tracker-ops", required=True)
    sync.add_argument("--terminal", action="append", default=[])
    sync.add_argument("--held-status", action="append", default=[])
    sync.add_argument("--ignored-labels-json", default="[]")
    sync.set_defaults(func=cmd_sync)

    packet = sub.add_parser("packet")
    packet.add_argument("--workspace", required=True)
    packet.add_argument("--tasks", required=True)
    packet.add_argument("--feature", required=True)
    packet.add_argument("--task", required=True)
    packet.add_argument("--role", required=True)
    packet.add_argument("--attempt", type=int, required=True)
    packet.add_argument("--worktree", required=True)
    packet.add_argument("--branch", required=True)
    packet.add_argument("--config", required=True)
    packet.add_argument("--contracts", required=True)
    packet.add_argument("--baseline", required=True)
    packet.set_defaults(func=cmd_packet)

    claim = sub.add_parser("claim")
    claim.add_argument("--workspace", required=True)
    claim.add_argument("--team", required=True)
    claim.add_argument("--feature", required=True)
    claim.add_argument("--task", required=True)
    claim.add_argument("--role", required=True)
    claim.add_argument("--attempt", type=int, required=True)
    claim.add_argument("--claim-id", required=True)
    claim.add_argument("--target", required=True)
    claim.set_defaults(func=cmd_claim)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
