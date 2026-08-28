#!/usr/bin/env python3
"""Collect and render project-scoped health for protected agent processes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA = "agent-health-snapshot-v1"
LIFECYCLE_SCHEMA = "project-lifecycle-list-v1"
INTERVAL_SECONDS = 300
MAX_EXECUTION_BYTES = 1024 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


class AgentHealthError(RuntimeError):
    pass


def load_sibling(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise AgentHealthError(f"cannot load required health component {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


heartbeat_status = load_sibling("startup_factory_heartbeat_status", "heartbeat-status.py")
teamwork_path = load_sibling("startup_factory_teamwork_path", "teamwork-path.py")


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def git_output(repository: Path, *arguments: str) -> str:
    git = "/usr/bin/git" if Path("/usr/bin/git").is_file() else "git"
    try:
        completed = subprocess.run(
            [git, "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentHealthError(f"cannot inspect canonical Git worktree: {exc}") from exc
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        raise AgentHealthError("repository is not inside a valid Git worktree")
    return value


def git_common_directory(repository_raw: str | Path) -> Path:
    repository = Path(repository_raw).resolve(strict=True)
    common_raw = git_output(
        repository, "rev-parse", "--path-format=absolute", "--git-common-dir"
    )
    if "\n" in common_raw:
        raise AgentHealthError("canonical Git common directory is ambiguous")
    try:
        return Path(common_raw).resolve(strict=True)
    except OSError as exc:
        raise AgentHealthError(f"cannot inspect canonical Git common directory: {exc}") from exc


def canonical_teamwork_host(repository_raw: str | Path) -> Path:
    """Return the primary worktree that owns project-wide `.teamwork` state."""

    repository = Path(repository_raw).resolve(strict=True)
    common = git_common_directory(repository)
    listing = git_output(repository, "worktree", "list", "--porcelain")
    primary_raw = next(
        (
            line.removeprefix("worktree ")
            for line in listing.splitlines()
            if line.startswith("worktree ")
        ),
        None,
    )
    if primary_raw is None:
        raise AgentHealthError("Git did not report a primary worktree")
    primary_lexical = Path(os.path.abspath(primary_raw))
    if primary_lexical != Path(os.path.realpath(primary_lexical)):
        raise AgentHealthError("primary Git worktree must not be reached through a symlink")
    try:
        primary = primary_lexical.resolve(strict=True)
    except OSError as exc:
        raise AgentHealthError(f"cannot inspect primary Git worktree: {exc}") from exc
    try:
        top = Path(git_output(primary, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except OSError as exc:
        raise AgentHealthError(f"cannot inspect primary Git worktree: {exc}") from exc
    if top != primary or git_common_directory(primary) != common:
        raise AgentHealthError("primary Git worktree does not share the current project identity")
    return primary


def repository_identity(repository_raw: str | Path) -> str:
    common = git_common_directory(repository_raw)
    info = common.stat()
    material = (
        os.fsencode(common)
        + b"\0"
        + str(info.st_dev).encode("ascii")
        + b"\0"
        + str(info.st_ino).encode("ascii")
    )
    return hashlib.sha256(material).hexdigest()


def directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def open_directory_at(
    parent_descriptor: int, name: str, label: str
) -> int | None:
    try:
        descriptor = os.open(name, directory_flags(), dir_fd=parent_descriptor)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AgentHealthError(f"cannot open {label} safely: {exc}") from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise AgentHealthError(f"{label} is not a directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_workspace_descriptor(workspace_host: Path, workspace: Path) -> int | None:
    """Open a managed workspace without following any relative path component."""

    try:
        relative = workspace.relative_to(workspace_host)
    except ValueError as exc:
        raise AgentHealthError("managed workspace is outside its teamwork host") from exc
    if not relative.parts:
        raise AgentHealthError("managed workspace must be below its teamwork host")
    try:
        named_host = workspace_host.stat(follow_symlinks=False)
        descriptor = os.open(workspace_host, directory_flags())
    except OSError as exc:
        raise AgentHealthError(f"cannot open teamwork host safely: {exc}") from exc
    try:
        opened_host = os.fstat(descriptor)
        if not stat.S_ISDIR(opened_host.st_mode) or (
            opened_host.st_dev,
            opened_host.st_ino,
        ) != (named_host.st_dev, named_host.st_ino):
            raise AgentHealthError("teamwork host changed identity while being opened")
        for part in relative.parts:
            child = open_directory_at(descriptor, part, "managed workspace")
            if child is None:
                os.close(descriptor)
                return None
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_bounded_json_at(parent_descriptor: int, name: str) -> dict[str, Any] | None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AgentHealthError(f"cannot open execution record safely: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_EXECUTION_BYTES:
            return None
        chunks: list[bytes] = []
        remaining = MAX_EXECUTION_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_EXECUTION_BYTES or len(raw) != opened.st_size:
            return None
        after = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            return None
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def execution_binding(
    workspace_host: Path,
    workspace: Path,
    workspace_descriptor: int | None,
    instance: str,
) -> dict[str, Any] | None:
    match = heartbeat_status.TASK_INSTANCE_RE.fullmatch(instance)
    if match is None:
        return None
    role = match.group("role")
    task_key = match.group("task_key")
    attempt = int(match.group("attempt"))
    if not re.fullmatch(r"[a-z0-9-]{1,63}", role) or not IDENTIFIER.fullmatch(task_key):
        return None
    try:
        teamwork_path.child(
            str(workspace_host), workspace, f"executions/{task_key}.json"
        )
    except (OSError, RuntimeError, SystemExit) as exc:
        raise AgentHealthError("cannot resolve managed execution record path") from exc
    if workspace_descriptor is None:
        return None
    executions_descriptor = open_directory_at(
        workspace_descriptor, "executions", "managed executions directory"
    )
    if executions_descriptor is None:
        return None
    try:
        record = read_bounded_json_at(executions_descriptor, f"{task_key}.json")
    finally:
        os.close(executions_descriptor)
    if record is None:
        return None
    task_id = record.get("taskId")
    if (
        not isinstance(task_id, str)
        or not task_id
        or len(task_id) > 1024
        or any(ord(character) < 32 or character == "|" for character in task_id)
        or record.get("taskKey") != task_key
        or record.get("role") != role
        or type(record.get("attempt")) is not int
        or record.get("attempt") != attempt
    ):
        return None
    expected_key = (
        re.sub(r"[^a-zA-Z0-9]+", "-", task_id).strip("-").lower()[:32]
        or "task"
    )
    expected_key += "-" + hashlib.sha256(task_id.encode()).hexdigest()[:10]
    if task_key != expected_key:
        return None
    return {"taskId": task_id, "taskKey": task_key, "role": role, "attempt": attempt}


def heartbeat_value(
    workspace_host: Path,
    workspace: Path,
    workspace_descriptor: int | None,
    instance: str,
    *,
    read: bool = True,
) -> str | None:
    try:
        teamwork_path.child(str(workspace_host), workspace, f"heartbeats/{instance}")
    except (OSError, RuntimeError, SystemExit) as exc:
        raise AgentHealthError("cannot resolve managed heartbeat path") from exc
    if not read or workspace_descriptor is None:
        return None
    heartbeats_descriptor = open_directory_at(
        workspace_descriptor, "heartbeats", "managed heartbeats directory"
    )
    if heartbeats_descriptor is None:
        return None
    try:
        return heartbeat_status.read_heartbeat_at(heartbeats_descriptor, instance)
    finally:
        os.close(heartbeats_descriptor)


def validate_envelope(envelope: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[str]]:
    if not isinstance(envelope, dict) or envelope.get("schemaVersion") != LIFECYCLE_SCHEMA:
        raise AgentHealthError("lifecycle collector returned an unsupported envelope")
    repository_id = envelope.get("repositoryId")
    records = envelope.get("records")
    warnings = envelope.get("warnings")
    legacy_omitted = envelope.get("legacyOmitted")
    if not isinstance(repository_id, str) or not re.fullmatch(r"[0-9a-f]{64}", repository_id):
        raise AgentHealthError("lifecycle envelope has an invalid repository identity")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise AgentHealthError("lifecycle envelope records must be objects")
    if not isinstance(warnings, list) or any(not isinstance(item, str) for item in warnings):
        raise AgentHealthError("lifecycle envelope warnings must be strings")
    if type(legacy_omitted) is not int or legacy_omitted < 0:
        raise AgentHealthError("lifecycle envelope legacy omission count is invalid")
    return repository_id, records, list(warnings)


def assessment_for(
    record: dict[str, Any],
    heartbeat: str | None,
    binding: dict[str, Any] | None,
    now: datetime,
    stuck_minutes: int,
    start_grace_seconds: int,
) -> dict[str, Any]:
    state = record.get("state")
    value = None if state in {"dead", "identity-mismatch"} else heartbeat
    arguments: dict[str, Any] = {
        "expected_instance": record["instance"],
        "start_grace": heartbeat_status.timedelta(seconds=start_grace_seconds),
    }
    if record["category"] == "task":
        if binding is None:
            arguments["expected_role"] = "__missing_execution_binding__"
        else:
            arguments.update(
                expected_task=binding["taskId"],
                expected_role=binding["role"],
                expected_attempt=binding["attempt"],
            )
    else:
        arguments.update(expected_task="-", expected_role=record["instance"])
    return heartbeat_status.classify(
        record,
        value,
        now,
        heartbeat_status.timedelta(minutes=stuck_minutes),
        **arguments,
    )


def build_snapshot(
    envelope: dict[str, Any],
    *,
    repo: str | Path,
    teamwork_host: str | Path | None = None,
    teamwork_root: str,
    now: datetime,
    stuck_minutes: int,
    start_grace_seconds: int,
) -> dict[str, Any]:
    if not 1 <= stuck_minutes <= 24 * 60:
        raise AgentHealthError("stuck minutes must be from 1 to 1440")
    if not 1 <= start_grace_seconds <= 86400:
        raise AgentHealthError("start grace must be from 1 to 86400 seconds")
    repository = Path(repo).resolve(strict=True)
    workspace_host = Path(teamwork_host or repository).resolve(strict=True)
    repository_id, records, warnings = validate_envelope(envelope)
    rows: list[dict[str, Any]] = []
    non_agent_processes_omitted = 0
    for record in records:
        if "auth" in record or "launchToken" in record:
            raise AgentHealthError("lifecycle envelope exposed protected authentication material")
        if record.get("schemaVersion") != 3 or record.get("repositoryId") != repository_id:
            raise AgentHealthError("lifecycle record is not bound to the envelope project")
        team = record.get("team")
        category = record.get("category")
        instance = record.get("instance")
        if (
            not isinstance(team, str)
            or not IDENTIFIER.fullmatch(team)
            or not isinstance(instance, str)
            or not IDENTIFIER.fullmatch(instance)
            or category not in {"gate", "task", "release"}
        ):
            raise AgentHealthError("lifecycle record has an invalid presentation identity")
        if category == "release":
            non_agent_processes_omitted += 1
            continue
        try:
            workspace = teamwork_path.workspace(str(workspace_host), teamwork_root, team)
        except (OSError, RuntimeError, SystemExit) as exc:
            raise AgentHealthError(f"cannot resolve managed team workspace for {team}") from exc
        workspace_descriptor = open_workspace_descriptor(workspace_host, workspace)
        try:
            binding = (
                execution_binding(
                    workspace_host, workspace, workspace_descriptor, instance
                )
                if category == "task"
                else None
            )
            if category == "task" and binding is None:
                warnings.append(
                    f"Managed task agent {team}/{instance} has no unique current execution binding; assignment and percentage were omitted."
                )
            try:
                heartbeat = heartbeat_value(
                    workspace_host,
                    workspace,
                    workspace_descriptor,
                    instance,
                    read=record.get("state") not in {"dead", "identity-mismatch"},
                )
            except heartbeat_status.HeartbeatError as exc:
                assessment = heartbeat_status.stalled(
                    "stalled:invalid-heartbeat", None, str(exc)
                )
            else:
                assessment = assessment_for(
                    record,
                    heartbeat,
                    binding,
                    now,
                    stuck_minutes,
                    start_grace_seconds,
                )
        finally:
            if workspace_descriptor is not None:
                os.close(workspace_descriptor)
        try:
            created = heartbeat_status.parse_time(record.get("createdAt"), "lifecycle createdAt")
        except heartbeat_status.HeartbeatError as exc:
            raise AgentHealthError(str(exc)) from exc
        elapsed = (
            max(0, int((now - created).total_seconds()))
            if record.get("state") == "live"
            else None
        )
        if binding is not None:
            role = binding["role"]
            task_id = binding["taskId"]
            attempt = binding["attempt"]
        elif category == "task":
            match = heartbeat_status.TASK_INSTANCE_RE.fullmatch(instance)
            role = match.group("role") if match else instance
            task_id = None
            attempt = int(match.group("attempt")) if match else None
        else:
            role = instance
            task_id = None
            attempt = None
        progress = assessment.get("progressPercent")
        if type(progress) is not int or not 0 <= progress <= 100:
            progress = None
        rows.append(
            {
                "team": team,
                "category": category,
                "instance": instance,
                "role": role,
                "taskId": task_id,
                "attempt": attempt,
                "lifecycleState": record.get("state"),
                "verdict": assessment["verdict"],
                "activity": assessment.get("activity"),
                "progressPercent": progress,
                "progressSource": "self-reported" if progress is not None else None,
                "elapsedSeconds": elapsed,
                "updatedAt": assessment.get("observedAt") or record["createdAt"],
                "nextActionBy": assessment["nextActionBy"],
            }
        )
    if non_agent_processes_omitted:
        warnings.append(
            f"Omitted {non_agent_processes_omitted} managed non-agent release "
            f"process{'es' if non_agent_processes_omitted != 1 else ''}."
        )
    rows.sort(key=lambda row: (row["team"], row["category"], row["instance"]))
    return {
        "schemaVersion": SCHEMA,
        "generatedAt": iso(now),
        "repositoryId": repository_id,
        "intervalSeconds": INTERVAL_SECONDS,
        "presentationOnly": True,
        "nonAgentProcessesOmitted": non_agent_processes_omitted,
        "agents": rows,
        "warnings": warnings,
    }


def unmanaged_snapshot(repository_id: str, now: datetime) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA,
        "generatedAt": iso(now),
        "repositoryId": repository_id,
        "intervalSeconds": INTERVAL_SECONDS,
        "presentationOnly": True,
        "nonAgentProcessesOmitted": 0,
        "agents": [],
        "warnings": [
            "Lifecycle supervision is unmanaged; agent health is unavailable and no workspace-authored rows were fabricated."
        ],
    }


def human_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h{minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d{hours:02d}h"


def render_table(snapshot: dict[str, Any]) -> str:
    headings = ("TEAM", "AGENT", "ASSIGNMENT", "STATUS", "PROGRESS", "UPDATED")
    values: list[tuple[str, ...]] = []
    for row in snapshot["agents"]:
        progress = (
            f"{row['progressPercent']}%"
            if row["progressPercent"] is not None
            else (
                human_duration(row["elapsedSeconds"])
                if row["elapsedSeconds"] is not None
                else "-"
            )
        )
        assignment = row["taskId"]
        if assignment is None:
            assignment = "gate queue" if row["category"] == "gate" else "-"
        values.append(
            (
                row["team"],
                row["role"],
                assignment,
                row["verdict"],
                progress,
                row["updatedAt"],
            )
        )
    widths = [len(item) for item in headings]
    for row in values:
        for index, item in enumerate(row):
            widths[index] = max(widths[index], len(str(item)))

    def line(row: tuple[str, ...]) -> str:
        return "  ".join(str(item).ljust(widths[index]) for index, item in enumerate(row)).rstrip()

    lines = [line(headings), line(tuple("-" * width for width in widths))]
    lines.extend(line(row) for row in values)
    if not values:
        lines.append("(no managed agents for this project)")
    lines.append("* Percentages are self-reported, fresh, and presentation-only.")
    lines.extend(f"Warning: {warning}" for warning in snapshot["warnings"])
    return "\n".join(lines)


def lifecycle_envelope(repository: Path, lifecycle_root: str) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).with_name("process-lifecycle.py")),
        "project-list",
        "--root",
        lifecycle_root,
        "--repo",
        str(repository),
    ]
    try:
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentHealthError(f"cannot read protected lifecycle state: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "protected lifecycle collector failed"
        raise AgentHealthError(detail)
    try:
        envelope = json.loads(completed.stdout)
    except ValueError as exc:
        raise AgentHealthError("protected lifecycle collector returned invalid JSON") from exc
    if not isinstance(envelope, dict):
        raise AgentHealthError("protected lifecycle collector returned a non-object envelope")
    return envelope


def watch(
    emit: Callable[[], None],
    *,
    interval_seconds: int = INTERVAL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    maximum_snapshots: int | None = None,
) -> None:
    if interval_seconds <= 0:
        raise AgentHealthError("watch interval must be positive")
    deadline = monotonic()
    emitted = 0
    while maximum_snapshots is None or emitted < maximum_snapshots:
        remaining = deadline - monotonic()
        if remaining > 0:
            sleep(remaining)
        emit()
        emitted += 1
        deadline += interval_seconds
        observed = monotonic()
        while deadline <= observed:
            deadline += interval_seconds


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--repo", required=True)
    result.add_argument("--teamwork-root", required=True)
    result.add_argument("--lifecycle-root")
    result.add_argument("--stuck-minutes", required=True, type=int)
    result.add_argument("--start-grace-seconds", required=True, type=int)
    result.add_argument("--json", action="store_true")
    result.add_argument("--watch", action="store_true")
    result.add_argument("--now", help="fixed ISO-8601 time for a one-shot deterministic probe")
    return result


def main() -> int:
    args = parser().parse_args()
    if args.watch and args.now:
        raise AgentHealthError("--now cannot be combined with --watch")
    repository = Path(args.repo).resolve(strict=True)
    teamwork_host = canonical_teamwork_host(repository)
    fixed_now = heartbeat_status.parse_time(args.now, "now") if args.now else None

    def emit() -> None:
        now = fixed_now or datetime.now(timezone.utc)
        if args.lifecycle_root:
            snapshot = build_snapshot(
                lifecycle_envelope(repository, args.lifecycle_root),
                repo=repository,
                teamwork_host=teamwork_host,
                teamwork_root=args.teamwork_root,
                now=now,
                stuck_minutes=args.stuck_minutes,
                start_grace_seconds=args.start_grace_seconds,
            )
        else:
            snapshot = unmanaged_snapshot(repository_identity(repository), now)
        if args.json:
            print(json.dumps(snapshot, sort_keys=True, separators=(",", ":")), flush=True)
        else:
            print(render_table(snapshot), flush=True)

    if args.watch:
        watch(emit)
    else:
        emit()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AgentHealthError, heartbeat_status.HeartbeatError) as exc:
        print(f"agent-health: {exc}", file=sys.stderr)
        raise SystemExit(1)
