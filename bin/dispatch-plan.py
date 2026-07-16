#!/usr/bin/env python3
"""Build one deterministic dispatch action plan from a tracker snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
from product_acceptance import ProductAcceptancePending, evaluate as evaluate_product_acceptance, validate_request
from task_metadata import parse_task_metadata


MARKER_RE = re.compile(r"^\s*\[([\w-]+)\]")
HOLD_STATES = {"blocked", "resume-review-pending", "manual-takeover"}


def last(task: dict, *names: str) -> int:
    index = -1
    for i, comment in enumerate(task.get("comments") or []):
        match = MARKER_RE.match(str(comment.get("body") or ""))
        if match and match.group(1) in names:
            index = i
    return index


def design_request(task: dict) -> int:
    return last(task, "design-note", "resume-plan")


def metadata(task: dict) -> dict:
    return parse_task_metadata(task.get("description"), task.get("title"))


def resources(task: dict) -> set[str]:
    data = metadata(task)
    return {"file:" + item for item in data["files"]} | {"resource:" + item for item in data["resources"]}


def claims_conflict(left: set[str], right: set[str]) -> bool:
    if left & right:
        return True
    left_files = [item[5:].rstrip("/") for item in left if item.startswith("file:")]
    right_files = [item[5:].rstrip("/") for item in right if item.startswith("file:")]
    return any(a.startswith(b + "/") or b.startswith(a + "/") for a in left_files for b in right_files)


def open_directory(path: Path, label: str) -> int:
    flags = os.O_RDONLY
    for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"):
        flags |= getattr(os, name, 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"cannot securely open {label}: {exc}") from exc


def open_child_directory(parent_fd: int, name: str, label: str) -> int:
    flags = os.O_RDONLY
    for flag in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"):
        flags |= getattr(os, flag, 0)
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuntimeError(f"cannot securely open {label}: {exc}") from exc


def read_regular_at(parent_fd: int, name: str, label: str, limit: int = 64 * 1024 * 1024) -> str:
    flags = os.O_RDONLY
    for flag in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, flag, 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuntimeError(f"cannot securely open {label}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"{label} must be a non-symlink regular file")
        if info.st_size > limit:
            raise RuntimeError(f"{label} exceeds the {limit}-byte safety limit")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise RuntimeError(f"{label} exceeds the {limit}-byte safety limit")
        return raw.decode("utf-8")
    finally:
        os.close(descriptor)


def task_key(task_id: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", task_id).strip("-").lower()[:32] or "task"
    return "%s-%s" % (slug, hashlib.sha256(task_id.encode()).hexdigest()[:10])


def strict_object(raw: str, label: str) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise RuntimeError(f"{label} has duplicate field {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def execution_identity(
    executions_fd: int | None,
    workdir: Path,
    team: str,
    feature_id: str,
    task_id: str,
) -> tuple[str, int] | None:
    key = task_key(task_id)
    if executions_fd is None:
        return None
    try:
        body = read_regular_at(executions_fd, key + ".json", "task execution record", 1024 * 1024)
    except FileNotFoundError:
        return None
    record = strict_object(body, "task execution record")
    role = record.get("role")
    attempt = record.get("attempt")
    if not isinstance(role, str) or not re.fullmatch(r"[a-z0-9-]{1,63}", role):
        raise RuntimeError("task execution record has an unsafe role")
    if type(attempt) is not int or attempt < 1:
        raise RuntimeError("task execution record has an invalid attempt")
    expected = {
        "schemaVersion": 1,
        "featureId": feature_id,
        "taskId": task_id,
        "taskKey": key,
        "branch": f"agent-task/{team}/{key}",
        "worktree": str(workdir / "worktrees" / f"{role}#{attempt}-{key}"),
        "packetPath": str(workdir / "artifacts" / key / f"attempt-{attempt}" / "task-packet.md"),
        "packetJsonPath": str(workdir / "artifacts" / key / f"attempt-{attempt}" / "task-packet.json"),
        "reportPath": str(workdir / "artifacts" / key / f"attempt-{attempt}" / "task-report.md"),
    }
    if any(record.get(name) != value for name, value in expected.items()):
        raise RuntimeError("task execution record does not match its team/feature/task/attempt binding")
    return role, attempt


def claim_identity(
    claims_fd: int | None,
    team: str,
    feature_id: str,
    task: dict,
    working_status: str,
) -> tuple[str, int] | None:
    task_id = str(task["taskId"])
    key = task_key(task_id)
    if claims_fd is None:
        return None
    try:
        body = read_regular_at(claims_fd, key + ".json", "task claim record", 1024 * 1024)
    except FileNotFoundError:
        return None
    record = strict_object(body, "task claim record")
    role = record.get("role")
    attempt = record.get("attempt")
    if not isinstance(role, str) or not re.fullmatch(r"[a-z0-9-]{1,63}", role):
        raise RuntimeError("task claim record has an unsafe role")
    if type(attempt) is not int or attempt < 1:
        raise RuntimeError("task claim record has an invalid attempt")
    expected = {
        "schemaVersion": 1,
        "team": team,
        "featureId": feature_id,
        "taskId": task_id,
        "taskKey": key,
        "attempt": attempt,
        "role": role,
        "targetStatus": working_status,
    }
    expected_claim_id = "dispatch-" + hashlib.sha256(
        "\0".join((team, feature_id, task_id, role, str(attempt), working_status)).encode()
    ).hexdigest()[:32]
    expected["claimId"] = expected_claim_id
    digest = "sha256:" + hashlib.sha256(
        json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    if any(record.get(name) != value for name, value in expected.items()):
        raise RuntimeError("task claim record does not match its team/feature/task/attempt binding")
    if record.get("claimDigest") != digest:
        raise RuntimeError("task claim record digest does not match its immutable identity")
    expected_tail = (
        f"claim-id: {expected_claim_id}\n"
        f"role: {role}\n"
        f"target-status: {working_status}\n\n"
        "— dispatcher"
    )

    def valid_receipt(comment: dict) -> bool:
        body = str(comment.get("body") or "").strip()
        if not body.startswith("[claim]") or "claim-id:" not in body:
            return False
        position = body.find("claim-id:")
        prefix = body[len("[claim]"):position]
        if prefix != "\n" and not re.fullmatch(r" \(\d{4}-\d{2}-\d{2}\): ", prefix):
            return False
        return body[position:] == expected_tail

    matching = [
        comment
        for comment in task.get("comments") or []
        if valid_receipt(comment)
    ]
    if len(matching) != 1:
        raise RuntimeError("active task claim lacks one exact tracker-side claim receipt")
    return role, attempt


def emit(*parts) -> None:
    print("\t".join(str(part).replace("\t", " ").replace("\n", " ") for part in parts))


def ignored_labels(raw: str) -> set[str]:
    try:
        values = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"ignored task labels are not valid JSON: {exc}") from exc
    if not isinstance(values, list):
        raise RuntimeError("ignored task labels must be a JSON list")
    result: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value or value != value.strip():
            raise RuntimeError("ignored task labels contain a malformed label")
        canonical = value.casefold()
        if canonical in result:
            raise RuntimeError("ignored task labels contain a case-insensitive duplicate")
        result.add(canonical)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--team", required=True)
    parser.add_argument("--feature", required=True)
    parser.add_argument("--stuck-minutes", type=int, required=True)
    parser.add_argument("--execution", choices=["sequential", "parallel"], required=True)
    parser.add_argument("--max-active", type=int)
    parser.add_argument("--ignored-labels-json", default="[]")
    args = parser.parse_args()

    skill = Path(args.skill)
    workdir = Path(args.workdir)
    workdir_fd = open_directory(workdir, "team workspace")
    board = json.loads((skill / "config" / "statuses.config.json").read_text())
    payload = json.loads(read_regular_at(workdir_fd, "tasks.json", "tracker snapshot"))
    try:
        executions_fd = open_child_directory(workdir_fd, "executions", "execution-record directory")
    except FileNotFoundError:
        executions_fd = None
    try:
        claims_fd = open_child_directory(workdir_fd, "claims", "claim-record directory")
    except FileNotFoundError:
        claims_fd = None
    try:
        holds = strict_object(
            read_regular_at(workdir_fd, "task-holds.json", "task hold registry"),
            "task hold registry",
        )
    except FileNotFoundError:
        holds = {"schemaVersion": 1, "featureId": args.feature, "tasks": {}}
    if (
        holds.get("schemaVersion") != 1
        or holds.get("featureId") != args.feature
        or not isinstance(holds.get("tasks"), dict)
    ):
        raise RuntimeError("task hold registry has an unsupported or mismatched schema")
    hold_entries = holds["tasks"]
    dependency_verdicts = holds.get("dependencyVerdicts", {})
    if not isinstance(dependency_verdicts, dict):
        raise RuntimeError("task hold registry dependency verdicts are malformed")
    for key, entry in hold_entries.items():
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("taskId"), str)
            or key != task_key(entry["taskId"])
            or entry.get("state")
            not in {"blocked", "resume-review-pending", "manual-takeover", "resumed"}
        ):
            raise RuntimeError("task hold registry contains a malformed identity or state")

    def hold_entry(task_id: str) -> dict | None:
        entry = hold_entries.get(task_key(task_id))
        if entry is not None and entry.get("taskId") != task_id:
            raise RuntimeError("task hold registry identity mismatch")
        return entry

    def task_is_held(task_id: str) -> bool:
        entry = hold_entry(task_id)
        return bool(entry and entry.get("state") in HOLD_STATES)
    tasks = payload.get("tasks") or []
    excluded = ignored_labels(args.ignored_labels_json)
    filtered_tasks = []
    for task in tasks:
        labels = task.get("labels")
        if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
            raise RuntimeError("tracker snapshot task labels must be a list of label names")
        if excluded.intersection(label.casefold() for label in labels):
            continue
        filtered_tasks.append(task)
    tasks = filtered_tasks
    if str(payload.get("featureId") or "") != args.feature:
        raise RuntimeError("tracker snapshot featureId does not match the dispatcher invocation")
    by_id = {str(task["taskId"]): task for task in tasks}
    terminal = {status["name"] for status in board["tasks"]["statuses"] if status.get("terminal")}
    by_kind = {
        status.get("kind"): status["name"]
        for status in board["tasks"]["statuses"]
        if status.get("kind")
    }
    queued_status = by_kind.get("queued", "Planned")
    working_status = by_kind.get("working", "Active")
    review_status = by_kind.get("review", "Review")
    blocked_status = by_kind.get("blocked", "Blocked")

    protocol_team_lead = "team-lead"
    protocol_principal_architect = "principal-architect"
    protocol_sceptical_architect = "sceptical-architect"
    protocol_security_reviewer = "senior-security-engineer"
    protocol_product_manager = None
    specialist_dispatch_tracks: set[str] = set()
    try:
        preset_text = read_regular_at(workdir_fd, "preset.env", "team preset", 1024 * 1024)
    except FileNotFoundError:
        preset_text = None
    if preset_text is not None:
        required_protocol_roles = {
            "TEAM_LEAD": "team-lead",
            "PRINCIPAL_ARCHITECT": "principal-architect",
            "SCEPTICAL_ARCHITECT": "sceptical-architect",
            "SECURITY_REVIEWER": "senior-security-engineer",
        }
        resolved_protocol_roles: dict[str, str] = {}
        for key, fallback in required_protocol_roles.items():
            matches = re.findall(
                rf"^PROTOCOL_{key}=([^\r\n]+)$", preset_text, re.M
            )
            if len(matches) != 1:
                raise RuntimeError(
                    f"team preset must define exactly one mandatory PROTOCOL_{key}"
                )
            value = matches[0].strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", value):
                raise RuntimeError(f"team preset has an invalid mandatory PROTOCOL_{key}")
            resolved_protocol_roles[key] = value or fallback
        if len(set(resolved_protocol_roles.values())) != len(required_protocol_roles):
            raise RuntimeError(
                "team preset review board must use four distinct concrete agents"
            )
        protocol_team_lead = resolved_protocol_roles["TEAM_LEAD"]
        protocol_principal_architect = resolved_protocol_roles["PRINCIPAL_ARCHITECT"]
        protocol_sceptical_architect = resolved_protocol_roles["SCEPTICAL_ARCHITECT"]
        protocol_security_reviewer = resolved_protocol_roles["SECURITY_REVIEWER"]
        match = re.search(r"^PROTOCOL_PRODUCT_MANAGER=(.+)$", preset_text, re.M)
        protocol_product_manager = match.group(1) if match and match.group(1) != "null" else None
        llm_matches = re.findall(r"^PROTOCOL_LLM=([^\r\n]+)$", preset_text, re.M)
        if len(llm_matches) > 1:
            raise RuntimeError("team preset must not duplicate PROTOCOL_LLM")
        if llm_matches:
            llm_role = llm_matches[0].strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", llm_role):
                raise RuntimeError("team preset has an invalid PROTOCOL_LLM")
            role_brief_exists = any(
                os.path.isfile(os.path.join(args.skill, root, llm_role + ".md"))
                for root in ("roles", os.path.join("teams", "roles"))
            )
            if not role_brief_exists:
                raise RuntimeError("team preset PROTOCOL_LLM role has no role brief")
            specialist_dispatch_tracks.add("llm")

    def blockers_terminal(task: dict) -> bool:
        blockers = [str(blocker) for blocker in (task.get("blockedBy") or [])]
        unfinished = [
            blocker
            for blocker in blockers
            if by_id.get(blocker, {}).get("status") not in terminal
        ]
        if not unfinished:
            return True
        blocked_sources = sorted(
            blocker
            for blocker in unfinished
            if by_id.get(blocker, {}).get("status") == blocked_status
        )
        if sorted(unfinished) != blocked_sources:
            return False
        clearance = dependency_verdicts.get(task_key(str(task.get("taskId") or "")))
        if not isinstance(clearance, dict):
            return False
        expected = {
            "taskId": str(task.get("taskId") or ""),
            "status": task.get("status"),
            "revision": task.get("revision"),
            "blockedBy": sorted(blockers),
            "blockedSources": blocked_sources,
        }
        return (
            clearance.get("verdict") in {"partially-actionable", "independent"}
            and all(clearance.get(name) == value for name, value in expected.items())
        )

    blocked_tasks = [
        str(task["taskId"])
        for task in tasks
        if task.get("status") == blocked_status
    ]
    blocked_ids = set(blocked_tasks)
    blocked_impacts = []
    for task in tasks:
        task_id = str(task["taskId"])
        if task.get("status") == blocked_status:
            emit("blocked-hold", task_id)
        elif (
            not task_is_held(task_id)
            and task.get("status") in {queued_status, working_status, review_status}
        ):
            blocked_dependencies = [
                str(blocker)
                for blocker in task.get("blockedBy") or []
                if str(blocker) in blocked_ids
            ]
            if blocked_dependencies:
                blocked_impacts.append("%s <- %s" % (task_id, ",".join(blocked_dependencies)))
        for blocker in task.get("blockedBy") or []:
            if str(blocker) not in by_id:
                print(
                    "dispatch: warning - %s blockedBy references unknown [task] '%s'" % (task_id, blocker),
                    file=sys.stderr,
                )

    design_queue = [
        str(task["taskId"])
        for task in tasks
        if not task_is_held(str(task["taskId"]))
        and design_request(task) > last(task, "design-approved", "design-pushback")
    ]
    sceptical_design_queue = [
        str(task["taskId"])
        for task in tasks
        if not task_is_held(str(task["taskId"]))
        and design_request(task) > last(
            task, "sceptical-design-approved", "sceptical-design-pushback"
        )
    ]
    team_lead_review_queue, architecture_queue, sceptical_architecture_queue = [], [], []
    security_queue, merge_queue, anomalies = [], [], []

    def approval_signer(task: dict, index: int) -> str | None:
        body = str((task.get("comments") or [])[index].get("body") or "")
        signature = re.search(
            r"(?:\u2014|-)\s*([\w-]+)(?:\s*\((?:posted by[^)]*|as [^)]+)\))?\s*$",
            body.strip(),
        )
        return signature.group(1) if signature else None

    for task in tasks:
        if task.get("status") != review_status:
            continue
        task_id = str(task["taskId"])
        if task_is_held(task_id):
            continue
        request = last(task, "review-request")
        if request < 0:
            anomalies.append(task_id)
            continue
        findings = last(task, "review-findings")
        if findings > request:
            anomalies.append(task_id)
            continue
        team_lead_approval = last(task, "team-lead-approval")
        architecture_approval = last(task, "architecture-approval")
        sceptical_approval = last(task, "sceptical-architecture-approval")
        security_approval = last(task, "security-approval")
        approvals = {
            "team-lead-approval": (team_lead_approval, protocol_team_lead),
            "architecture-approval": (
                architecture_approval,
                protocol_principal_architect,
            ),
            "sceptical-architecture-approval": (
                sceptical_approval,
                protocol_sceptical_architect,
            ),
            "security-approval": (security_approval, protocol_security_reviewer),
        }
        if all(index > request for index, _ in approvals.values()):
            invalid = False
            for marker_name, (index, expected_signer) in approvals.items():
                signer = approval_signer(task, index)
                if signer != expected_signer:
                    anomalies.append(task_id)
                    print(
                        "dispatch: warning - %s [%s] signed by '%s', expected mandatory gate '%s'"
                        % (task_id, marker_name, signer, expected_signer),
                        file=sys.stderr,
                    )
                    invalid = True
                    break
            if invalid:
                continue
            merge_queue.append(task_id)
        else:
            if team_lead_approval <= request:
                team_lead_review_queue.append(task_id)
            if architecture_approval <= request:
                architecture_queue.append(task_id)
            if sceptical_approval <= request:
                sceptical_architecture_queue.append(task_id)
            if security_approval <= request:
                security_queue.append(task_id)

    # The release executor creates this exact request only after recomputing the
    # closed integration chain.  Tracker containers are not uniformly
    # commentable, so the feature-level verdict lives on its deterministic
    # anchor task and is routed here like every other gate queue.
    product_closeout_role = None
    product_closeout_detail = None
    product_request = workdir / "product-acceptance-request.json"
    all_terminal = bool(tasks) and all(task.get("status") in terminal for task in tasks)
    if all_terminal:
        try:
            request_text = read_regular_at(
                workdir_fd, "product-acceptance-request.json", "product-acceptance request", 1024 * 1024
            )
        except FileNotFoundError:
            request_text = None
        except (OSError, RuntimeError) as exc:
            product_closeout_role = "team-lead"
            product_closeout_detail = (
                "Product-acceptance request is invalid or ambiguous (%s); repair the deterministic release handoff, "
                "do not author an approval from guessed values." % str(exc)[:300]
            )
            request_text = None
        if request_text is not None:
            try:
                request = json.loads(request_text)
                if not isinstance(request, dict):
                    raise ProductAcceptancePending("request must be a JSON object")
                validate_request(request, payload)
                try:
                    evaluate_product_acceptance(
                        payload,
                        feature_id=str(request["featureId"]),
                        commit=str(request["commit"]),
                        integration_evidence_digest=str(request["integrationEvidenceDigest"]),
                    )
                except ProductAcceptancePending as exc:
                    product_closeout_role = "product-manager" if protocol_product_manager else "team-lead"
                    product_closeout_detail = (
                        "Feature closeout is awaiting a mechanically bound product verdict: %s. "
                        "Read canonicalBody from the validated non-symlink request %s and post it unchanged on "
                        "anchor task %s through the standard outbox."
                        % (str(exc)[:300], product_request, request["anchorTaskId"])
                    )
            except (OSError, ValueError, KeyError, ProductAcceptancePending) as exc:
                product_closeout_role = "team-lead"
                product_closeout_detail = (
                    "Product-acceptance request is invalid or ambiguous (%s); repair the deterministic release handoff, "
                    "do not author an approval from guessed values." % str(exc)[:300]
                )

    if design_queue or architecture_queue:
        emit(
            "launch",
            "principal-architect",
            "Dispatch queue - design gates: %s; architecture reviews: %s. Drain every item and exit."
            % (", ".join(design_queue) or "none", ", ".join(architecture_queue) or "none"),
            "|".join(architecture_queue),
        )
    if sceptical_design_queue or sceptical_architecture_queue:
        emit(
            "launch",
            "sceptical-architect",
            "Dispatch queue - independent design challenges: %s; release-bound architecture reviews: %s. Drain every item and exit."
            % (
                ", ".join(sceptical_design_queue) or "none",
                ", ".join(sceptical_architecture_queue) or "none",
            ),
            "|".join(sceptical_architecture_queue),
        )
    if security_queue:
        emit(
            "launch",
            protocol_security_reviewer,
            "Dispatch queue - independent security reviews: %s. Drain every item and exit."
            % ", ".join(security_queue),
            "|".join(security_queue),
        )
    if team_lead_review_queue:
        emit(
            "launch",
            "team-lead",
            "Dispatch queue - final quality reviews: %s. Drain every item and exit."
            % ", ".join(team_lead_review_queue),
            "|".join(team_lead_review_queue),
        )
    if merge_queue:
        emit(
            "launch",
            "integrator",
            "Dispatch queue - independently four-party-approved, integrate in dependency order: %s."
            % ", ".join(merge_queue),
            "|".join(merge_queue),
        )
    if product_closeout_role and product_closeout_detail:
        emit("launch", product_closeout_role, product_closeout_detail)

    # Relaunch task-scoped workers that own active implementation or rework.
    for task in tasks:
        if task.get("status") != working_status:
            continue
        task_id = str(task["taskId"])
        if task_is_held(task_id):
            continue
        execution = execution_identity(
            executions_fd, workdir, args.team, args.feature, task_id
        )
        claim = claim_identity(
            claims_fd, args.team, args.feature, task, working_status
        )
        if execution and claim and execution[0] != claim[0]:
            raise RuntimeError("task execution role conflicts with its durable claim role")
        durable = execution or claim
        tracker_role = task.get("assignee")
        if durable is None:
            if not tracker_role:
                # No authenticated local dispatch identity exists. Do not guess a
                # role from a remote adapter that cannot persist assignees.
                continue
            role, attempt = str(tracker_role), 1
        else:
            role, attempt = durable
            if tracker_role and str(tracker_role) != role:
                raise RuntimeError("tracker assignee conflicts with the durable dispatch identity")
        design_note = design_request(task)
        design_approved = last(task, "design-approved")
        design_pushback = last(task, "design-pushback")
        sceptical_design_approved = last(task, "sceptical-design-approved")
        sceptical_design_pushback = last(task, "sceptical-design-pushback")
        if design_note >= 0 and (
            design_approved <= design_note
            or design_pushback > design_approved
            or sceptical_design_approved <= design_note
            or sceptical_design_pushback > sceptical_design_approved
        ):
            continue
        request = last(task, "review-request")
        findings = last(task, "review-findings")
        if request < 0 or findings > request:
            if findings > request:
                attempt += 1
            emit("launch-task", role, task_id, attempt)

    active_count = sum(
        1
        for task in tasks
        if task.get("status") == working_status
        and not task_is_held(str(task["taskId"]))
    )
    unintegrated = [
        task
        for task in tasks
        if task.get("status") in {working_status, review_status}
        and not task_is_held(str(task["taskId"]))
    ]
    held = set().union(*(resources(task) for task in unintegrated)) if unintegrated else set()
    held_unsafe = any(not metadata(task)["parallelSafe"] for task in unintegrated)
    if args.execution == "sequential":
        slots = 0 if unintegrated else 1
    else:
        cap = args.max_active or 2
        slots = max(0, cap - active_count)

    selected_resources = set()
    selected_unsafe = False
    selected_count = 0
    missing_gate, constrained = [], []
    candidates = [
        task
        for task in tasks
        if task.get("status") == queued_status
        and not task_is_held(str(task["taskId"]))
        and (
            not task.get("assignee")
            or (hold_entry(str(task["taskId"])) or {}).get("state") == "resumed"
            or (
                last(task, "review-request") >= 0
                and last(task, "review-findings") > last(task, "review-request")
            )
        )
        and blockers_terminal(task)
    ]
    for task in candidates:
        task_id = str(task["taskId"])
        if slots <= 0:
            constrained.append(task_id)
            continue
        design_note = design_request(task)
        design_approved = last(task, "design-approved")
        design_pushback = last(task, "design-pushback")
        sceptical_design_approved = last(task, "sceptical-design-approved")
        sceptical_design_pushback = last(task, "sceptical-design-pushback")
        if (
            design_note < 0
            or design_approved <= design_note
            or design_pushback > design_approved
            or sceptical_design_approved <= design_note
            or sceptical_design_pushback > sceptical_design_approved
        ):
            missing_gate.append(task_id)
            continue
        data = metadata(task)
        claims = resources(task)
        if args.execution == "parallel":
            if held_unsafe or selected_unsafe:
                constrained.append(task_id)
                continue
            if not data["parallelSafe"]:
                if unintegrated or selected_count or selected_unsafe:
                    constrained.append(task_id)
                    continue
                selected_unsafe = True
            elif claims_conflict(claims, held | selected_resources):
                constrained.append(task_id)
                continue
        role = (
            data["track"]
            if data["track"] in {"backend", "frontend", "qa"} | specialist_dispatch_tracks
            else "backend"
        )
        attempt = 1
        resumed = (hold_entry(task_id) or {}).get("state") == "resumed"
        rework = (
            last(task, "review-request") >= 0
            and last(task, "review-findings") > last(task, "review-request")
        )
        if rework:
            previous = execution_identity(
                executions_fd, workdir, args.team, args.feature, task_id
            )
            if previous is None:
                constrained.append(task_id + " (rework lacks durable execution identity)")
                continue
            role, previous_attempt = previous
            if task.get("assignee") and str(task["assignee"]) != role:
                raise RuntimeError(
                    "rework task assignee conflicts with its durable execution identity"
                )
            attempt = previous_attempt + 1
        elif resumed:
            previous = execution_identity(
                executions_fd, workdir, args.team, args.feature, task_id
            )
            if previous is not None:
                role, previous_attempt = previous
                if task.get("assignee") and str(task["assignee"]) != role:
                    raise RuntimeError(
                        "resumed task assignee conflicts with its durable execution identity"
                    )
                attempt = previous_attempt + 1
            elif task.get("assignee"):
                constrained.append(task_id + " (resume lacks durable execution identity)")
                continue
        emit("claim-task", role, task_id, attempt)
        selected_resources |= claims
        selected_count += 1
        slots -= 1

    stale = []
    try:
        heartbeat_fd = open_child_directory(workdir_fd, "heartbeats", "heartbeat directory")
    except FileNotFoundError:
        heartbeat_fd = None
    if heartbeat_fd is not None:
        now = time.time()
        for name in os.listdir(heartbeat_fd):
            info = os.stat(name, dir_fd=heartbeat_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                stale.append(name + " (unsafe non-file heartbeat)")
            elif now - info.st_mtime > args.stuck_minutes * 60:
                stale.append(name)

    resume_pending = [
        entry["taskId"]
        for entry in hold_entries.values()
        if entry.get("state") == "resume-review-pending"
    ]
    manual_takeovers = [
        entry["taskId"]
        for entry in hold_entries.values()
        if entry.get("state") == "manual-takeover"
    ]
    if (
        missing_gate
        or constrained
        or stale
        or anomalies
        or blocked_tasks
        or blocked_impacts
        or resume_pending
        or manual_takeovers
    ):
        detail = "Lead-actionable - missing design gates: %s; constrained ready tasks: %s; stale: %s" % (
            ", ".join(missing_gate) or "none",
            ", ".join(constrained) or "none",
            ", ".join(stale) or "none",
        )
        if anomalies:
            detail += "; anomalous [Review]: %s" % ", ".join(anomalies)
        if blocked_tasks:
            detail += "; human-held [Blocked] tasks: %s (supervise only; never move them outbound)" % ", ".join(blocked_tasks)
        if blocked_impacts:
            detail += (
                "; possible downstream impact: %s (verify implementation is actually prevented; "
                "only then move the dependent into [Blocked])" % "; ".join(blocked_impacts)
            )
        if resume_pending:
            detail += (
                "; human-resumed tasks awaiting full communication review: %s "
                "(read the durable resume request; post only the digest-bound [resume-review], "
                "and [resume-plan] when requirements changed)" % ", ".join(resume_pending)
            )
        if manual_takeovers:
            detail += (
                "; human resumed directly into a non-queued status: %s "
                "(manual takeover; do not claim or launch)" % ", ".join(manual_takeovers)
            )
        emit("launch", "team-lead", detail + ". One supervision pass, then exit.")


if __name__ == "__main__":
    main()
