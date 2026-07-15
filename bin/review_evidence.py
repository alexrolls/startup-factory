#!/usr/bin/env python3
"""Create and validate review envelopes bound to one exact Git diff package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path


COMMIT_RE = re.compile(r"[0-9a-f]{40}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
MARKER_RE = re.compile(r"^\s*\[([\w-]+)\]")
SIGNATURE_RE = re.compile(
    r"^(?:\s*(?:—|-)\s*)[a-z0-9-]+(?:\s*\((?:posted by[^)]*|as [^)]+)\))?\s*$",
    re.IGNORECASE,
)
REQUEST_FIELDS = ("Review-Base-Commit", "Task-Branch-Head", "Review-Package-SHA256")
APPROVAL_FIELDS = ("Review-Request-SHA256", "Task-Branch-Head", "Review-Package-SHA256")


class EvidenceError(RuntimeError):
    pass


def normalize(body: object) -> str:
    return str(body or "").replace("\r\n", "\n").replace("\r", "\n")


def digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(normalize(body).encode()).hexdigest()


def marker(body: str) -> str:
    match = MARKER_RE.match(normalize(body))
    return match.group(1) if match else ""


def fields(body: str, names: tuple[str, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in names:
        matches = re.findall(r"(?m)^" + re.escape(name) + r":\s*(\S+)\s*$", normalize(body))
        if len(matches) != 1:
            raise EvidenceError(f"[{marker(body) or 'review'}] needs exactly one {name} field")
        result[name] = matches[0]
    return result


def request_binding(body: str) -> dict[str, str]:
    if marker(body) != "review-request":
        raise EvidenceError("review request body has the wrong marker")
    values = fields(body, REQUEST_FIELDS)
    if not COMMIT_RE.fullmatch(values["Review-Base-Commit"]):
        raise EvidenceError("review request has an invalid Review-Base-Commit")
    if not COMMIT_RE.fullmatch(values["Task-Branch-Head"]):
        raise EvidenceError("review request has an invalid Task-Branch-Head")
    if not DIGEST_RE.fullmatch(values["Review-Package-SHA256"]):
        raise EvidenceError("review request has an invalid Review-Package-SHA256")
    return {
        "base": values["Review-Base-Commit"],
        "head": values["Task-Branch-Head"],
        "package": values["Review-Package-SHA256"],
        "requestDigest": digest(body),
    }


def without_reserved(body: str) -> str:
    reserved = set(REQUEST_FIELDS) | set(APPROVAL_FIELDS)
    lines = [
        line for line in normalize(body).rstrip().splitlines()
        if not any(re.match(r"^" + re.escape(name) + r":", line) for name in reserved)
    ]
    return "\n".join(lines).rstrip()


def insert_fields(body: str, additions: list[str]) -> str:
    lines = without_reserved(body).splitlines()
    insertion = len(lines)
    for index in range(len(lines) - 1, -1, -1):
        if not lines[index].strip():
            continue
        if SIGNATURE_RE.fullmatch(lines[index]):
            insertion = index
        break
    block = [""] + additions + [""]
    lines[insertion:insertion] = block
    return "\n".join(lines).strip() + "\n"


def bind_request(body: str, base: str, head: str, package: str) -> str:
    if marker(body) != "review-request":
        raise EvidenceError("only [review-request] can be bound as a request")
    if not COMMIT_RE.fullmatch(base) or not COMMIT_RE.fullmatch(head) or not DIGEST_RE.fullmatch(package):
        raise EvidenceError("request binding uses an invalid commit or package digest")
    return insert_fields(body, [
        f"Review-Base-Commit: {base}",
        f"Task-Branch-Head: {head}",
        f"Review-Package-SHA256: {package}",
    ])


def latest_review_request(snapshot: dict, task_id: str) -> str:
    task = next(
        (item for item in snapshot.get("tasks") or [] if str(item.get("taskId")) == task_id),
        None,
    )
    if not task:
        raise EvidenceError(f"task {task_id!r} is absent from the authoritative feature export")
    requests = [
        normalize(comment.get("body"))
        for comment in task.get("comments") or []
        if marker(normalize(comment.get("body"))) == "review-request"
    ]
    if not requests:
        raise EvidenceError("task has no review request to approve")
    return requests[-1]


def bind_approval(body: str, request_body: str) -> str:
    if marker(body) not in {
        "review-approval",
        "architecture-approval",
        "sceptical-architecture-approval",
    }:
        raise EvidenceError("only required review/architecture approvals can be bound as approvals")
    binding = request_binding(request_body)
    return insert_fields(body, [
        f"Review-Request-SHA256: {binding['requestDigest']}",
        f"Task-Branch-Head: {binding['head']}",
        f"Review-Package-SHA256: {binding['package']}",
    ])


def review_records(
    snapshot: dict, task_id: str, review_statuses: set[str]
) -> tuple[dict, int, int, int, int]:
    task = next(
        (item for item in snapshot.get("tasks") or [] if str(item.get("taskId")) == task_id),
        None,
    )
    if not task:
        raise EvidenceError(f"task {task_id!r} is absent from the tracker snapshot")
    if review_statuses and task.get("status") not in review_statuses:
        raise EvidenceError(f"task {task_id} is not in the review status")
    comments = task.get("comments") or []
    positions: dict[str, int] = {}
    for index, comment in enumerate(comments):
        current = marker(normalize(comment.get("body")))
        if current:
            positions[current] = index
    request = positions.get("review-request", -1)
    review = positions.get("review-approval", -1)
    architecture = positions.get("architecture-approval", -1)
    sceptical_architecture = positions.get("sceptical-architecture-approval", -1)
    findings = positions.get("review-findings", -1)
    if (
        request < 0
        or review <= request
        or architecture <= request
        or sceptical_architecture <= request
        or findings > request
    ):
        raise EvidenceError(
            f"task {task_id} does not have a current independently triple-approved review request"
        )
    return task, request, review, architecture, sceptical_architecture


def validate(
    snapshot: dict,
    task_id: str,
    *,
    base: str,
    head: str,
    package: str,
    review_statuses: set[str] | None = None,
) -> str:
    task, request_index, review_index, architecture_index, sceptical_index = review_records(
        snapshot, task_id, review_statuses or set()
    )
    comments = task.get("comments") or []
    request_body = normalize(comments[request_index].get("body"))
    binding = request_binding(request_body)
    if (binding["base"], binding["head"], binding["package"]) != (base, head, package):
        raise EvidenceError("review request is not bound to the exact current base/head/package")
    for index, name in (
        (review_index, "review-approval"),
        (architecture_index, "architecture-approval"),
        (sceptical_index, "sceptical-architecture-approval"),
    ):
        approval_body = normalize(comments[index].get("body"))
        values = fields(approval_body, APPROVAL_FIELDS)
        expected = {
            "Review-Request-SHA256": binding["requestDigest"],
            "Task-Branch-Head": head,
            "Review-Package-SHA256": package,
        }
        if values != expected:
            raise EvidenceError(f"[{name}] is not bound to the exact review request/head/package")

    def record(name: str, index: int) -> dict:
        raw = comments[index]
        return {
            "marker": name,
            "id": None if raw.get("id") is None else str(raw.get("id")),
            "body": normalize(raw.get("body")),
            "author": None if raw.get("author") is None else str(raw.get("author")),
            "createdAt": None if raw.get("createdAt") is None else str(raw.get("createdAt")),
            "updatedAt": None if raw.get("updatedAt") is None else str(raw.get("updatedAt")),
            "revision": None if raw.get("revision") is None else str(raw.get("revision")),
        }

    evidence = {
        "schemaVersion": 3,
        "taskId": task_id,
        "reviewBaseCommit": base,
        "taskBranchHead": head,
        "reviewPackageSha256": package,
        "request": record("review-request", request_index),
        "reviewApproval": record("review-approval", review_index),
        "architectureApproval": record("architecture-approval", architecture_index),
        "scepticalArchitectureApproval": record(
            "sceptical-architecture-approval", sceptical_index
        ),
    }
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def atomic_write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(path.parent, directory_flags)
    temporary = f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def safe_read(path: Path, maximum: int = 8 * 1024 * 1024) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise EvidenceError(f"{path} must be a regular file no larger than {maximum} bytes")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            return handle.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("bind-request")
    request.add_argument("body", type=Path)
    request.add_argument("base")
    request.add_argument("head")
    request.add_argument("package")
    request.add_argument("output", type=Path)
    approval = commands.add_parser("bind-approval")
    approval.add_argument("body", type=Path)
    approval.add_argument("snapshot", type=Path)
    approval.add_argument("task")
    approval.add_argument("output", type=Path)
    check = commands.add_parser("validate")
    check.add_argument("snapshot", type=Path)
    check.add_argument("task")
    check.add_argument("base")
    check.add_argument("head")
    check.add_argument("package")
    check.add_argument("board", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "bind-request":
            atomic_write(args.output, bind_request(safe_read(args.body, 65536), args.base, args.head, args.package))
        elif args.command == "bind-approval":
            snapshot = json.loads(safe_read(args.snapshot))
            request_body = latest_review_request(snapshot, args.task)
            atomic_write(args.output, bind_approval(safe_read(args.body, 65536), request_body))
        else:
            snapshot = json.loads(safe_read(args.snapshot))
            board = json.loads(safe_read(args.board))
            statuses = {
                str(item.get("name"))
                for item in board.get("tasks", {}).get("statuses", [])
                if item.get("kind") == "review"
            }
            print(validate(
                snapshot,
                args.task,
                base=args.base,
                head=args.head,
                package=args.package,
                review_statuses=statuses,
            ))
    except (OSError, ValueError, EvidenceError) as exc:
        print(f"review-evidence: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
