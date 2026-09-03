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

sys.dont_write_bytecode = True
from task_metadata import normalize_review_gates, parse_task_metadata, required_review_gates


COMMIT_RE = re.compile(r"[0-9a-f]{40}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
MARKER_RE = re.compile(r"^\s*\[([\w-]+)\]")
SIGNATURE_RE = re.compile(
    r"^(?:\s*(?:—|-)\s*)[a-z0-9-]+(?:\s*\((?:posted by[^)]*|as [^)]+)\))?\s*$",
    re.IGNORECASE,
)
PUBLICATION_TRAILER_RE = re.compile(r"^\s*delivery-id:\s*\S+\s*$", re.IGNORECASE)
FILES_EVIDENCE_RE = re.compile(r"(?mi)^[ \t]*files[ \t]*:[ \t]*([^\n]+?)[ \t]*$")
FILES_EVIDENCE_PROSE_RE = re.compile(
    r"(?mi)^[ \t]*(?:files\s+approved[^:\n]*|approved\s+files[^:\n]*)[ \t]*:[ \t]*([^\n]+?)[ \t]*$"
)
FILES_SEPARATOR_RE = re.compile(r"[,·•]")
REQUEST_FIELDS = ("Review-Base-Commit", "Task-Branch-Head", "Review-Package-SHA256")
REQUEST_REVIEW_GATES_FIELD = "Review-Gates"
APPROVAL_BINDING_FIELDS = (
    "Review-Request-SHA256",
    "Task-Branch-Head",
    "Review-Package-SHA256",
)
APPROVAL_PROVENANCE_FIELDS = ("Reviewer-Role", "Reviewer-Context")
APPROVAL_FIELDS = APPROVAL_BINDING_FIELDS + APPROVAL_PROVENANCE_FIELDS
CORE_APPROVAL_MARKERS = (
    "team-lead-approval",
    "architecture-approval",
    "sceptical-architecture-approval",
)
SUPPORTING_GATE_MARKERS = {
    "qa": "review-approval",
    "security": "security-approval",
}


class EvidenceError(RuntimeError):
    pass


def normalize(body: object) -> str:
    return str(body or "").replace("\r\n", "\n").replace("\r", "\n")


def digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(normalize(body).encode()).hexdigest()


def marker(body: str) -> str:
    match = MARKER_RE.match(normalize(body))
    return match.group(1) if match else ""


def strip_publication_trailer(body: str) -> str:
    """Drop the trailer the publication path appends to a body after it is authored.

    `tracker-ops.sh comment-once` appends `delivery-id: <id>` as the last line of
    every artifact it publishes, i.e. *after* the role signature.  Anything that
    reads a published artifact from the tail — a signature match, a "last line"
    heuristic — sees the trailer instead of what the role wrote.  Readers call
    this first so that the tail of the returned text is the tail the author
    actually wrote.

    The trailer is deliberately not moved at the writing end: it is appended last
    by contract, and the hold-verification path reconstructs a published body as
    `body + "\\n\\ndelivery-id: " + id` to prove a comment was not tampered with.
    """
    lines = normalize(body).strip().split("\n")
    while lines and (not lines[-1].strip() or PUBLICATION_TRAILER_RE.match(lines[-1])):
        lines.pop()
    return "\n".join(lines).strip()


def parse_files_evidence(body: str) -> set[str] | None:
    """Return the reviewed file set an artifact declares, or None when absent.

    The canonical form is `Files: a, b, c`.  Reviewers also routinely label the
    same evidence `Files approved (exact):` or `Approved files (...):`, and list
    the paths with middots or spaces instead of commas, because that reads better
    inside a prose verdict.  All of those state the same fact, so all of them are
    accepted here; the caller still has to prove the parsed set equals the exact
    reviewed Git file set, which is where the actual guarantee lives.

    The canonical label wins whenever it is present, so an artifact that carries
    one keeps its existing meaning no matter what prose surrounds it; the looser
    labels are consulted only when there is no `Files:` line to read.
    """
    text = normalize(body)
    match = FILES_EVIDENCE_RE.search(text) or FILES_EVIDENCE_PROSE_RE.search(text)
    if not match:
        return None
    values = {part.strip().strip("`") for part in FILES_SEPARATOR_RE.split(match.group(1))}
    values.discard("")
    # A single remaining value that still contains whitespace is a space-separated
    # list.  Comma/middot separation is resolved first so that a path containing a
    # space survives the ordinary case.
    if len(values) == 1:
        only = next(iter(values))
        if re.search(r"\s", only):
            values = {part.strip().strip("`") for part in only.split()}
            values.discard("")
    return values


def fields(body: str, names: tuple[str, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in names:
        matches = re.findall(r"(?m)^" + re.escape(name) + r":\s*(\S+)\s*$", normalize(body))
        if len(matches) != 1:
            raise EvidenceError(f"[{marker(body) or 'review'}] needs exactly one {name} field")
        result[name] = matches[0]
    return result


def request_binding(body: str) -> dict[str, object]:
    if marker(body) != "review-request":
        raise EvidenceError("review request body has the wrong marker")
    values = fields(body, REQUEST_FIELDS)
    if not COMMIT_RE.fullmatch(values["Review-Base-Commit"]):
        raise EvidenceError("review request has an invalid Review-Base-Commit")
    if not COMMIT_RE.fullmatch(values["Task-Branch-Head"]):
        raise EvidenceError("review request has an invalid Task-Branch-Head")
    if not DIGEST_RE.fullmatch(values["Review-Package-SHA256"]):
        raise EvidenceError("review request has an invalid Review-Package-SHA256")
    gate_matches = re.findall(
        r"(?m)^" + re.escape(REQUEST_REVIEW_GATES_FIELD) + r":\s*(\S+)\s*$",
        normalize(body),
    )
    if len(gate_matches) > 1:
        raise EvidenceError("[review-request] needs at most one Review-Gates field")
    gate_value = gate_matches[0].lower() if gate_matches else "none"
    try:
        review_gates = [] if gate_value == "none" else normalize_review_gates(
            tuple(gate_value.split(","))
        )
    except ValueError as exc:
        raise EvidenceError(f"review request has invalid Review-Gates: {exc}") from exc
    return {
        "base": values["Review-Base-Commit"],
        "head": values["Task-Branch-Head"],
        "package": values["Review-Package-SHA256"],
        "reviewGates": review_gates,
        "requestDigest": digest(body),
    }


def without_reserved(body: str) -> str:
    reserved = set(REQUEST_FIELDS) | {REQUEST_REVIEW_GATES_FIELD} | set(APPROVAL_FIELDS)
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


def bind_request(
    body: str,
    base: str,
    head: str,
    package: str,
    review_gates: tuple[str, ...] | list[str] = (),
) -> str:
    if marker(body) != "review-request":
        raise EvidenceError("only [review-request] can be bound as a request")
    if not COMMIT_RE.fullmatch(base) or not COMMIT_RE.fullmatch(head) or not DIGEST_RE.fullmatch(package):
        raise EvidenceError("request binding uses an invalid commit or package digest")
    try:
        normalized_gates = normalize_review_gates(tuple(review_gates))
    except ValueError as exc:
        raise EvidenceError(f"request binding uses invalid review gates: {exc}") from exc
    return insert_fields(body, [
        f"Review-Base-Commit: {base}",
        f"Task-Branch-Head: {head}",
        f"Review-Package-SHA256: {package}",
        f"Review-Gates: {','.join(normalized_gates) if normalized_gates else 'none'}",
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


def bind_approval(
    body: str,
    request_body: str,
    reviewer_role: str,
    reviewer_context: str,
) -> str:
    if marker(body) not in {
        "review-approval",
        "security-approval",
        *CORE_APPROVAL_MARKERS,
    }:
        raise EvidenceError("only required review/architecture approvals can be bound as approvals")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", reviewer_role):
        raise EvidenceError("reviewer role must be one concrete role identifier")
    if (
        not reviewer_context
        or len(reviewer_context) > 256
        or any(char.isspace() or ord(char) < 33 for char in reviewer_context)
    ):
        raise EvidenceError("reviewer context must be one bounded non-whitespace instance identifier")
    binding = request_binding(request_body)
    return insert_fields(body, [
        f"Review-Request-SHA256: {binding['requestDigest']}",
        f"Task-Branch-Head: {binding['head']}",
        f"Review-Package-SHA256: {binding['package']}",
        f"Reviewer-Role: {reviewer_role}",
        f"Reviewer-Context: {reviewer_context}",
    ])


def review_records(
    snapshot: dict, task_id: str, review_statuses: set[str]
) -> tuple[dict, int, dict[str, int]]:
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
    findings = positions.get("review-findings", -1)
    approvals = {
        name: positions.get(name, -1)
        for name in CORE_APPROVAL_MARKERS
    }
    if (
        request < 0
        or any(index <= request for index in approvals.values())
        or findings > request
    ):
        raise EvidenceError(
            f"task {task_id} does not have a current independently three-party-approved review request"
        )
    return task, request, approvals


def validate(
    snapshot: dict,
    task_id: str,
    *,
    base: str,
    head: str,
    package: str,
    review_statuses: set[str] | None = None,
    required_gates: tuple[str, ...] | list[str] = (),
) -> str:
    task, request_index, approval_indexes = review_records(
        snapshot, task_id, review_statuses or set()
    )
    comments = task.get("comments") or []
    request_body = normalize(comments[request_index].get("body"))
    binding = request_binding(request_body)
    if (binding["base"], binding["head"], binding["package"]) != (base, head, package):
        raise EvidenceError("review request is not bound to the exact current base/head/package")
    metadata = parse_task_metadata(task.get("description"), task.get("title"))
    try:
        effective_gates = normalize_review_gates(
            tuple(set(metadata["reviewGates"]) | set(required_gates))
        )
    except ValueError as exc:
        raise EvidenceError(f"invalid effective review gates: {exc}") from exc
    if binding["reviewGates"] != effective_gates:
        raise EvidenceError("review request Review-Gates do not match current task metadata")
    reviewer_roles: set[str] = set()
    reviewer_contexts: set[str] = set()

    def validate_approval(name: str, index: int, *, mandatory: bool) -> None:
        approval_body = normalize(comments[index].get("body"))
        values = fields(approval_body, APPROVAL_FIELDS)
        expected = {
            "Review-Request-SHA256": binding["requestDigest"],
            "Task-Branch-Head": head,
            "Review-Package-SHA256": package,
        }
        if {field: values[field] for field in APPROVAL_BINDING_FIELDS} != expected:
            raise EvidenceError(f"[{name}] is not bound to the exact review request/head/package")
        reviewer_role = values["Reviewer-Role"]
        reviewer_context = values["Reviewer-Context"]
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", reviewer_role):
            raise EvidenceError(f"[{name}] has an invalid concrete Reviewer-Role")
        if (
            not reviewer_context
            or len(reviewer_context) > 256
            or any(char.isspace() or ord(char) < 33 for char in reviewer_context)
        ):
            raise EvidenceError(f"[{name}] has an invalid Reviewer-Context")
        if reviewer_role in reviewer_roles:
            if mandatory:
                raise EvidenceError("core approvals do not name three distinct reviewer roles")
            raise EvidenceError("required supporting approval reuses a reviewer role")
        if reviewer_context in reviewer_contexts:
            if mandatory:
                raise EvidenceError("core approvals do not prove three distinct reviewer contexts")
            raise EvidenceError("required supporting approval reuses a reviewer context")
        reviewer_roles.add(reviewer_role)
        reviewer_contexts.add(reviewer_context)

    for name in CORE_APPROVAL_MARKERS:
        validate_approval(name, approval_indexes[name], mandatory=True)

    positions: dict[str, int] = {}
    for index, comment in enumerate(comments):
        current = marker(normalize(comment.get("body")))
        if current:
            positions[current] = index
    supporting_indexes: list[tuple[str, str, int]] = []
    for gate in effective_gates:
        name = SUPPORTING_GATE_MARKERS[gate]
        index = positions.get(name, -1)
        if index <= request_index:
            raise EvidenceError(
                f"task {task_id} lacks a current required [{name}] for review gate {gate}"
            )
        validate_approval(name, index, mandatory=False)
        supporting_indexes.append((gate, name, index))
    if supporting_indexes and any(
        index >= approval_indexes["team-lead-approval"]
        for _, _, index in supporting_indexes
    ):
        raise EvidenceError(
            "team-lead approval must be newer than every required supporting approval"
        )

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
        "schemaVersion": 7,
        "taskId": task_id,
        "reviewBaseCommit": base,
        "taskBranchHead": head,
        "reviewPackageSha256": package,
        "request": record("review-request", request_index),
        "teamLeadApproval": record(
            "team-lead-approval", approval_indexes["team-lead-approval"]
        ),
        "architectureApproval": record(
            "architecture-approval", approval_indexes["architecture-approval"]
        ),
        "scepticalArchitectureApproval": record(
            "sceptical-architecture-approval",
            approval_indexes["sceptical-architecture-approval"],
        ),
        "supportingApprovals": [
            {"gate": gate, **record(name, index)}
            for gate, name, index in supporting_indexes
        ],
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
    request.add_argument("--review-gates", default="")
    approval = commands.add_parser("bind-approval")
    approval.add_argument("body", type=Path)
    approval.add_argument("snapshot", type=Path)
    approval.add_argument("task")
    approval.add_argument("output", type=Path)
    approval.add_argument("reviewer_role")
    approval.add_argument("reviewer_context")
    check = commands.add_parser("validate")
    check.add_argument("snapshot", type=Path)
    check.add_argument("task")
    check.add_argument("base")
    check.add_argument("head")
    check.add_argument("package")
    check.add_argument("board", type=Path)
    check.add_argument("--preset", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "bind-request":
            review_gates = tuple(
                gate.strip().lower()
                for gate in args.review_gates.split(",")
                if gate.strip()
            )
            atomic_write(
                args.output,
                bind_request(
                    safe_read(args.body, 65536),
                    args.base,
                    args.head,
                    args.package,
                    review_gates,
                ),
            )
        elif args.command == "bind-approval":
            snapshot = json.loads(safe_read(args.snapshot))
            request_body = latest_review_request(snapshot, args.task)
            atomic_write(
                args.output,
                bind_approval(
                    safe_read(args.body, 65536),
                    request_body,
                    args.reviewer_role,
                    args.reviewer_context,
                ),
            )
        else:
            snapshot = json.loads(safe_read(args.snapshot))
            board = json.loads(safe_read(args.board))
            statuses = {
                str(item.get("name"))
                for item in board.get("tasks", {}).get("statuses", [])
                if item.get("kind") == "review"
            }
            preset_gates = required_review_gates(
                safe_read(args.preset, 1024 * 1024) if args.preset else ""
            )
            print(validate(
                snapshot,
                args.task,
                base=args.base,
                head=args.head,
                package=args.package,
                review_statuses=statuses,
                required_gates=preset_gates,
            ))
    except (OSError, ValueError, EvidenceError) as exc:
        print(f"review-evidence: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
