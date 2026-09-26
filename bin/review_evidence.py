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
from broker_evidence import (  # noqa: E402
    EvidenceError as BrokerEvidenceError,
    verify_review_publication,
)
from delivery_profile import assess_review_diff  # noqa: E402
from task_metadata import (  # noqa: E402
    normalize_review_gates,
    parse_task_metadata,
    profile_forced_review_gates,
    required_review_gates,
)


COMMIT_RE = re.compile(r"[0-9a-f]{40}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
MARKER_RE = re.compile(r"^\s*\[([\w-]+)\]")
SIGNATURE_RE = re.compile(
    r"^(?:\s*(?:—|-)\s*)[a-z0-9-]+(?:\s*\((?:posted by[^)]*|as [^)]+)\))?\s*$",
    re.IGNORECASE,
)
PUBLICATION_TRAILER_RE = re.compile(r"^\s*delivery-id:\s*\S+\s*$", re.IGNORECASE)
DELIVERY_ID_RE = re.compile(r"delivery-[0-9a-f]{32}")
FILES_EVIDENCE_RE = re.compile(r"(?mi)^[ \t]*files[ \t]*:[ \t]*([^\n]*?)[ \t]*$")
FILES_EVIDENCE_PROSE_RE = re.compile(
    r"(?mi)^[ \t]*(?:files\s+approved[^:\n]*|approved\s+files[^:\n]*)[ \t]*:[ \t]*([^\n]*?)[ \t]*$"
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


def publication_delivery(body: str) -> str:
    """Return the sole exact terminal broker delivery trailer."""
    text = str(body or "")
    matches = re.findall(r"(?m)^delivery-id: (delivery-[0-9a-f]{32})$", text)
    if len(matches) != 1 or not text.endswith("\n\ndelivery-id: " + matches[0]):
        raise EvidenceError(
            "review artifact needs one exact terminal broker delivery-id trailer"
        )
    if len(re.findall(r"(?mi)^\s*delivery-id\s*:[^\n]*$", text)) != 1:
        raise EvidenceError("review artifact has ambiguous delivery-id trailers")
    return matches[0]


def parse_files_evidence(body: str) -> set[str] | None:
    """Return the reviewed file set an artifact declares, or None when absent.

    The canonical form is `Files: a, b, c`.  Reviewers also routinely label the
    same evidence `Files approved (exact):` or `Approved files (...):`, and list
    paths with middots instead of commas. All of those state the same fact, so
    they are accepted here; the caller still has to prove the parsed set equals
    the exact reviewed Git file set, which is where the actual guarantee lives.

    Exactly one declaration is allowed. Multiple canonical/prose declarations,
    duplicate paths, mixed separators, and unquoted whitespace-only separation
    are ambiguous evidence and fail closed.
    """
    text = normalize(body)
    matches = [
        *(match.group(1) for match in FILES_EVIDENCE_RE.finditer(text)),
        *(match.group(1) for match in FILES_EVIDENCE_PROSE_RE.finditer(text)),
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise EvidenceError("review artifact must contain exactly one Files declaration")
    raw = matches[0].strip()
    separator_kinds = {character for character in raw if character in {",", "·", "•"}}
    if len(separator_kinds) > 1:
        raise EvidenceError("Files evidence uses mixed or ambiguous separators")
    parts = FILES_SEPARATOR_RE.split(raw) if separator_kinds else [raw]
    values: list[str] = []
    for part in parts:
        value = part.strip()
        quoted = value.startswith("`") and value.endswith("`")
        if not value:
            raise EvidenceError("Files evidence contains an empty path")
        if value.startswith("`") or value.endswith("`"):
            if not (quoted and len(value) > 2):
                raise EvidenceError("Files evidence contains an unmatched path quote")
            value = value[1:-1]
        if "`" in value:
            raise EvidenceError("Files evidence contains an ambiguous path quote")
        if not separator_kinds and not quoted and re.search(r"\s", value):
            raise EvidenceError(
                "Files evidence with whitespace must quote one path or use an explicit separator"
            )
        values.append(value)
    if len(values) != len(set(values)):
        raise EvidenceError("Files evidence contains a duplicate path")
    return set(values)


def required_files_evidence(body: str, artifact: str) -> set[str]:
    values = parse_files_evidence(body)
    if values is None:
        raise EvidenceError(f"[{artifact}] lacks one unambiguous Files declaration")
    if not values:
        raise EvidenceError(f"[{artifact}] has an empty Files declaration")
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


def insert_provenance(body: str, additions: list[str]) -> str:
    """Append broker provenance to the producer-signed binding block.

    The author-time helper already surrounds the three immutable binding fields
    with the two separator lines allowed by the tracker line budget.  Keep those
    exact producer bytes and insert the two broker-authenticated fields directly
    after the binding fields instead of creating a second blank-line block.
    """
    text = normalize(body).rstrip()
    for name in APPROVAL_PROVENANCE_FIELDS:
        if re.search(r"(?m)^" + re.escape(name) + r":", text):
            raise EvidenceError(
                f"[{marker(body) or 'approval'}] producer body must not claim {name}"
            )
    lines = text.splitlines()
    binding_indexes = [
        index
        for index, line in enumerate(lines)
        if any(
            re.match(r"^" + re.escape(name) + r":", line)
            for name in APPROVAL_BINDING_FIELDS
        )
    ]
    if len(binding_indexes) != len(APPROVAL_BINDING_FIELDS):
        raise EvidenceError(
            f"[{marker(body) or 'approval'}] needs one complete producer binding block"
        )
    lines[max(binding_indexes) + 1:max(binding_indexes) + 1] = additions
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
    required_files_evidence(body, "review-request")
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


def _validate_approval_shape(body: str, request_body: str) -> dict[str, object]:
    if marker(body) not in {
        "review-approval",
        "security-approval",
        *CORE_APPROVAL_MARKERS,
    }:
        raise EvidenceError("only required review/architecture approvals can be bound as approvals")
    request_files = required_files_evidence(request_body, "review-request")
    approval_files = required_files_evidence(body, marker(body))
    if approval_files != request_files:
        raise EvidenceError(
            f"[{marker(body)}] Files declaration contradicts the bound review request"
        )
    return request_binding(request_body)


def bind_approval_request(body: str, request_body: str) -> str:
    """Author-time helper that puts the exact request binding in the signed body."""
    binding = _validate_approval_shape(body, request_body)
    return insert_fields(body, [
        f"Review-Request-SHA256: {binding['requestDigest']}",
        f"Task-Branch-Head: {binding['head']}",
        f"Review-Package-SHA256: {binding['package']}",
    ])


def finalize_bound_approval(
    body: str,
    request_body: str,
    reviewer_role: str,
    reviewer_context: str,
) -> str:
    """Validate a producer-signed binding and add only broker provenance.

    The exact request/head/package fields are deliberately never inserted or
    replaced here.  They must already be in the producer body covered by its
    publication capability.
    """
    binding = _validate_approval_shape(body, request_body)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", reviewer_role):
        raise EvidenceError("reviewer role must be one concrete role identifier")
    if (
        not reviewer_context
        or len(reviewer_context) > 256
        or any(char.isspace() or ord(char) < 33 for char in reviewer_context)
    ):
        raise EvidenceError("reviewer context must be one bounded non-whitespace instance identifier")
    observed = fields(body, APPROVAL_BINDING_FIELDS)
    expected = {
        "Review-Request-SHA256": str(binding["requestDigest"]),
        "Task-Branch-Head": str(binding["head"]),
        "Review-Package-SHA256": str(binding["package"]),
    }
    if observed != expected:
        raise EvidenceError(
            f"[{marker(body)}] producer binding does not match the latest review request/head/package"
        )
    provenance_present = any(
        re.search(r"(?m)^" + re.escape(name) + r":", normalize(body))
        for name in APPROVAL_PROVENANCE_FIELDS
    )
    if provenance_present:
        observed_provenance = fields(body, APPROVAL_PROVENANCE_FIELDS)
        expected_provenance = {
            "Reviewer-Role": reviewer_role,
            "Reviewer-Context": reviewer_context,
        }
        if observed_provenance != expected_provenance:
            raise EvidenceError(
                f"[{marker(body)}] producer provenance contradicts the verified reviewer"
            )
        return normalize(body).strip() + "\n"
    return insert_provenance(body, [
        f"Reviewer-Role: {reviewer_role}",
        f"Reviewer-Context: {reviewer_context}",
    ])


def bind_approval(
    body: str,
    request_body: str,
    reviewer_role: str,
    reviewer_context: str,
) -> str:
    """Compose an exact producer binding and broker provenance for fixtures/tools."""
    return finalize_bound_approval(
        bind_approval_request(body, request_body),
        request_body,
        reviewer_role,
        reviewer_context,
    )


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
        or any(index < 0 for index in approvals.values())
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
    review_target_status: str | None = None,
    required_gates: tuple[str, ...] | list[str] = (),
    repo: str | os.PathLike[str] | None = None,
    workspace: str | os.PathLike[str] | None = None,
    team: str | None = None,
    feature: str | None = None,
    request_role: str | None = None,
    request_attempt: int | None = None,
) -> str:
    if (
        repo is None
        or workspace is None
        or not team
        or not feature
        or not request_role
        or isinstance(request_attempt, bool)
        or not isinstance(request_attempt, int)
        or request_attempt < 1
    ):
        raise EvidenceError(
            "protected review receipt scope requires repo/workspace/team/feature/request role/attempt"
        )
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", request_role):
        raise EvidenceError("review request role is invalid")
    if snapshot.get("featureId") != feature:
        raise EvidenceError("tracker snapshot feature does not match protected receipt scope")
    allowed_current_statuses = review_statuses or set()
    if not allowed_current_statuses:
        raise EvidenceError("review evidence needs at least one allowed current task status")
    if not review_target_status:
        raise EvidenceError("review evidence needs the single semantic review target status")
    review_target = review_target_status
    task, request_index, approval_indexes = review_records(
        snapshot, task_id, allowed_current_statuses
    )
    comments = task.get("comments") or []
    request_body = normalize(comments[request_index].get("body"))
    binding = request_binding(request_body)
    request_files = required_files_evidence(request_body, "review-request")
    if (binding["base"], binding["head"], binding["package"]) != (base, head, package):
        raise EvidenceError("review request is not bound to the exact current base/head/package")
    receipt_deliveries: set[str] = set()
    receipt_hashes: set[str] = set()

    def authenticated_receipt(name: str, index: int, target_status: object) -> dict:
        raw_body = str(comments[index].get("body") or "")
        delivery = publication_delivery(raw_body)
        try:
            receipt = verify_review_publication(
                Path(repo),
                Path(workspace),
                team=team,
                feature=feature,
                task=task_id,
                marker=name,
                delivery=delivery,
                target_status=target_status,
                tracker_body=raw_body,
            )
        except (BrokerEvidenceError, OSError, ValueError) as exc:
            raise EvidenceError(
                f"[{name}] lacks its exact authenticated broker receipt: {exc}"
            ) from exc
        if receipt.get("attempt") != request_attempt:
            raise EvidenceError(f"[{name}] receipt is bound to another task attempt")
        receipt_hash = str(receipt.get("receiptSha256") or "")
        if delivery in receipt_deliveries or receipt_hash in receipt_hashes:
            raise EvidenceError("review evidence reuses a protected publication receipt")
        receipt_deliveries.add(delivery)
        receipt_hashes.add(receipt_hash)
        return receipt

    request_receipt = authenticated_receipt(
        "review-request", request_index, review_target
    )
    if (
        request_receipt.get("executionKind") != "task"
        or request_receipt.get("producerRole") != request_role
    ):
        raise EvidenceError(
            "[review-request] receipt does not match the canonical task execution"
        )
    expected_request_receipt_binding = {
        "kind": "review-request",
        "base": base,
        "head": head,
        "package": package,
    }
    if request_receipt.get("reviewBinding") != expected_request_receipt_binding:
        raise EvidenceError(
            "[review-request] protected binding does not match base/head/package"
        )
    profile_gates = profile_forced_review_gates(
        assess_review_diff(repo, base, head, task)
    )
    try:
        metadata = parse_task_metadata(task.get("description"), task.get("title"))
    except ValueError:
        # assess_review_diff classified malformed metadata as high-risk; keep
        # validation routable while requiring both supporting gates.
        metadata = parse_task_metadata("", task.get("title"))
    try:
        effective_gates = normalize_review_gates(
            tuple(
                set(metadata["reviewGates"])
                | set(required_gates)
                | set(profile_gates)
            )
        )
    except ValueError as exc:
        raise EvidenceError(f"invalid effective review gates: {exc}") from exc
    if binding["reviewGates"] != effective_gates:
        raise EvidenceError("review request Review-Gates do not match current task metadata")
    reviewer_roles: set[str] = set()
    reviewer_contexts: set[str] = set()
    approval_receipts: dict[str, dict] = {}

    def validate_approval(name: str, index: int, *, mandatory: bool) -> None:
        approval_body = normalize(comments[index].get("body"))
        approval_files = required_files_evidence(approval_body, name)
        if approval_files != request_files:
            raise EvidenceError(f"[{name}] Files declaration contradicts the review request")
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
        receipt = authenticated_receipt(name, index, None)
        expected_context = "%s:%s" % (
            receipt.get("capabilityId"),
            receipt.get("capabilityInstance"),
        )
        if (
            receipt.get("executionKind") != "gate"
            or receipt.get("producerRole") != reviewer_role
            or reviewer_context != expected_context
        ):
            raise EvidenceError(
                f"[{name}] Reviewer-Role/Reviewer-Context do not match its authenticated receipt"
            )
        if receipt.get("reviewBinding") != {"kind": name}:
            raise EvidenceError(f"[{name}] protected review binding is invalid")
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
        approval_receipts[name] = receipt

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
        if index < 0:
            raise EvidenceError(
                f"task {task_id} lacks a current required [{name}] for review gate {gate}"
            )
        validate_approval(name, index, mandatory=False)
        supporting_indexes.append((gate, name, index))
    request_time = request_receipt["publishedAtUnixNs"]
    if any(
        receipt["publishedAtUnixNs"] <= request_time
        for receipt in approval_receipts.values()
    ):
        raise EvidenceError("every approval must be newer than the protected review request")
    lead_time = approval_receipts["team-lead-approval"]["publishedAtUnixNs"]
    required_before_lead = [
        approval_receipts["architecture-approval"],
        approval_receipts["sceptical-architecture-approval"],
        *(approval_receipts[name] for _, name, _ in supporting_indexes),
    ]
    if any(receipt["publishedAtUnixNs"] >= lead_time for receipt in required_before_lead):
        raise EvidenceError(
            "team-lead approval must be newer than both architects and every required supporting approval"
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
            "receipt": (
                request_receipt if name == "review-request" else approval_receipts[name]
            ),
        }

    evidence = {
        "schemaVersion": 8,
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
    producer_approval = commands.add_parser("bind-producer-approval")
    producer_approval.add_argument("body", type=Path)
    producer_approval.add_argument("snapshot", type=Path)
    producer_approval.add_argument("task")
    producer_approval.add_argument("bindings", type=Path)
    producer_approval.add_argument("output", type=Path)
    finalize_approval = commands.add_parser("finalize-approval")
    finalize_approval.add_argument("body", type=Path)
    finalize_approval.add_argument("snapshot", type=Path)
    finalize_approval.add_argument("task")
    finalize_approval.add_argument("output", type=Path)
    finalize_approval.add_argument("reviewer_role")
    finalize_approval.add_argument("reviewer_context")
    check = commands.add_parser("validate")
    check.add_argument("snapshot", type=Path)
    check.add_argument("task")
    check.add_argument("base")
    check.add_argument("head")
    check.add_argument("package")
    check.add_argument("board", type=Path)
    check.add_argument("--preset", type=Path)
    check.add_argument("--repo", required=True)
    check.add_argument("--workspace", required=True)
    check.add_argument("--team", required=True)
    check.add_argument("--feature", required=True)
    check.add_argument("--request-role", required=True)
    check.add_argument("--attempt", type=int, required=True)
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
        elif args.command in {
            "bind-approval",
            "bind-producer-approval",
            "finalize-approval",
        }:
            snapshot = json.loads(safe_read(args.snapshot))
            request_body = latest_review_request(snapshot, args.task)
            if args.command == "bind-producer-approval":
                manifest = json.loads(safe_read(args.bindings, 65536))
                binding = request_binding(request_body)
                expected = (
                    manifest.get("reviewBaseCommit"),
                    manifest.get("taskBranchHead"),
                    manifest.get("reviewPackageSha256"),
                )
                if (binding["base"], binding["head"], binding["package"]) != expected:
                    raise EvidenceError(
                        "latest review request does not match the exact review package manifest"
                    )
                result = bind_approval_request(
                    safe_read(args.body, 65536), request_body
                )
            elif args.command == "finalize-approval":
                result = finalize_bound_approval(
                    safe_read(args.body, 65536),
                    request_body,
                    args.reviewer_role,
                    args.reviewer_context,
                )
            else:
                result = bind_approval(
                    safe_read(args.body, 65536),
                    request_body,
                    args.reviewer_role,
                    args.reviewer_context,
                )
            atomic_write(args.output, result)
        else:
            snapshot = json.loads(safe_read(args.snapshot))
            board = json.loads(safe_read(args.board))
            statuses = {
                str(item.get("name"))
                for item in board.get("tasks", {}).get("statuses", [])
                if item.get("kind") == "review"
            }
            if len(statuses) != 1:
                raise EvidenceError(
                    "review board must define exactly one semantic review status"
                )
            review_target = next(iter(statuses))
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
                review_target_status=review_target,
                required_gates=preset_gates,
                repo=args.repo,
                workspace=args.workspace,
                team=args.team,
                feature=args.feature,
                request_role=args.request_role,
                request_attempt=args.attempt,
            ))
    except (OSError, ValueError, EvidenceError) as exc:
        print(f"review-evidence: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
