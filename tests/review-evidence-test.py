#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from review_evidence import (  # noqa: E402
    EvidenceError,
    bind_approval,
    bind_approval_request,
    bind_request,
    finalize_bound_approval,
    parse_files_evidence,
    validate as validate_review,
)
import broker_evidence  # noqa: E402
from outbox_capability import delivery_directory, mint, sign_entry  # noqa: E402


_REPO_TEMPORARY = tempfile.TemporaryDirectory()
TEST_ROOT = pathlib.Path(_REPO_TEMPORARY.name).resolve()
REPO = TEST_ROOT / "repository"
REPO.mkdir()
subprocess.run(["git", "init", "-q", str(REPO)], check=True)
subprocess.run(
    ["git", "-C", str(REPO), "config", "user.email", "test@example.com"],
    check=True,
)
subprocess.run(
    ["git", "-C", str(REPO), "config", "user.name", "Test"], check=True
)
(REPO / "README.md").write_text("base\n")
subprocess.run(["git", "-C", str(REPO), "add", "README.md"], check=True)
subprocess.run(["git", "-C", str(REPO), "commit", "-qm", "base"], check=True)
BASE = subprocess.check_output(
    ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
).strip()
(REPO / "app.py").write_text("value = 1\n")
subprocess.run(["git", "-C", str(REPO), "add", "app.py"], check=True)
subprocess.run(["git", "-C", str(REPO), "commit", "-qm", "app"], check=True)
HEAD = subprocess.check_output(
    ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
).strip()
PACKAGE = "sha256:" + "c" * 64
TEAM = "factory-one"
FEATURE = "FEATURE-1"
TASK = "TASK-1"
WORKSPACE = REPO / ".teamwork" / TEAM
(WORKSPACE / "outbox" / "bodies").mkdir(parents=True)
(WORKSPACE / "outbox" / "pending").mkdir(parents=True)
AUTHORITY = TEST_ROOT / "authority"
AUTHORITY.mkdir(mode=0o700)
(AUTHORITY / "record-auth.key").write_bytes(os.urandom(32))
(AUTHORITY / "record-auth.key").chmod(0o600)
os.environ["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = str(AUTHORITY)
_DELIVERY_COUNTER = 0


def capability(
    role: str,
    kind: str,
    *,
    repo: pathlib.Path = REPO,
    workspace: pathlib.Path = WORKSPACE,
) -> dict:
    global _DELIVERY_COUNTER
    _DELIVERY_COUNTER += 1
    return mint(
        str(repo),
        str(workspace),
        TEAM,
        FEATURE,
        role,
        kind,
        TASK if kind == "task" else "-",
        1 if kind == "task" else 0,
        "%s:%s" % (kind, _DELIVERY_COUNTER),
    )


def publish(
    body: str,
    marker: str,
    role: str,
    producer: dict,
    *,
    target: str | None = None,
    repo: pathlib.Path = REPO,
    workspace: pathlib.Path = WORKSPACE,
) -> str:
    global _DELIVERY_COUNTER
    _DELIVERY_COUNTER += 1
    delivery = "delivery-%032x" % _DELIVERY_COUNTER
    identifier = "entry-%032x" % _DELIVERY_COUNTER
    raw = body.encode()
    producer_body = workspace / "outbox" / "bodies" / (identifier + ".md")
    producer_body.parent.mkdir(parents=True, exist_ok=True)
    producer_body.write_bytes(raw)
    entry = {
        "schemaVersion": 1,
        "id": identifier,
        "team": TEAM,
        "featureId": FEATURE,
        "taskId": TASK,
        "attempt": 1,
        "actor": role,
        "marker": marker,
        "bodyPath": str(producer_body),
        "targetStatus": target,
        "phase": "pending",
        "createdAt": "2026-09-19T10:00:00+00:00",
    }
    entry["producerCapability"] = sign_entry(
        entry,
        raw,
        producer["id"],
        producer["secret"],
        producer["instance"],
        producer["expiresAt"],
    )
    pending = workspace / "outbox" / "pending"
    pending.mkdir(parents=True, exist_ok=True)
    source_entry = pending / (identifier + ".producer.json")
    source_entry_raw = broker_evidence.canonical(entry) + b"\n"
    source_entry.write_bytes(source_entry_raw)
    source_entry.chmod(0o400)
    deliveries = delivery_directory(repo, workspace, TEAM, FEATURE)
    source = deliveries / (delivery + ".source.md")
    final = deliveries / (delivery + ".publish.md")
    source.write_bytes(raw)
    source.chmod(0o400)
    final.write_bytes(raw)
    final.chmod(0o400)
    if marker == "review-request":
        parsed = __import__("review_evidence").request_binding(body)
        review_binding = {
            "kind": marker,
            "base": parsed["base"],
            "head": parsed["head"],
            "package": parsed["package"],
        }
    else:
        review_binding = {"kind": marker}
    entry.update(
        {
            "brokerSchemaVersion": 1,
            "deliveryId": delivery,
            "brokerAssignedAt": "2026-09-19T10:00:01+00:00",
            "sourceEntryPath": str(source_entry),
            "sourceEntrySha256": broker_evidence.sha256(source_entry_raw),
            "stagedBodyPath": str(source),
            "stagedBodySha256": broker_evidence.sha256(raw),
            "publishBodyPath": str(final),
            "publishBodySha256": broker_evidence.sha256(raw),
            "reviewBinding": review_binding,
            "brokerPhase": "published",
        }
    )
    path = deliveries / (identifier + ".entry.json")
    path.write_bytes(broker_evidence.canonical(entry) + b"\n")
    path.chmod(0o600)
    broker_evidence.record(repo, workspace, path)
    return body.rstrip("\n") + "\n\ndelivery-id: " + delivery


def validate(*args, **kwargs):
    kwargs.setdefault("repo", REPO)
    kwargs.setdefault("workspace", WORKSPACE)
    kwargs.setdefault("team", TEAM)
    kwargs.setdefault("feature", FEATURE)
    kwargs.setdefault("request_role", "backend")
    kwargs.setdefault("request_attempt", 1)
    kwargs.setdefault("review_statuses", {"Review"})
    kwargs.setdefault("review_target_status", "Review")
    return validate_review(*args, **kwargs)


def approved_snapshot(
    review_gates: tuple[str, ...] = (),
    *,
    base: str = BASE,
    head: str = HEAD,
    description: str | None = None,
    repo: pathlib.Path = REPO,
    workspace: pathlib.Path = WORKSPACE,
) -> dict:
    request_capability = capability("backend", "task", repo=repo, workspace=workspace)
    request = publish(
        bind_request(
        "[review-request]\nFiles: app.py\n\n- backend\n",
        base,
        head,
        PACKAGE,
        review_gates,
        ),
        "review-request",
        "backend",
        request_capability,
        target="Review",
        repo=repo,
        workspace=workspace,
    )
    comments = [{"id": "request", "body": request, "author": "backend", "createdAt": "1"}]
    if "security" in review_gates:
        security_capability = capability(
            "senior-security-engineer", "gate", repo=repo, workspace=workspace
        )
        security = publish(
            bind_approval(
                "[security-approval]\nFiles: app.py\n\n- senior-security-engineer\n",
                request,
                "senior-security-engineer",
                security_capability["id"] + ":" + security_capability["instance"],
            ),
            "security-approval",
            "senior-security-engineer",
            security_capability,
            repo=repo,
            workspace=workspace,
        )
        comments.append(
            {"id": "security", "body": security, "author": "senior-security-engineer", "createdAt": "2"}
        )
    approval_bodies: dict[str, str] = {}
    for marker_name, role, source in (
        (
            "architecture-approval",
            "principal-architect",
            "[architecture-approval]\nFiles: app.py\n\n- principal-architect\n",
        ),
        (
            "sceptical-architecture-approval",
            "sceptical-architect",
            "[sceptical-architecture-approval]\nFiles: app.py\n\n- sceptical-architect\n",
        ),
        (
            "team-lead-approval",
            "team-lead",
            "[team-lead-approval]\nFiles: app.py\n\n- team-lead\n",
        ),
    ):
        producer = capability(role, "gate", repo=repo, workspace=workspace)
        approval_bodies[marker_name] = publish(
            bind_approval(
                source,
                request,
                role,
                producer["id"] + ":" + producer["instance"],
            ),
            marker_name,
            role,
            producer,
            repo=repo,
            workspace=workspace,
        )
    comments.extend([
        {"id": "architecture", "body": approval_bodies["architecture-approval"], "author": "principal-architect", "createdAt": "3"},
        {"id": "sceptical-architecture", "body": approval_bodies["sceptical-architecture-approval"], "author": "sceptical-architect", "createdAt": "4"},
        {"id": "team-lead", "body": approval_bodies["team-lead-approval"], "author": "team-lead", "createdAt": "5"},
    ])
    return {
        "featureId": FEATURE,
        "tasks": [{
            "taskId": TASK,
            "status": "Review",
            "description": (
                description
                if description is not None
                else "files: app.py\nreview-gates: " + ",".join(review_gates)
                if review_gates
                else "files: app.py"
            ),
            "comments": comments,
        }],
    }


def require_qa(
    data: dict,
    *,
    repo: pathlib.Path = REPO,
    workspace: pathlib.Path = WORKSPACE,
) -> str:
    task = data["tasks"][0]
    request = task["comments"][0]["body"]
    qa_capability = capability(
        "senior-qa-engineer", "gate", repo=repo, workspace=workspace
    )
    approval = publish(
        bind_approval(
            "[review-approval]\nFiles: app.py\n\n- senior-qa-engineer\n",
            request,
            "senior-qa-engineer",
            qa_capability["id"] + ":" + qa_capability["instance"],
        ),
        "review-approval",
        "senior-qa-engineer",
        qa_capability,
        repo=repo,
        workspace=workspace,
    )
    task["comments"].insert(
        1,
        {"id": "qa", "body": approval, "author": "senior-qa-engineer", "createdAt": "6"}
    )
    lead = next(
        item
        for item in task["comments"]
        if str(item.get("body") or "").startswith("[team-lead-approval]")
    )
    lead_capability = capability("team-lead", "gate", repo=repo, workspace=workspace)
    lead["body"] = publish(
        bind_approval(
            "[team-lead-approval]\nFiles: app.py\n\n- team-lead\n",
            request,
            "team-lead",
            lead_capability["id"] + ":" + lead_capability["instance"],
        ),
        "team-lead-approval",
        "team-lead",
        lead_capability,
        repo=repo,
        workspace=workspace,
    )
    return approval


class ReviewEvidenceTest(unittest.TestCase):
    def test_files_evidence_rejects_duplicate_and_ambiguous_declarations(self):
        cases = (
            (
                "[review-request]\nFiles: app.py\nFiles: other.py\n",
                "exactly one Files declaration",
            ),
            (
                "[review-request]\nFiles: app.py\nApproved files (exact): other.py\n",
                "exactly one Files declaration",
            ),
            (
                "[review-request]\nFiles: app.py, app.py\n",
                "duplicate path",
            ),
            (
                "[review-request]\nFiles: app.py, other.py · third.py\n",
                "mixed or ambiguous separators",
            ),
            (
                "[review-request]\nFiles: app.py other.py\n",
                "whitespace must quote one path",
            ),
            (
                "[review-request]\nFiles: `unterminated path.md\n",
                "unmatched path quote",
            ),
        )
        for body, message in cases:
            with self.subTest(body=body):
                with self.assertRaisesRegex(EvidenceError, message):
                    parse_files_evidence(body)
        self.assertEqual(
            {"docs/path with spaces.md"},
            parse_files_evidence(
                "[review-request]\nFiles: `docs/path with spaces.md`\n"
            ),
        )

    def test_binding_rejects_ambiguous_or_contradictory_files_evidence(self):
        with self.assertRaisesRegex(EvidenceError, "duplicate path"):
            bind_request(
                "[review-request]\nFiles: app.py, app.py\n",
                BASE,
                HEAD,
                PACKAGE,
            )
        request = bind_request(
            "[review-request]\nFiles: app.py\n",
            BASE,
            HEAD,
            PACKAGE,
        )
        with self.assertRaisesRegex(EvidenceError, "contradicts the bound review request"):
            bind_approval(
                "[team-lead-approval]\nFiles: other.py\n",
                request,
                "team-lead",
                "gate:team-lead:contradiction",
            )

    def test_validation_rejects_duplicate_or_contradictory_files_evidence(self):
        duplicate_request = approved_snapshot()
        duplicate_request["tasks"][0]["comments"][0]["body"] = duplicate_request[
            "tasks"
        ][0]["comments"][0]["body"].replace(
            "Files: app.py", "Files: app.py\nFiles: other.py"
        )
        with self.assertRaisesRegex(EvidenceError, "exactly one Files declaration"):
            validate(
                duplicate_request,
                "TASK-1",
                base=BASE,
                head=HEAD,
                package=PACKAGE,
            )

        contradictory_approval = approved_snapshot()
        contradictory_approval["tasks"][0]["comments"][1]["body"] = (
            contradictory_approval["tasks"][0]["comments"][1]["body"].replace(
                "Files: app.py", "Files: other.py"
            )
        )
        with self.assertRaisesRegex(EvidenceError, "contradicts the review request"):
            validate(
                contradictory_approval,
                "TASK-1",
                base=BASE,
                head=HEAD,
                package=PACKAGE,
            )

    def test_independent_three_party_approval_is_bound_to_exact_package(self):
        result = validate(
            approved_snapshot(),
            "TASK-1",
            base=BASE,
            head=HEAD,
            package=PACKAGE,
            review_statuses={"Review"},
        )
        self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")

    def test_terminal_replay_keeps_review_as_the_publication_target(self):
        data = approved_snapshot()
        data["tasks"][0]["status"] = "Ready to deploy"
        result = validate(
            data,
            "TASK-1",
            base=BASE,
            head=HEAD,
            package=PACKAGE,
            review_statuses={"Review", "Ready to deploy"},
        )
        self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")
        with self.assertRaisesRegex(EvidenceError, "authenticated broker receipt"):
            validate(
                data,
                "TASK-1",
                base=BASE,
                head=HEAD,
                package=PACKAGE,
                review_statuses={"Review", "Ready to deploy"},
                review_target_status="Ready to deploy",
            )

    def test_missing_security_approval_keeps_release_gate_closed(self):
        data = approved_snapshot(
            ("qa", "security"), description="review-gates: security"
        )
        require_qa(data)
        comments = data["tasks"][0]["comments"]
        comments[:] = [
            item
            for item in comments
            if not str(item.get("body") or "").startswith("[security-approval]")
        ]
        with self.assertRaisesRegex(EvidenceError, r"required \[security-approval\]"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_same_file_branch_movement_invalidates_approvals(self):
        with self.assertRaisesRegex(EvidenceError, "exact current base/head/package"):
            validate(
                approved_snapshot(),
                "TASK-1",
                base=BASE,
                head="d" * 40,
                package=PACKAGE,
            )

    def test_broker_cannot_rebind_a_signed_a_approval_to_new_head_b(self):
        request_a = bind_request(
            "[review-request]\nFiles: app.py\n",
            BASE,
            HEAD,
            PACKAGE,
        )
        request_b = bind_request(
            "[review-request]\nFiles: app.py\n",
            BASE,
            "d" * 40,
            "sha256:" + "e" * 64,
        )
        producer_body = bind_approval_request(
            "[architecture-approval]\nFiles: app.py\n\n- principal-architect\n",
            request_a,
        )
        self.assertIn("Task-Branch-Head: " + HEAD, producer_body)
        finalized = finalize_bound_approval(
            producer_body,
            request_a,
            "principal-architect",
            "cap-00000000000000000000000000000000:gate:principal-architect",
        )
        self.assertEqual(
            finalized,
            finalize_bound_approval(
                finalized,
                request_a,
                "principal-architect",
                "cap-00000000000000000000000000000000:gate:principal-architect",
            ),
        )
        authored = "\n".join(
            ["[architecture-approval]", "Files: app.py"]
            + [f"evidence line {index}" for index in range(3, 25)]
            + ["- principal-architect"]
        ) + "\n"
        self.assertEqual(25, len(authored.strip().splitlines()))
        bounded = finalize_bound_approval(
            bind_approval_request(authored, request_a),
            request_a,
            "principal-architect",
            "cap-00000000000000000000000000000000:gate:principal-architect",
        )
        self.assertEqual(32, len(bounded.strip().splitlines()))
        self.assertIn(
            "Review-Package-SHA256: " + PACKAGE + "\nReviewer-Role: principal-architect",
            bounded,
        )
        with self.assertRaisesRegex(EvidenceError, "producer binding does not match"):
            finalize_bound_approval(
                producer_body,
                request_b,
                "principal-architect",
                "cap-00000000000000000000000000000000:gate:principal-architect",
            )

    def test_broker_requires_complete_producer_signed_approval_binding(self):
        request = bind_request(
            "[review-request]\nFiles: app.py\n",
            BASE,
            HEAD,
            PACKAGE,
        )
        for body in (
            "[architecture-approval]\nFiles: app.py\n\n- principal-architect\n",
            (
                "[architecture-approval]\nFiles: app.py\n"
                "Task-Branch-Head: %s\n\n- principal-architect\n" % HEAD
            ),
        ):
            with self.subTest(body=body):
                with self.assertRaisesRegex(EvidenceError, "needs exactly one"):
                    finalize_bound_approval(
                        body,
                        request,
                        "principal-architect",
                        "cap-00000000000000000000000000000000:gate:principal-architect",
                    )

    def test_approval_cannot_be_reused_for_another_request(self):
        data = approved_snapshot()
        data["tasks"][0]["comments"][1]["body"] = data["tasks"][0]["comments"][1][
            "body"
        ].replace("Review-Request-SHA256: sha256:", "Review-Request-SHA256: sha256:" + "0")
        with self.assertRaisesRegex(EvidenceError, "exactly one|not bound"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_later_finding_invalidates_both_approvals(self):
        data = approved_snapshot()
        data["tasks"][0]["comments"].append(
            {"id": "finding", "body": "[review-findings]\nMust fix", "createdAt": "6"}
        )
        with self.assertRaisesRegex(EvidenceError, "independently three-party-approved"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_new_request_needs_new_approvals(self):
        data = approved_snapshot()
        data["tasks"][0]["comments"].append(
            {
                "id": "request-2",
                "body": bind_request("[review-request]\nFiles: app.py\n", BASE, HEAD, PACKAGE),
                "createdAt": "6",
            }
        )
        with self.assertRaisesRegex(EvidenceError, "terminal broker delivery-id"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_direct_reviewer_context_edit_is_not_authenticated(self):
        data = approved_snapshot()
        body = data["tasks"][0]["comments"][1]["body"]
        data["tasks"][0]["comments"][1]["body"] = re.sub(
            r"(?m)^Reviewer-Context: \S+$",
            "Reviewer-Context: cap-00000000000000000000000000000000:forged",
            body,
        )
        with self.assertRaisesRegex(EvidenceError, "authenticated broker receipt"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_duplicate_reviewer_role_is_not_independent(self):
        data = approved_snapshot()
        data["tasks"][0]["comments"][1]["body"] = data["tasks"][0]["comments"][1][
            "body"
        ].replace("Reviewer-Role: principal-architect", "Reviewer-Role: team-lead")
        with self.assertRaisesRegex(EvidenceError, "authenticated broker receipt"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_required_qa_approval_is_bound_and_included(self):
        data = approved_snapshot(("qa",))
        require_qa(data)
        result = validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)
        self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")

    def test_missing_required_qa_approval_keeps_gate_closed(self):
        data = approved_snapshot(("qa",))
        with self.assertRaisesRegex(EvidenceError, r"required \[review-approval\]"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_tracker_reordering_cannot_change_protected_approval_order(self):
        data = approved_snapshot(("qa",))
        require_qa(data)
        task = data["tasks"][0]
        task["comments"].insert(0, task["comments"].pop(1))
        result = validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)
        self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")

    def test_required_qa_must_use_an_independent_context(self):
        data = approved_snapshot(("qa",))
        require_qa(data)
        task = data["tasks"][0]
        task["comments"][1]["body"] = re.sub(
            r"(?m)^Reviewer-Context: \S+$",
            "Reviewer-Context: cap-00000000000000000000000000000000:forged",
            task["comments"][1]["body"],
        )
        with self.assertRaisesRegex(EvidenceError, "authenticated broker receipt"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_team_lead_approval_must_follow_required_qa(self):
        data = approved_snapshot(("qa",))
        require_qa(data)
        task = data["tasks"][0]
        request = task["comments"][0]["body"]
        qa_capability = capability("senior-qa-engineer", "gate")
        late_qa = publish(
            bind_approval(
                "[review-approval]\nFiles: app.py\n\n- senior-qa-engineer\n",
                request,
                "senior-qa-engineer",
                qa_capability["id"] + ":" + qa_capability["instance"],
            ),
            "review-approval",
            "senior-qa-engineer",
            qa_capability,
        )
        next(
            item
            for item in task["comments"]
            if str(item.get("body") or "").startswith("[review-approval]")
        )["body"] = late_qa
        with self.assertRaisesRegex(EvidenceError, "team-lead approval must be newer"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_team_lead_approval_must_follow_both_architects(self):
        data = approved_snapshot()
        comments = data["tasks"][0]["comments"]
        request = comments[0]["body"]
        architect_capability = capability("principal-architect", "gate")
        late_architecture = publish(
            bind_approval(
                "[architecture-approval]\nFiles: app.py\n\n- principal-architect\n",
                request,
                "principal-architect",
                architect_capability["id"] + ":" + architect_capability["instance"],
            ),
            "architecture-approval",
            "principal-architect",
            architect_capability,
        )
        next(
            item
            for item in comments
            if str(item.get("body") or "").startswith("[architecture-approval]")
        )["body"] = late_architecture
        with self.assertRaisesRegex(EvidenceError, "team-lead approval must be newer"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_review_gate_metadata_drift_invalidates_the_request(self):
        data = approved_snapshot(("qa",))
        require_qa(data)
        data["tasks"][0]["description"] = ""
        with self.assertRaisesRegex(EvidenceError, "Review-Gates do not match"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_preset_security_gate_keeps_fail_closed_metadata_gates(self):
        data = approved_snapshot(("qa", "security"))
        data["tasks"][0]["description"] = ""
        require_qa(data)
        result = validate(
            data,
            "TASK-1",
            base=BASE,
            head=HEAD,
            package=PACKAGE,
            required_gates=("security",),
        )
        self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")

    def test_preset_required_security_gate_must_be_bound_to_request(self):
        with self.assertRaisesRegex(EvidenceError, "Review-Gates do not match"):
            validate(
                approved_snapshot(),
                "TASK-1",
                base=BASE,
                head=HEAD,
                package=PACKAGE,
                required_gates=("security",),
            )

    def test_exact_security_diff_cannot_bypass_qa_and_security(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            repo = root / "repository"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Test"],
                check=True,
            )
            (repo / "README.md").write_text("base\n")
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
            base = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            (repo / "src").mkdir()
            (repo / "src" / "auth.py").write_text("def authenticate():\n    return True\n")
            subprocess.run(["git", "-C", str(repo), "add", "src/auth.py"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "auth"], check=True)
            head = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            workspace = repo / ".teamwork" / TEAM
            (workspace / "outbox" / "staged").mkdir(parents=True)
            (workspace / "outbox" / "pending").mkdir(parents=True)
            authority = root / "authority"
            authority.mkdir(mode=0o700)
            (authority / "record-auth.key").write_bytes(os.urandom(32))
            (authority / "record-auth.key").chmod(0o600)

            with mock.patch.dict(
                os.environ,
                {"STARTUP_FACTORY_LIFECYCLE_STATE_ROOT": str(authority)},
            ):
                bypass = approved_snapshot(
                    base=base,
                    head=head,
                    description="",
                    repo=repo,
                    workspace=workspace,
                )
                with self.assertRaisesRegex(EvidenceError, "Review-Gates do not match"):
                    validate(
                        bypass,
                        "TASK-1",
                        base=base,
                        head=head,
                        package=PACKAGE,
                        repo=repo,
                        workspace=workspace,
                    )

                governed = approved_snapshot(
                    ("qa", "security"),
                    base=base,
                    head=head,
                    description="",
                    repo=repo,
                    workspace=workspace,
                )
                require_qa(governed, repo=repo, workspace=workspace)
                result = validate(
                    governed,
                    "TASK-1",
                    base=base,
                    head=head,
                    package=PACKAGE,
                    repo=repo,
                    workspace=workspace,
                )
                self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")

    def test_unreadable_exact_diff_fails_closed_to_both_gates(self):
        governed = approved_snapshot(("qa", "security"), description="")
        require_qa(governed)
        with self.assertRaisesRegex(EvidenceError, "authenticated broker receipt"):
            validate(
                governed,
                "TASK-1",
                base=BASE,
                head=HEAD,
                package=PACKAGE,
                repo="/definitely/not/a/repository",
            )


if __name__ == "__main__":
    unittest.main()
