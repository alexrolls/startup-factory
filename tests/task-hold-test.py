#!/usr/bin/env python3
"""Black-box tests for task-scoped Blocked holds and resume review."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from outbox_capability import mint, sign_entry

SCRIPT = ROOT / "bin" / "task-hold.py"
BROKER_EVIDENCE = ROOT / "bin" / "broker_evidence.py"
FEATURE = "FEATURE-1"
TEAM = "factory-one"
BLOCKED = "Blocked"
QUEUED = "Planned"


def comment(
    comment_id: str,
    body: str,
    *,
    author: str = "person@example.test",
    revision: str | None = None,
) -> dict:
    return {
        "id": comment_id,
        "body": body,
        "author": author,
        "createdAt": "2026-07-14T10:00:00Z",
        "updatedAt": "2026-07-14T10:00:00Z",
        "revision": revision or comment_id,
    }


def task(
    task_id: str,
    status: str,
    *,
    title: str | None = None,
    description: str | None = None,
    comments: list[dict] | None = None,
    attachments: list[dict] | None = None,
    blocked_by: list[str] | None = None,
    revision: str = "r1",
) -> dict:
    return {
        "taskId": task_id,
        "title": title or "Title for %s" % task_id,
        "description": description or "Description for %s" % task_id,
        "status": status,
        "statusRaw": status,
        "assignee": None,
        "blockedBy": list(blocked_by or []),
        "labels": [],
        "comments": list(comments or []),
        "attachments": list(attachments or []),
        "updatedAt": "2026-07-14T10:00:00Z",
        "revision": revision,
    }


class TaskHoldTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.base)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.snapshot_path = self.base / "tasks.json"
        self.delivery_counter = 0
        self.authority_root: Path | None = None
        self.capabilities = {
            role: mint(
                str(self.base),
                str(self.workspace),
                TEAM,
                FEATURE,
                role,
                "gate",
                "-",
                0,
                "test-%s" % role,
            )
            for role in ("team-lead", "principal-architect")
        }

    def tearDown(self) -> None:
        if self.authority_root is not None:
            for path in sorted(self.authority_root.rglob("*"), reverse=True):
                if path.is_file() and not path.is_symlink():
                    path.unlink()
                elif path.is_dir() and not path.is_symlink():
                    path.rmdir()
            self.authority_root.rmdir()
        self.temporary.cleanup()

    def write_snapshot(self, tasks: list[dict]) -> None:
        self.snapshot_path.write_text(
            json.dumps({"featureId": FEATURE, "tasks": tasks}, indent=2) + "\n"
        )

    def next_delivery(self) -> str:
        self.delivery_counter += 1
        return "delivery-%032x" % self.delivery_counter

    def write_receipt(
        self,
        delivery: str,
        marker: str,
        body: str,
        *,
        task_id: str = "TASK-1",
        actor: str = "team-lead",
        **overrides: object,
    ) -> None:
        done = self.workspace / "outbox" / "done"
        done.mkdir(parents=True, exist_ok=True)
        staged = self.workspace / "outbox" / "staged"
        staged.mkdir(parents=True, exist_ok=True)
        raw_body = body.encode("utf-8")
        body_path = staged / (delivery + ".source.md")
        body_path.write_bytes(raw_body)
        receipt = {
            "schemaVersion": 1,
            "id": "receipt-%s" % delivery,
            "team": TEAM,
            "featureId": FEATURE,
            "taskId": task_id,
            "attempt": 0,
            "actor": actor,
            "marker": marker,
            "targetStatus": None,
            "phase": "published",
            "deliveryId": delivery,
            "stagedBodyPath": str(body_path),
            "stagedBodySha256": "sha256:" + hashlib.sha256(raw_body).hexdigest(),
        }
        receipt.update(overrides)
        capability = self.capabilities[actor]
        receipt["producerCapability"] = sign_entry(
            receipt,
            raw_body,
            capability["id"],
            capability["secret"],
            capability["instance"],
            capability["expiresAt"],
        )
        (done / ("%s-%s.json" % (marker, delivery))).write_text(
            json.dumps(receipt, indent=2) + "\n"
        )

    def marker_comment(
        self,
        comment_id: str,
        marker: str,
        fields: list[str],
        *,
        task_id: str = "TASK-1",
        actor: str = "team-lead",
        delivery: str | None = None,
        publish_receipt: bool = True,
    ) -> dict:
        delivery = delivery or self.next_delivery()
        staged_body = "\n".join(
            [
                "[%s]" % marker,
                *fields,
                "",
                "— %s" % actor,
            ]
        )
        if publish_receipt:
            self.write_receipt(
                delivery, marker, staged_body, task_id=task_id, actor=actor
            )
        return comment(
            comment_id,
            staged_body + "\n\ndelivery-id: %s" % delivery,
            author=actor,
        )

    def command(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        if self.authority_root is not None:
            environment["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = str(
                self.authority_root
            )
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )

    def sync(self, tasks: list[dict], *, succeeds: bool = True) -> dict | None:
        self.write_snapshot(tasks)
        result = self.command(
            "sync",
            "--repo",
            str(self.base),
            "--workspace",
            str(self.workspace),
            "--tasks",
            str(self.snapshot_path),
            "--feature",
            FEATURE,
            "--team",
            TEAM,
            "--blocked-status",
            BLOCKED,
            "--queued-status",
            QUEUED,
            "--ignored-labels-json",
            '["human-work"]',
            "--inflight-status",
            QUEUED,
            "--inflight-status",
            "Active",
            "--inflight-status",
            "Review",
        )
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return None

    def registry(self) -> dict:
        return json.loads((self.workspace / "task-holds.json").read_text())

    def entry(self, task_id: str = "TASK-1") -> dict:
        matches = [
            value
            for value in self.registry()["tasks"].values()
            if value.get("taskId") == task_id
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def check(self, task_id: str) -> subprocess.CompletedProcess[str]:
        return self.command(
            "check",
            "--repo",
            str(self.base),
            "--workspace",
            str(self.workspace),
            "--team",
            TEAM,
            "--feature",
            FEATURE,
            "--task",
            task_id,
        )

    def test_blocked_hold_is_task_scoped_and_preserves_full_communication(self) -> None:
        blocked = task(
            "TASK-1",
            BLOCKED,
            comments=[comment("c1", "A complete tracker comment")],
            attachments=[{"id": "attachment-1", "name": "requirements.pdf", "size": 42}],
            blocked_by=["TASK-0"],
        )
        independent = task("TASK-2", QUEUED)

        result = self.sync([blocked, independent])

        self.assertEqual(result["stopTasks"], ["TASK-1"])
        self.assertEqual(result["heldTasks"], ["TASK-1"])
        self.assertEqual(result["resumedTasks"], [])
        self.assertEqual(self.check("TASK-1").returncode, 3)
        self.assertEqual(self.check("TASK-2").returncode, 0)
        entry = self.entry()
        snapshot = json.loads(Path(entry["blockedSnapshotPath"]).read_text())
        self.assertEqual(snapshot["task"]["comments"], blocked["comments"])
        self.assertEqual(snapshot["task"]["attachments"], blocked["attachments"])
        self.assertEqual(snapshot["task"]["blockedBy"], ["TASK-0"])
        self.assertNotIn(
            "TASK-2", [value["taskId"] for value in self.registry()["tasks"].values()]
        )

        # Repeated observation is idempotent: it asks the launcher for another
        # safe stop, but does not create a new hold generation or snapshot.
        original_path = entry["blockedSnapshotPath"]
        repeated = self.sync([blocked, independent])
        self.assertEqual(repeated["stopTasks"], ["TASK-1"])
        self.assertEqual(self.entry()["generation"], 1)
        self.assertEqual(self.entry()["blockedSnapshotPath"], original_path)

    def test_nonqueued_exit_becomes_manual_takeover_until_queued(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])

        active = self.sync([task("TASK-1", "Active", revision="r2")])
        self.assertEqual(active["heldTasks"], ["TASK-1"])
        self.assertEqual(active["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "manual-takeover")
        self.assertEqual(self.entry()["manualStatus"], "Active")
        self.assertEqual(self.check("TASK-1").returncode, 3)

        review = self.sync([task("TASK-1", "Review", revision="r3")])
        self.assertEqual(review["heldTasks"], ["TASK-1"])
        self.assertEqual(self.entry()["state"], "manual-takeover")

        queued = self.sync([task("TASK-1", QUEUED, revision="r4")])
        self.assertEqual(queued["heldTasks"], ["TASK-1"])
        self.assertEqual([item["taskId"] for item in queued["resumePending"]], ["TASK-1"])
        self.assertEqual(self.entry()["state"], "resume-review-pending")

    def test_human_work_label_stops_exact_task_and_skips_dependency_actions(self) -> None:
        blocked = task("TASK-A", BLOCKED)
        reserved = task(
            "TASK-B", "Active", blocked_by=["TASK-A"], revision="reserved-r1"
        )
        reserved["labels"] = ["Human-Work"]
        independent = task("TASK-C", QUEUED)

        result = self.sync([blocked, reserved, independent])

        self.assertEqual(result["stopTasks"], ["TASK-A", "TASK-B"])
        self.assertEqual(result["humanWorkTasks"], ["TASK-B"])
        self.assertEqual(result["dependencyReview"], [])
        self.assertEqual(result["blockDependents"], [])

    def test_protected_ledger_prevents_deleted_or_tampered_resume_bypass(self) -> None:
        self.authority_root = self.base.parent / (self.base.name + "-hold-authority")
        self.authority_root.mkdir(mode=0o700)
        key = self.authority_root / "record-auth.key"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)

        self.sync([task("TASK-1", BLOCKED)])
        protected_files = list((self.authority_root / "task-holds").glob("*.json"))
        self.assertEqual(len(protected_files), 1)

        # Deleting the workspace mirror cannot erase the Blocked generation.
        (self.workspace / "task-holds.json").unlink()
        pending = self.sync([task("TASK-1", QUEUED, revision="r2")])
        self.assertEqual(pending["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")

        # A forged local 'resumed' state is ignored; exact checks consult the
        # authenticated protected ledger.
        forged = self.registry()
        next(iter(forged["tasks"].values()))["state"] = "resumed"
        (self.workspace / "task-holds.json").write_text(json.dumps(forged) + "\n")
        self.assertEqual(self.check("TASK-1").returncode, 3)

    def test_protected_broker_receipt_is_required_for_resume_authority(self) -> None:
        self.authority_root = self.base.parent / (self.base.name + "-broker-authority")
        self.authority_root.mkdir(mode=0o700)
        key = self.authority_root / "record-auth.key"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)

        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        marker = self.marker_comment(
            "protected-review",
            "resume-review",
            [
                "hold-id: %s" % hold["holdId"],
                "communication-digest: %s" % request["currentCommunicationDigest"],
                "verdict: unchanged",
                "summary: exact protected publication",
            ],
        )
        queued["comments"].append(marker)

        forged_workspace_only = self.sync([queued])
        self.assertEqual(forged_workspace_only["resumedTasks"], [])
        delivery = marker["body"].rsplit("delivery-id: ", 1)[1]
        receipt = next(
            (self.workspace / "outbox" / "done").glob("*%s*.json" % delivery)
        )
        environment = dict(os.environ)
        environment["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = str(
            self.authority_root
        )
        recorded = subprocess.run(
            [
                sys.executable,
                str(BROKER_EVIDENCE),
                "--repo",
                str(self.base),
                "--workspace",
                str(self.workspace),
                "--entry",
                str(receipt),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertEqual(recorded.returncode, 0, recorded.stderr)
        accepted = self.sync([queued])
        self.assertEqual(accepted["resumedTasks"], ["TASK-1"])

    def test_queued_resume_reviews_every_change_and_archives_old_claim(self) -> None:
        original = task(
            "TASK-1",
            BLOCKED,
            title="Original title",
            description="Original description",
            comments=[
                comment("keep", "unchanged"),
                comment("edit", "old body", revision="comment-r1"),
                comment("delete", "removed later"),
            ],
            attachments=[{"id": "old", "name": "old.txt"}],
        )
        self.sync([original])
        hold = self.entry()
        current = task(
            "TASK-1",
            QUEUED,
            title="Updated title",
            description="Updated description",
            comments=[
                comment("keep", "unchanged"),
                comment("edit", "new body", revision="comment-r2"),
                comment("add", "new requirement"),
            ],
            attachments=[{"id": "new", "name": "new.txt"}],
            revision="r2",
        )

        pending = self.sync([current])
        self.assertEqual([item["taskId"] for item in pending["resumePending"]], ["TASK-1"])
        request = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        self.assertEqual(request["delta"]["addedCommentIds"], ["add"])
        self.assertEqual(request["delta"]["deletedCommentIds"], ["delete"])
        self.assertEqual(request["delta"]["editedCommentIds"], ["edit"])
        self.assertTrue(request["delta"]["titleChanged"])
        self.assertTrue(request["delta"]["descriptionChanged"])
        self.assertTrue(request["delta"]["attachmentsChanged"])
        current_digest = request["currentCommunicationDigest"]

        # A review for any other communication digest cannot release the task.
        current["comments"].append(
            self.marker_comment(
                "wrong-review",
                "resume-review",
                [
                    "hold-id: %s" % hold["holdId"],
                    "communication-digest: sha256:%s" % ("0" * 64),
                    "verdict: unchanged",
                    "summary: reviewed the wrong snapshot",
                ],
            )
        )
        still_pending = self.sync([current])
        self.assertEqual(still_pending["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")
        # Resume markers are deliberately excluded from the reviewed digest,
        # so posting the verdict does not create a digest recursion.
        request_after_wrong_review = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        self.assertEqual(
            request_after_wrong_review["currentCommunicationDigest"], current_digest
        )

        claim_directory = self.workspace / "claims"
        claim_directory.mkdir()
        claim = {"taskId": "TASK-1", "attempt": 2, "role": "backend"}
        (claim_directory / (hold["taskKey"] + ".json")).write_text(
            json.dumps(claim) + "\n"
        )
        current["comments"].append(
            self.marker_comment(
                "valid-review",
                "resume-review",
                [
                    "hold-id: %s" % hold["holdId"],
                    "communication-digest: %s" % current_digest,
                    "verdict: unchanged",
                    "summary: all communication read in full",
                ],
            )
        )

        resumed = self.sync([current])

        self.assertEqual(resumed["resumedTasks"], ["TASK-1"])
        self.assertEqual(resumed["heldTasks"], [])
        self.assertEqual(self.entry()["state"], "resumed")
        self.assertEqual(self.check("TASK-1").returncode, 0)
        self.assertFalse((claim_directory / (hold["taskKey"] + ".json")).exists())
        history = claim_directory / "history" / (
            "%s-a2-hold-1.json" % hold["taskKey"]
        )
        self.assertEqual(json.loads(history.read_text()), claim)

    def test_requirements_changed_needs_both_later_design_approvals(self) -> None:
        lead_role = "principal-team-lead"
        architect_role = "principal-architect-concrete"
        sceptical_role = "sceptical-architect-concrete"
        (self.workspace / "preset.env").write_text(
            "PROTOCOL_TEAM_LEAD=%s\nPROTOCOL_PRINCIPAL_ARCHITECT=%s\n"
            "PROTOCOL_SCEPTICAL_ARCHITECT=%s\n"
            % (lead_role, architect_role, sceptical_role)
        )
        for role in (lead_role, architect_role, sceptical_role):
            self.capabilities[role] = mint(
                str(self.base),
                str(self.workspace),
                TEAM,
                FEATURE,
                role,
                "gate",
                "-",
                0,
                "test-%s" % role,
            )
        self.sync([task("TASK-1", BLOCKED, description="old")])
        hold = self.entry()
        queued = task("TASK-1", QUEUED, description="new", revision="r2")
        self.sync([queued])
        request = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        queued["comments"].append(
            self.marker_comment(
                "resume",
                "resume-review",
                [
                    "hold-id: %s" % hold["holdId"],
                    "communication-digest: %s" % request["currentCommunicationDigest"],
                    "verdict: requirements-changed",
                    "summary: acceptance criteria changed",
                ],
                actor=lead_role,
            )
        )

        without_design = self.sync([queued])
        self.assertEqual(without_design["resumedTasks"], [])
        queued["comments"].append(
            self.marker_comment(
                "design",
                "resume-plan",
                ["summary: Updated implementation plan"],
                actor=lead_role,
            )
        )
        queued["comments"].append(
            self.marker_comment(
                "approval",
                "design-approved",
                ["summary: Approved updated design"],
                actor=architect_role,
            )
        )
        queued["comments"].append(
            self.marker_comment(
                "sceptical-approval",
                "sceptical-design-approved",
                ["summary: Independent challenge cleared"],
                actor=sceptical_role,
            )
        )

        approved = self.sync([queued])
        self.assertEqual(approved["resumedTasks"], ["TASK-1"])

    def test_new_ordinary_comment_invalidates_an_exact_resume_verdict(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request_path = Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json"
        reviewed_digest = json.loads(request_path.read_text())[
            "currentCommunicationDigest"
        ]
        queued["comments"].append(
            self.marker_comment(
                "first-review",
                "resume-review",
                [
                    "hold-id: %s" % hold["holdId"],
                    "communication-digest: %s" % reviewed_digest,
                    "verdict: unchanged",
                    "summary: communication reviewed",
                ],
            )
        )
        queued["comments"].append(
            comment("late-requirement", "New acceptance criterion after the review")
        )

        invalidated = self.sync([queued])

        self.assertEqual(invalidated["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")
        fresh_digest = json.loads(request_path.read_text())["currentCommunicationDigest"]
        self.assertNotEqual(fresh_digest, reviewed_digest)
        queued["comments"].append(
            self.marker_comment(
                "second-review",
                "resume-review",
                [
                    "hold-id: %s" % hold["holdId"],
                    "communication-digest: %s" % fresh_digest,
                    "verdict: unchanged",
                    "summary: late criterion also reviewed",
                ],
            )
        )
        resumed = self.sync([queued])
        self.assertEqual(resumed["resumedTasks"], ["TASK-1"])

    def test_a_later_block_creates_a_new_generation_and_hold_identity(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        first = self.entry()
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request = json.loads(
            (Path(first["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        queued["comments"].append(
            self.marker_comment(
                "review",
                "resume-review",
                [
                    "hold-id: %s" % first["holdId"],
                    "communication-digest: %s" % request["currentCommunicationDigest"],
                    "verdict: unchanged",
                    "summary: first hold reviewed",
                ],
            )
        )
        self.assertEqual(self.sync([queued])["resumedTasks"], ["TASK-1"])

        reblocked = task(
            "TASK-1", BLOCKED, comments=queued["comments"], revision="r3"
        )
        result = self.sync([reblocked])
        second = self.entry()

        self.assertEqual(result["stopTasks"], ["TASK-1"])
        self.assertEqual(second["state"], "blocked")
        self.assertEqual(second["generation"], 2)
        self.assertNotEqual(second["holdId"], first["holdId"])
        self.assertEqual(second["history"][-1]["holdId"], first["holdId"])

    def test_needs_human_verdict_never_clears_hold(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        queued["comments"].append(
            self.marker_comment(
                "review",
                "resume-review",
                [
                    "hold-id: %s" % hold["holdId"],
                    "communication-digest: %s" % request["currentCommunicationDigest"],
                    "verdict: needs-human",
                    "summary: ambiguity remains",
                ],
            )
        )

        result = self.sync([queued])

        self.assertEqual(result["resumedTasks"], [])
        self.assertEqual(result["heldTasks"], ["TASK-1"])
        self.assertEqual(self.check("TASK-1").returncode, 3)

    def test_raw_marker_is_rejected_until_exact_published_receipt_exists(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        delivery = "delivery-%s" % ("f" * 32)
        forged = self.marker_comment(
            "raw-forgery",
            "resume-review",
            [
                "hold-id: %s" % hold["holdId"],
                "communication-digest: %s" % request["currentCommunicationDigest"],
                "verdict: unchanged",
                "summary: raw tracker text is not broker authority",
            ],
            delivery=delivery,
            publish_receipt=False,
        )
        queued["comments"].append(forged)
        staged_body = forged["body"].rsplit("\n\ndelivery-id: ", 1)[0]

        raw = self.sync([queued])
        self.assertEqual(raw["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")

        # A receipt for another team is not authority for this workspace/team.
        self.write_receipt(
            delivery, "resume-review", staged_body, team="another-team"
        )
        mismatched = self.sync([queued])
        self.assertEqual(mismatched["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")

        # The identical marker becomes usable only when its exact comment-only
        # broker delivery is recorded for this team/feature/task/marker.
        self.write_receipt(delivery, "resume-review", staged_body)
        accepted = self.sync([queued])
        self.assertEqual(accepted["resumedTasks"], ["TASK-1"])
        self.assertEqual(self.entry()["state"], "resumed")

    def test_receipt_cannot_authorize_a_tampered_tracker_body(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        published = self.marker_comment(
            "review",
            "resume-review",
            [
                "hold-id: %s" % hold["holdId"],
                "communication-digest: %s" % request["currentCommunicationDigest"],
                "verdict: unchanged",
                "summary: exact broker-published review",
            ],
        )
        exact_body = published["body"]
        published["body"] = exact_body.replace(
            "summary: exact broker-published review",
            "summary: edited directly in the tracker",
        )
        queued["comments"].append(published)

        tampered = self.sync([queued])
        self.assertEqual(tampered["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")

        published["body"] = exact_body
        exact = self.sync([queued])
        self.assertEqual(exact["resumedTasks"], ["TASK-1"])

    def test_signed_staged_marker_cannot_be_rebound_to_mutable_publish_bytes(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        published = self.marker_comment(
            "review",
            "resume-review",
            [
                "hold-id: %s" % hold["holdId"],
                "communication-digest: %s" % request["currentCommunicationDigest"],
                "verdict: unchanged",
                "summary: signed original review",
            ],
        )
        delivery = published["body"].rsplit("delivery-id: ", 1)[1]
        receipt_path = next((self.workspace / "outbox" / "done").glob("*%s*.json" % delivery))
        receipt = json.loads(receipt_path.read_text())
        forged_body = (
            published["body"].rsplit("\n\ndelivery-id: ", 1)[0]
            .replace("summary: signed original review", "summary: mutable forged review")
            .encode("utf-8")
        )
        forged_path = self.workspace / "outbox" / "staged" / (delivery + ".publish.md")
        forged_path.write_bytes(forged_body)
        receipt["publishBodyPath"] = str(forged_path)
        receipt["publishBodySha256"] = "sha256:" + hashlib.sha256(forged_body).hexdigest()
        receipt_path.write_text(json.dumps(receipt) + "\n")
        published["body"] = forged_body.decode() + "\n\ndelivery-id: " + delivery
        queued["comments"].append(published)

        rejected = self.sync([queued])

        self.assertEqual(rejected["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")

    def test_old_delivery_cannot_be_replayed_for_a_new_hold_generation(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        first = self.entry()
        first_queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([first_queued])
        first_request = json.loads(
            (Path(first["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        first_review = self.marker_comment(
            "first-review",
            "resume-review",
            [
                "hold-id: %s" % first["holdId"],
                "communication-digest: %s"
                % first_request["currentCommunicationDigest"],
                "verdict: unchanged",
                "summary: first generation reviewed",
            ],
        )
        first_queued["comments"].append(first_review)
        self.assertEqual(self.sync([first_queued])["resumedTasks"], ["TASK-1"])
        old_delivery = first_review["body"].rsplit("delivery-id: ", 1)[1]

        second_blocked = task(
            "TASK-1", BLOCKED, comments=first_queued["comments"], revision="r3"
        )
        self.sync([second_blocked])
        second = self.entry()
        self.assertEqual(second["generation"], 2)
        second_queued = task(
            "TASK-1",
            QUEUED,
            description="requirements after second hold",
            comments=first_queued["comments"],
            revision="r4",
        )
        self.sync([second_queued])
        second_request = json.loads(
            (Path(second["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        second_queued["comments"].append(
            self.marker_comment(
                "replayed-review",
                "resume-review",
                [
                    "hold-id: %s" % second["holdId"],
                    "communication-digest: %s"
                    % second_request["currentCommunicationDigest"],
                    "verdict: unchanged",
                    "summary: forged by replaying the old delivery identity",
                ],
                delivery=old_delivery,
                publish_receipt=False,
            )
        )

        replayed = self.sync([second_queued])
        self.assertEqual(replayed["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")
        # The unauthenticated replay remains ordinary tracker communication, so
        # it deliberately changes the reviewed digest and requires a fresh
        # lead verdict that acknowledges its presence.
        second_request = json.loads(
            (Path(second["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )

        second_queued["comments"].append(
            self.marker_comment(
                "second-review",
                "resume-review",
                [
                    "hold-id: %s" % second["holdId"],
                    "communication-digest: %s"
                    % second_request["currentCommunicationDigest"],
                    "verdict: unchanged",
                    "summary: second generation reviewed through the broker",
                ],
            )
        )
        accepted = self.sync([second_queued])
        self.assertEqual(accepted["resumedTasks"], ["TASK-1"])

    def test_dirty_previous_worktree_cannot_be_discarded_or_reused(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        worktree = self.base / "prior-worktree"
        subprocess.run(
            ["git", "init", "-q", str(worktree)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        (worktree / "unfinished.txt").write_text("valuable uncommitted work\n")
        executions = self.workspace / "executions"
        executions.mkdir()
        (executions / (hold["taskKey"] + ".json")).write_text(
            json.dumps({"taskId": "TASK-1", "worktree": str(worktree)}) + "\n"
        )
        claims = self.workspace / "claims"
        claims.mkdir()
        claim_path = claims / (hold["taskKey"] + ".json")
        claim_path.write_text(json.dumps({"taskId": "TASK-1", "attempt": 1}) + "\n")
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request_path = Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json"
        request = json.loads(request_path.read_text())
        queued["comments"].append(
            self.marker_comment(
                "review",
                "resume-review",
                [
                    "hold-id: %s" % hold["holdId"],
                    "communication-digest: %s" % request["currentCommunicationDigest"],
                    "verdict: unchanged",
                    "summary: no requirement changes",
                ],
            )
        )

        result = self.sync([queued])

        self.assertEqual(result["resumedTasks"], [])
        self.assertEqual(self.entry()["state"], "resume-review-pending")
        self.assertFalse(self.entry()["previousWorktreeClean"])
        self.assertTrue(claim_path.exists())
        self.assertEqual((worktree / "unfinished.txt").read_text(), "valuable uncommitted work\n")

    def test_blocked_snapshot_tampering_fails_closed(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        snapshot = Path(self.entry()["blockedSnapshotPath"])
        value = json.loads(snapshot.read_text())
        value["task"]["description"] = "tampered"
        snapshot.write_text(json.dumps(value) + "\n")

        self.sync([task("TASK-1", QUEUED, revision="r2")], succeeds=False)

        # The transition is not persisted when its immutable evidence changed.
        self.assertEqual(self.entry()["state"], "blocked")

    def test_dependency_review_uses_only_direct_graph_edges_and_revalidates(self) -> None:
        blocked = task("TASK-A", BLOCKED)
        dependent = task(
            "TASK-B", "Active", blocked_by=["TASK-A"], revision="dependent-r1"
        )
        prose_only = task(
            "TASK-C", "Active", description="TASK-A may be relevant", revision="prose-r1"
        )
        queued_dependent = task(
            "TASK-D", QUEUED, blocked_by=["TASK-A"], revision="queued-r1"
        )
        partially_actionable = task(
            "TASK-E", "Review", blocked_by=["TASK-A"], revision="partial-r1"
        )
        independently_actionable = task(
            "TASK-F", QUEUED, blocked_by=["TASK-A"], revision="independent-r1"
        )

        first = self.sync(
            [
                blocked,
                dependent,
                prose_only,
                queued_dependent,
                partially_actionable,
                independently_actionable,
            ]
        )

        self.assertEqual(
            [item["taskId"] for item in first["dependencyReview"]],
            ["TASK-B", "TASK-D", "TASK-E", "TASK-F"],
        )
        self.assertEqual(first["blockDependents"], [])
        self.assertNotIn("TASK-C", first["heldTasks"])
        self.assertNotIn("TASK-D", first["heldTasks"])
        digests = {
            item["taskId"]: item["graphDigest"] for item in first["dependencyReview"]
        }
        graph_digest = digests["TASK-B"]
        dependent["comments"].append(
            self.marker_comment(
                "dependency-review",
                "dependency-hold",
                [
                    "blocked-by: TASK-A",
                    "graph-digest: %s" % graph_digest,
                    "verdict: blocked",
                    "reason: no independently deliverable slice remains",
                ],
                task_id="TASK-B",
            )
        )
        partially_actionable["comments"].append(
            self.marker_comment(
                "partial-review",
                "dependency-hold",
                [
                    "blocked-by: TASK-A",
                    "graph-digest: %s" % digests["TASK-E"],
                    "verdict: partially-actionable",
                    "reason: a safe independent slice remains",
                ],
                task_id="TASK-E",
            )
        )
        queued_dependent["comments"].append(
            self.marker_comment(
                "queued-dependency-review",
                "dependency-hold",
                [
                    "blocked-by: TASK-A",
                    "graph-digest: %s" % digests["TASK-D"],
                    "verdict: blocked",
                    "reason: this queued implementation cannot start before TASK-A",
                ],
                task_id="TASK-D",
            )
        )
        independently_actionable["comments"].append(
            self.marker_comment(
                "independent-dependency-review",
                "dependency-hold",
                [
                    "blocked-by: TASK-A",
                    "graph-digest: %s" % digests["TASK-F"],
                    "verdict: independent",
                    "reason: this queued slice does not consume TASK-A output",
                ],
                task_id="TASK-F",
            )
        )

        second = self.sync(
            [
                blocked,
                dependent,
                prose_only,
                queued_dependent,
                partially_actionable,
                independently_actionable,
            ]
        )
        self.assertEqual(
            [item["taskId"] for item in second["blockDependents"]],
            ["TASK-B", "TASK-D"],
        )
        self.assertEqual(second["dependencyReview"], [])
        self.assertNotIn("TASK-E", second["heldTasks"])
        claim = self.command(
            "authorize-claim",
            "--repo",
            str(self.base),
            "--tasks",
            str(self.snapshot_path),
            "--feature",
            FEATURE,
            "--workspace",
            str(self.workspace),
            "--team",
            TEAM,
            "--task",
            "TASK-F",
            "--queued-status",
            QUEUED,
            "--blocked-status",
            BLOCKED,
            "--terminal-status",
            "Done",
        )
        self.assertEqual(claim.returncode, 0, claim.stderr)
        self.assertEqual(
            json.loads(claim.stdout)["dependencyAuthority"], "independent"
        )
        validation = self.command(
            "validate-dependent",
            "--repo",
            str(self.base),
            "--tasks",
            str(self.snapshot_path),
            "--feature",
            FEATURE,
            "--workspace",
            str(self.workspace),
            "--team",
            TEAM,
            "--task",
            "TASK-B",
            "--graph-digest",
            graph_digest,
            "--blocked-status",
            BLOCKED,
            "--inflight-status",
            "Active",
            "--inflight-status",
            "Review",
        )
        self.assertEqual(validation.returncode, 0, validation.stderr)
        self.assertEqual(json.loads(validation.stdout)["blockedBy"], ["TASK-A"])

        # A changed authoritative graph/revision invalidates the prior verdict
        # and asks the lead to review again instead of applying a stale block.
        dependent["revision"] = "dependent-r2"
        self.write_snapshot(
            [
                blocked,
                dependent,
                prose_only,
                queued_dependent,
                partially_actionable,
                independently_actionable,
            ]
        )
        stale = self.command(
            "validate-dependent",
            "--repo",
            str(self.base),
            "--tasks",
            str(self.snapshot_path),
            "--feature",
            FEATURE,
            "--workspace",
            str(self.workspace),
            "--team",
            TEAM,
            "--task",
            "TASK-B",
            "--graph-digest",
            graph_digest,
            "--blocked-status",
            BLOCKED,
            "--inflight-status",
            "Active",
            "--inflight-status",
            "Review",
        )
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("dependency graph changed", stale.stderr)
        changed = self.sync(
            [
                blocked,
                dependent,
                prose_only,
                queued_dependent,
                partially_actionable,
                independently_actionable,
            ]
        )
        self.assertEqual(
            [item["taskId"] for item in changed["blockDependents"]], ["TASK-D"]
        )
        self.assertEqual(
            [item["taskId"] for item in changed["dependencyReview"]], ["TASK-B"]
        )
        self.assertNotEqual(changed["dependencyReview"][0]["graphDigest"], graph_digest)

    def test_hold_storage_cannot_escape_workspace_through_parent_symlink(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        (self.workspace / "holds").symlink_to(outside, target_is_directory=True)

        self.sync([task("TASK-1", BLOCKED)], succeeds=False)

        self.assertEqual(list(outside.iterdir()), [])

    def test_resume_request_refuses_symlink_leaf_without_touching_target(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        victim = self.base / "victim.txt"
        victim.write_text("must survive\n")
        request = Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.md"
        request.symlink_to(victim)

        self.sync([task("TASK-1", QUEUED, revision="r2")], succeeds=False)

        self.assertEqual(victim.read_text(), "must survive\n")

    def test_claim_archive_refuses_history_parent_symlink(self) -> None:
        self.sync([task("TASK-1", BLOCKED)])
        hold = self.entry()
        queued = task("TASK-1", QUEUED, revision="r2")
        self.sync([queued])
        request = json.loads(
            (Path(hold["blockedSnapshotPath"]).parent / "resume-review-request.json").read_text()
        )
        queued["comments"].append(
            self.marker_comment(
                "review",
                "resume-review",
                [
                    "hold-id: %s" % hold["holdId"],
                    "communication-digest: %s" % request["currentCommunicationDigest"],
                    "verdict: unchanged",
                    "summary: all communication reviewed",
                ],
            )
        )
        claims = self.workspace / "claims"
        claims.mkdir()
        claim_path = claims / (hold["taskKey"] + ".json")
        claim_path.write_text(json.dumps({"taskId": "TASK-1", "attempt": 1}) + "\n")
        outside = self.base / "outside-history"
        outside.mkdir()
        (claims / "history").symlink_to(outside, target_is_directory=True)

        self.sync([queued], succeeds=False)

        self.assertTrue(claim_path.exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_tracker_snapshot_symlink_is_rejected(self) -> None:
        real_snapshot = self.base / "real-tasks.json"
        real_snapshot.write_text(
            json.dumps(
                {"featureId": FEATURE, "tasks": [task("TASK-1", BLOCKED)]}
            )
            + "\n"
        )
        self.snapshot_path.symlink_to(real_snapshot)
        result = self.command(
            "sync",
            "--repo",
            str(self.base),
            "--workspace",
            str(self.workspace),
            "--tasks",
            str(self.snapshot_path),
            "--feature",
            FEATURE,
            "--team",
            TEAM,
            "--blocked-status",
            BLOCKED,
            "--queued-status",
            QUEUED,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-symlink regular file", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
