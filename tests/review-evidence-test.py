#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from review_evidence import (  # noqa: E402
    EvidenceError,
    bind_approval,
    bind_request,
    validate,
)


BASE = "a" * 40
HEAD = "b" * 40
PACKAGE = "sha256:" + "c" * 64


def approved_snapshot() -> dict:
    request = bind_request(
        "[review-request]\nFiles: app.py\n\n- backend\n",
        BASE,
        HEAD,
        PACKAGE,
    )
    review = bind_approval(
        "[review-approval]\nFiles: app.py\n\n- reviewer\n",
        request,
    )
    architecture = bind_approval(
        "[architecture-approval]\nFiles: app.py\n\n- principal-architect\n",
        request,
    )
    sceptical = bind_approval(
        "[sceptical-architecture-approval]\nFiles: app.py\n\n- sceptical-architect\n",
        request,
    )
    return {
        "featureId": "FEATURE-1",
        "tasks": [{
            "taskId": "TASK-1",
            "status": "Review",
            "comments": [
                {"id": "request", "body": request, "author": "backend", "createdAt": "1"},
                {"id": "review", "body": review, "author": "reviewer", "createdAt": "2"},
                {
                    "id": "architecture",
                    "body": architecture,
                    "author": "principal-architect",
                    "createdAt": "3",
                },
                {
                    "id": "sceptical-architecture",
                    "body": sceptical,
                    "author": "sceptical-architect",
                    "createdAt": "4",
                },
            ],
        }],
    }


class ReviewEvidenceTest(unittest.TestCase):
    def test_independent_triple_approval_is_bound_to_exact_package(self):
        result = validate(
            approved_snapshot(),
            "TASK-1",
            base=BASE,
            head=HEAD,
            package=PACKAGE,
            review_statuses={"Review"},
        )
        self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")

    def test_missing_sceptical_approval_keeps_release_gate_closed(self):
        data = approved_snapshot()
        data["tasks"][0]["comments"] = data["tasks"][0]["comments"][:-1]
        with self.assertRaisesRegex(EvidenceError, "independently triple-approved"):
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
            {"id": "finding", "body": "[review-findings]\nMust fix", "createdAt": "5"}
        )
        with self.assertRaisesRegex(EvidenceError, "independently triple-approved"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)

    def test_new_request_needs_new_approvals(self):
        data = approved_snapshot()
        data["tasks"][0]["comments"].append(
            {
                "id": "request-2",
                "body": bind_request("[review-request]\nFiles: app.py\n", BASE, HEAD, PACKAGE),
                "createdAt": "5",
            }
        )
        with self.assertRaisesRegex(EvidenceError, "independently triple-approved"):
            validate(data, "TASK-1", base=BASE, head=HEAD, package=PACKAGE)


if __name__ == "__main__":
    unittest.main()
