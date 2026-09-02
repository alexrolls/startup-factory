#!/usr/bin/env python3
"""Black-box tests for the cheap change token that gates the feature export.

The export dominates the cost of a dispatch pass.  The token exists so an idle
pass costs a couple of requests instead of hundreds, which is what makes the
documented watch loop affordable.  Its one hard requirement is that it must
never report "nothing moved" when something did.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATUS_FIXTURE = ROOT / "tests" / "fixtures" / "statuses.default-profile.json"
PROJECT_UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"


def load_definitions(adapter, extra_config=""):
    source = (ROOT / "bin" / "tracker-ops.sh").read_text()
    embedded = source.split("<<'PYEOF'\n", 1)[1].rsplit("\nPYEOF", 1)[0]
    definitions = embedded.split("\nBACKENDS =", 1)[0]
    temp = tempfile.TemporaryDirectory()
    skill = Path(temp.name)
    (skill / "config").mkdir()
    (skill / "bin").mkdir()
    shutil.copy(DEFAULT_STATUS_FIXTURE, skill / "config" / "statuses.config.json")
    shutil.copy(ROOT / "bin" / "ticket_content_security.py",
                skill / "bin" / "ticket_content_security.py")
    (skill / "config" / "project-management.config.md").write_text(
        "PRODUCT_MANAGEMENT_TOOL=%s\nSTATUS_CONFIG=config/statuses.config.json\n%s"
        % (adapter, extra_config))
    old_argv = sys.argv
    sys.argv = ["tracker-ops-test", str(skill)]
    namespace = {"__name__": "tracker_ops_definitions"}
    try:
        exec(compile(definitions, "tracker-ops embedded", "exec"), namespace)
    finally:
        sys.argv = old_argv
    namespace["_tempdir"] = temp
    return namespace


class LinearChangeTokenTest(unittest.TestCase):
    def setUp(self):
        os.environ["LINEAR_API_KEY"] = "offline-test-key"
        self.ns = load_definitions("Linear", "LINEAR_DEFAULT_TEAM=ENG\n")
        self.linear = self.ns["Linear"]()
        self.requests = 0

    def respond(self, *, project="2026-09-02T10:00:00Z",
                issue="2026-09-02T11:00:00Z", comment="2026-09-02T11:30:00Z",
                issue_nodes=None, comment_nodes=None):
        """Answer both probe queries the way a newest-first connection would.

        The adapter asks for two nodes so it can check the ordering it asked
        for, so the stub returns a strictly older second node.
        """
        def newest_first(mark, older):
            return [{"updatedAt": mark}, {"updatedAt": older}] if mark else []

        def gql(query, variables=None):
            self.requests += 1
            if "comments(" in query:
                nodes = (comment_nodes if comment_nodes is not None
                         else newest_first(comment, "2026-09-01T00:00:00Z"))
                return {"comments": {"nodes": nodes}}
            nodes = (issue_nodes if issue_nodes is not None
                     else newest_first(issue, "2026-09-01T00:00:00Z"))
            return {"project": {"updatedAt": project,
                                "issues": {"nodes": nodes,
                                           "pageInfo": {"hasNextPage": False}}}}
        self.linear.gql = gql
        return gql

    def test_an_idle_project_costs_two_requests(self) -> None:
        """The whole point: bounded cost that does not scale with task count.

        A UUID feature id resolves without a lookup, so this counts the probe
        itself. A name-configured [feature] adds exactly one resolution request,
        which the next test pins; neither grows with [task] count.
        """
        self.respond()
        self.linear.change_token(PROJECT_UUID)
        self.assertEqual(self.requests, 2)

    def test_a_name_configured_project_adds_one_resolution_request(self) -> None:
        outer = self.respond()

        def gql(query, variables=None):
            if "projects(first: 2" in query:
                self.requests += 1
                return {"projects": {"nodes": [{"id": PROJECT_UUID,
                                                "name": "Feature One"}]}}
            return outer(query, variables)

        self.linear.gql = gql
        self.assertTrue(self.linear.change_token("Feature One"))
        self.assertEqual(self.requests, 3)

    def test_the_token_is_stable_while_nothing_moves(self) -> None:
        self.respond()
        first = self.linear.change_token(PROJECT_UUID)
        second = self.linear.change_token(PROJECT_UUID)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("linear:"))

    def test_an_edited_issue_moves_the_token(self) -> None:
        self.respond()
        before = self.linear.change_token(PROJECT_UUID)
        self.respond(issue="2026-09-02T11:45:00Z")
        self.assertNotEqual(before, self.linear.change_token(PROJECT_UUID))

    def test_a_new_comment_moves_the_token(self) -> None:
        """A review verdict arrives as a comment; missing it would strand it."""
        self.respond()
        before = self.linear.change_token(PROJECT_UUID)
        self.respond(comment="2026-09-02T12:15:00Z")
        self.assertNotEqual(before, self.linear.change_token(PROJECT_UUID))

    def test_a_project_edit_moves_the_token(self) -> None:
        self.respond()
        before = self.linear.change_token(PROJECT_UUID)
        self.respond(project="2026-09-02T12:00:00Z")
        self.assertNotEqual(before, self.linear.change_token(PROJECT_UUID))

    def test_an_empty_project_still_yields_a_token(self) -> None:
        self.respond(issue="", comment="")
        self.assertTrue(self.linear.change_token(PROJECT_UUID))

    def test_a_first_issue_moves_the_token_from_empty(self) -> None:
        self.respond(issue="", comment="")
        before = self.linear.change_token(PROJECT_UUID)
        self.respond(comment="")
        self.assertNotEqual(before, self.linear.change_token(PROJECT_UUID))

    def test_a_malformed_issue_response_forces_a_full_export(self) -> None:
        self.respond(issue_nodes="not-a-list")
        self.assertIsNone(self.linear.change_token(PROJECT_UUID))

    def test_a_malformed_comment_response_forces_a_full_export(self) -> None:
        self.respond(comment_nodes="not-a-list")
        self.assertIsNone(self.linear.change_token(PROJECT_UUID))

    def test_a_missing_project_forces_a_full_export(self) -> None:
        self.linear.gql = lambda query, variables=None: {}
        self.assertIsNone(self.linear.change_token(PROJECT_UUID))

    def test_an_oldest_first_connection_forces_a_full_export(self) -> None:
        """The ordering is checked, not trusted.

        If the connection came back oldest-first the mark would freeze and the
        cache would go stale silently, so the token refuses to answer.
        """
        self.respond(issue_nodes=[{"updatedAt": "2026-09-01T00:00:00Z"},
                                  {"updatedAt": "2026-09-02T11:00:00Z"}])
        self.assertIsNone(self.linear.change_token(PROJECT_UUID))

    def test_an_oldest_first_comment_connection_forces_a_full_export(self) -> None:
        self.respond(comment_nodes=[{"updatedAt": "2026-09-01T00:00:00Z"},
                                    {"updatedAt": "2026-09-02T11:30:00Z"}])
        self.assertIsNone(self.linear.change_token(PROJECT_UUID))

    def test_a_single_issue_project_needs_no_ordering_proof(self) -> None:
        """One node cannot be mis-ordered, so it is still a usable mark."""
        self.respond(issue_nodes=[{"updatedAt": "2026-09-02T11:00:00Z"}])
        self.assertTrue(self.linear.change_token(PROJECT_UUID))

    def test_a_non_string_timestamp_forces_a_full_export(self) -> None:
        self.respond(issue_nodes=[{"updatedAt": 1757000000}])
        self.assertIsNone(self.linear.change_token(PROJECT_UUID))


class MarkdownChangeTokenTest(unittest.TestCase):
    def setUp(self):
        self.ns = load_definitions("Markdown")
        self.markdown = self.ns["Markdown"]()
        self.text = "# Feature [Planned]\n\n- TASK-1 [Planned]\n"
        self.markdown.load = lambda feature_id: self.text

    def test_the_token_is_exact_for_a_single_file_board(self) -> None:
        first = self.markdown.change_token("FEATURE-1")
        self.assertTrue(first.startswith("sha256:"))
        self.assertEqual(first, self.markdown.change_token("FEATURE-1"))

    def test_any_edit_moves_the_token(self) -> None:
        before = self.markdown.change_token("FEATURE-1")
        self.text = "# Feature [Active]\n\n- TASK-1 [Active]\n"
        self.assertNotEqual(before, self.markdown.change_token("FEATURE-1"))

    def test_a_removed_task_moves_the_token(self) -> None:
        """A high-water mark could miss a delete; a digest cannot."""
        before = self.markdown.change_token("FEATURE-1")
        self.text = "# Feature [Planned]\n"
        self.assertNotEqual(before, self.markdown.change_token("FEATURE-1"))


class AdapterContractTest(unittest.TestCase):
    def test_adapters_without_a_token_are_still_supported(self) -> None:
        """Absence must degrade to the exhaustive export, never to a false skip."""
        namespace = load_definitions("Jira", "JIRA_PROJECT_KEY=ENG\n")
        for adapter in ("Jira", "GitHubIssues"):
            with self.subTest(adapter=adapter):
                backend = namespace.get(adapter)
                self.assertIsNotNone(backend)
                self.assertFalse(
                    callable(getattr(backend, "change_token", None)),
                    "%s advertises a change token; it needs its own coverage"
                    % adapter,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
