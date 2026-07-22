#!/usr/bin/env python3
"""Offline contract tests for the remote tracker adapters' pagination paths."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]


def load_definitions(adapter, extra_config=""):
    source = (ROOT / "bin" / "tracker-ops.sh").read_text()
    embedded = source.split("<<'PYEOF'\n", 1)[1].rsplit("\nPYEOF", 1)[0]
    definitions = embedded.split("\nBACKENDS =", 1)[0]
    temp = tempfile.TemporaryDirectory()
    skill = Path(temp.name)
    (skill / "config").mkdir()
    (skill / "bin").mkdir()
    shutil.copy(ROOT / "config" / "statuses.config.json",
                skill / "config" / "statuses.config.json")
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


def connection(nodes, has_next=False, cursor=None):
    return {"nodes": nodes,
            "pageInfo": {"hasNextPage": has_next, "endCursor": cursor}}


class LinearPaginationTest(unittest.TestCase):
    def setUp(self):
        os.environ["LINEAR_API_KEY"] = "offline-test-key"
        self.ns = load_definitions("Linear", "LINEAR_DEFAULT_TEAM=ENG\n")
        self.linear = self.ns["Linear"]()

    def test_export_hydrates_every_connection_and_orders_comments(self):
        project_id = "00000000-0000-0000-0000-000000000001"
        top_queries = []
        updates = []

        comments = {
            None: connection([
                {"id": "c2", "body": "later", "createdAt": "2026-02-02T00:00:00Z",
                 "updatedAt": "2026-02-02T00:00:00Z",
                 "user": {"name": "Later", "email": None}},
            ], True, "comments-2"),
            "comments-2": connection([
                {"id": "c1", "body": "late needle", "createdAt": "2026-01-01T00:00:00Z",
                 "updatedAt": "2026-04-04T00:00:00Z",
                 "user": {"name": "Early", "email": "early@example.test"}},
                {"id": "progress", "body": "[progress]\nold", "createdAt": "2026-03-03T00:00:00Z",
                 "updatedAt": "2026-03-03T00:00:00Z",
                 "user": {"name": "Bot", "email": None}},
            ]),
        }
        labels = {
            None: connection([{"name": "automation"}], True, "labels-2"),
            "labels-2": connection([{"name": "team-preset:deep"}]),
        }
        relations = {
            None: connection([], True, "relations-2"),
            "relations-2": connection([
                {"type": "blocks", "issue": {"identifier": "ENG-9"}},
            ]),
        }

        def gql(query, variables=None):
            variables = variables or {}
            if "teams(first:" in query:
                return {"teams": connection([
                    {"id": "team-id", "key": "ENG", "name": "Engineering"},
                ])}
            if "project(id:" in query and "issues(first:" in query:
                top_queries.append(query)
                self.assertIn("includeArchived: true", query)
                self.assertNotIn("comments(first:", query)
                self.assertNotIn("labels(first:", query)
                self.assertNotIn("inverseRelations(first:", query)
                if variables.get("after") is None:
                    return {"project": {"issues": connection([{
                        "id": "issue-id", "identifier": "ENG-1", "title": "Ship it",
                        "description": "body", "updatedAt": "2026-04-01T00:00:00Z",
                        "state": {"name": "ToDo"}, "assignee": {"name": "Ada"},
                        "team": {"id": "team-id", "key": "ENG", "name": "Engineering"},
                    }], True, "issues-2")}}
                return {"project": {"issues": connection([])}}
            if "comments(first:" in query:
                self.assertIn("updatedAt", query)
                return {"issue": {"comments": comments[variables.get("after")]}}
            if "labels(first:" in query:
                return {"issue": {"labels": labels[variables.get("after")]}}
            if "inverseRelations(first:" in query:
                return {"issue": {"inverseRelations": relations[variables.get("after")]}}
            if "issue(id:" in query and "team { id }" in query:
                return {"issue": {"id": "issue-id", "identifier": "ENG-1",
                                  "team": {"id": "team-id"}}}
            if "commentUpdate" in query:
                updates.append(variables)
                return {"commentUpdate": {"success": True,
                                           "comment": {"id": variables["cid"],
                                                       "body": variables["body"]}}}
            self.fail("unexpected Linear query: %s" % query)

        self.linear.gql = gql
        tasks = self.linear.export(project_id)
        self.ns["normalize_task_record"](tasks[0], "Linear export fixture")
        self.assertEqual(2, len(top_queries))
        self.assertEqual(["c2", "progress", "c1"],
                         [comment["id"] for comment in tasks[0]["comments"]])
        self.assertEqual("2026-04-04T00:00:00Z", tasks[0]["comments"][-1]["updatedAt"])
        self.assertEqual(tasks[0]["comments"][-1]["updatedAt"],
                         tasks[0]["comments"][-1]["revision"])
        self.assertEqual(["automation", "team-preset:deep"], tasks[0]["labels"])
        self.assertEqual(["ENG-9"], tasks[0]["blockedBy"])
        self.assertTrue(self.linear.comment_exists("ENG-1", "late needle"))
        self.assertEqual("progress", self.linear.upsert_progress("ENG-1", "[progress]\nnew"))
        self.assertEqual("progress", updates[0]["cid"])

    def test_scan_resolves_and_server_filters_team_and_status(self):
        issue_queries = []

        def gql(query, variables=None):
            variables = variables or {}
            if "teams(first:" in query:
                return {"teams": connection([
                    {"id": "team-id", "key": "ENG", "name": "Engineering"},
                ])}
            if "team(id:" in query and "states(first:" in query:
                return {"team": {"states": connection([
                    {"id": "todo-id", "name": "ToDo"},
                    {"id": "blocked-id", "name": "Blocked"},
                ])}}
            if "issues(first:" in query:
                issue_queries.append((query, variables))
                self.assertIn("filter: {team:", query)
                self.assertNotIn("comments(first:", query)
                return {"issues": connection([{
                    "id": "issue-id", "identifier": "ENG-2", "title": "Queued",
                    "description": None, "updatedAt": "2026-04-02T00:00:00Z",
                    "state": {"name": "ToDo"}, "assignee": None,
                    "team": {"id": "team-id", "key": "ENG", "name": "Engineering"},
                    "project": {"id": "project-id", "name": "Delivery"},
                }])}
            if "comments(first:" in query:
                return {"issue": {"comments": connection([])}}
            if "labels(first:" in query:
                return {"issue": {"labels": connection([])}}
            if "inverseRelations(first:" in query:
                return {"issue": {"inverseRelations": connection([])}}
            self.fail("unexpected Linear query: %s" % query)

        self.linear.gql = gql
        rows = self.linear.scan(["Planned", "Blocked"])
        self.ns["normalize_task_record"](rows[0], "Linear scan fixture",
                                         feature_field=True)
        self.assertEqual("ENG-2", rows[0]["taskId"])
        self.assertEqual("team-id", issue_queries[0][1]["teamId"])
        self.assertEqual(["Blocked", "ToDo"], issue_queries[0][1]["statuses"])

    def test_export_rejects_multi_team_project_instead_of_omitting_tasks(self):
        project_id = "00000000-0000-0000-0000-000000000001"

        def gql(query, variables=None):
            variables = variables or {}
            if "teams(first:" in query:
                return {"teams": connection([
                    {"id": "team-id", "key": "ENG", "name": "Engineering"},
                ])}
            if "project(id:" in query and "issues(first:" in query:
                self.assertNotIn("filter: {team:", query)
                self.assertIn("includeArchived: true", query)
                self.assertNotIn("teamId", variables)
                return {"project": {"issues": connection([{
                    "id": "other-issue", "identifier": "OPS-1", "title": "Other team",
                    "description": None, "updatedAt": "2026-04-02T00:00:00Z",
                    "state": {"name": "ToDo"}, "assignee": None,
                    "team": {"id": "other-team", "key": "OPS", "name": "Operations"},
                }])}}
            self.fail("unexpected Linear query: %s" % query)

        self.linear.gql = gql
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.linear.export(project_id)

    def test_misspelled_team_and_failed_mutation_fail_closed(self):
        self.linear.gql = lambda query, variables=None: {"teams": connection([])}
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.linear.scan(["Planned"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.linear.mutation_payload({"issueUpdate": {"success": False}},
                                         "issueUpdate", "test mutation")

    def test_feature_state_resolution_exhausts_project_status_pages(self):
        cursors = []
        project_id = "00000000-0000-0000-0000-000000000001"

        def gql(query, variables=None):
            variables = variables or {}
            if "projectStatuses(first:" in query:
                cursors.append(variables.get("after"))
                if variables.get("after") is None:
                    return {"projectStatuses": connection(
                        [{"id": "planned", "name": "ToDo"}], True, "page-2")}
                return {"projectStatuses": connection(
                    [{"id": "completed", "name": "Live"}])}
            if "projectUpdate" in query:
                self.assertEqual("completed", variables["sid"])
                return {"projectUpdate": {"success": True,
                                           "project": {"status": {"name": "Live"}}}}
            self.fail("unexpected Linear query: %s" % query)

        self.linear.gql = gql
        self.linear.set_feature_state(
            project_id, self.ns["feature_status_by_name"]("Resolved"))
        self.assertEqual([None, "page-2"], cursors)


class JiraPaginationTest(unittest.TestCase):
    def setUp(self):
        os.environ.update({"JIRA_BASE_URL": "https://jira.example.test",
                           "JIRA_EMAIL": "bot@example.test",
                           "JIRA_API_TOKEN": "offline-test-token"})
        self.ns = load_definitions(
            "Jira", "JIRA_PROJECT_KEY=PROJ\nJIRA_TASK_ISSUE_TYPE=Story\n")
        self.jira = self.ns["Jira"]()

    @staticmethod
    def issue(key, issue_type="Story", project_key="PROJ", parent=None):
        fields = {
            "summary": "Task %s" % key, "description": "description",
            "status": {"name": "ToDo"}, "assignee": None,
            "issuelinks": [], "labels": [], "updated": "2026-05-01T00:00:00Z",
            "project": {"key": project_key}, "issuetype": {"name": issue_type},
        }
        if parent is not None:
            fields["parent"] = {"key": parent, "fields": {"summary": "Parent %s" % parent}}
        return {"key": key, "fields": fields}

    def test_export_exhausts_issue_and_comment_pages(self):
        search_payloads, comment_starts = [], []

        def api(path, payload=None, method=None):
            parsed = urlparse(path)
            query = parse_qs(parsed.query)
            start = int(query.get("startAt", [0])[0])
            if parsed.path == "/rest/api/3/project/PROJ":
                self.assertIsNone(payload)
                self.assertIsNone(method)
                return {"id": "10000", "key": "PROJ", "name": "Project"}
            if parsed.path.endswith("/search/jql"):
                self.assertEqual("POST", method)
                self.assertEqual(
                    'project = "PROJ" AND issuetype = "Story" AND parent = "EPIC-1"',
                    payload["jql"])
                self.assertEqual(100, payload["maxResults"])
                self.assertEqual(
                    ["summary", "description", "status", "assignee",
                     "issuelinks", "labels", "updated", "project", "issuetype"],
                    payload["fields"])
                search_payloads.append(dict(payload))
                if payload.get("nextPageToken") is None:
                    return {"issues": [self.issue("PROJ-1")], "isLast": False,
                            "nextPageToken": "page-2"}
                self.assertEqual("page-2", payload["nextPageToken"])
                return {"issues": [self.issue("PROJ-2")], "isLast": True}
            if parsed.path.endswith("/comment"):
                comment_starts.append(start)
                rows = ([{"id": "%s-c%d" % (parsed.path.split("/")[-2], start + 1),
                          "body": "comment %d" % (start + 1),
                          "created": "2026-05-0%dT00:00:00Z" % (start + 1),
                          "updated": ("2026-05-03T00:00:00Z" if start == 0
                                      else "2026-05-02T00:00:00Z"),
                          "author": {"accountId": "bot"}}]
                        if start < 2 else [])
                return {"comments": rows, "total": 2}
            self.fail("unexpected Jira path: %s" % path)

        self.jira.api = api
        tasks = self.jira.export("EPIC-1")
        self.ns["normalize_task_record"](tasks[0], "Jira export fixture")
        self.assertEqual([None, "page-2"],
                         [page.get("nextPageToken") for page in search_payloads])
        self.assertEqual(2, len(tasks))
        self.assertEqual(4, len(comment_starts))
        self.assertEqual(2, len(tasks[0]["comments"]))
        self.assertTrue(tasks[0]["comments"][0]["updatedAt"].endswith("02T00:00:00Z"))
        self.assertEqual(tasks[0]["comments"][0]["updatedAt"],
                         tasks[0]["comments"][0]["revision"])

    def test_scan_resolves_exact_scope_and_filters_child_issue_type(self):
        calls = []

        def api(path, payload=None, method=None):
            calls.append((path, payload, method))
            parsed = urlparse(path)
            if parsed.path == "/rest/api/3/project/PROJ":
                return {"key": "PROJ"}
            if parsed.path.endswith("/search/jql"):
                self.assertEqual(
                    'project = "PROJ" AND issuetype = "Story" AND status in ("ToDo","Blocked")',
                    payload["jql"])
                self.assertEqual(
                    ["summary", "description", "status", "assignee", "issuelinks",
                     "parent", "labels", "updated", "project", "issuetype"],
                    payload["fields"])
                return {"issues": [self.issue("PROJ-1", parent="PROJ-EPIC")],
                        "isLast": True}
            if parsed.path.endswith("/comment"):
                return {"comments": [], "total": 0}
            self.fail("unexpected Jira path: %s" % path)

        self.jira.api = api
        items = self.jira.scan(["Planned", "Blocked"])
        self.assertEqual("PROJ-1", items[0]["taskId"])
        self.assertEqual("PROJ-EPIC", items[0]["featureId"])
        self.assertEqual("/rest/api/3/project/PROJ", calls[0][0])

    def test_scan_rejects_epic_even_if_search_returns_it(self):
        def api(path, payload=None, method=None):
            parsed = urlparse(path)
            if parsed.path == "/rest/api/3/project/PROJ":
                return {"key": "PROJ"}
            if parsed.path.endswith("/search/jql"):
                self.assertIn('issuetype = "Story"', payload["jql"])
                return {"issues": [self.issue("PROJ-EPIC", issue_type="Epic")],
                        "isLast": True}
            self.fail("Epic must be rejected before comments are fetched")

        self.jira.api = api
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.jira.scan(["Planned"])

    def test_scan_rejects_project_alias_and_cross_project_results(self):
        self.jira.api = lambda *_args, **_kwargs: {"key": "proj"}
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.jira.scan(["Planned"])

        def cross_project(path, payload=None, method=None):
            parsed = urlparse(path)
            if parsed.path == "/rest/api/3/project/PROJ":
                return {"key": "PROJ"}
            if parsed.path.endswith("/search/jql"):
                return {"issues": [self.issue("OTHER-1", project_key="OTHER")],
                        "isLast": True}
            self.fail("cross-project issue must be rejected before comments are fetched")

        self.jira.api = cross_project
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.jira.scan(["Planned"])

    def test_scan_requires_explicit_child_issue_type(self):
        namespace = load_definitions("Jira", "JIRA_PROJECT_KEY=PROJ\n")
        jira = namespace["Jira"]()
        jira.api = lambda *_args, **_kwargs: self.fail(
            "missing JIRA_TASK_ISSUE_TYPE must fail before network access")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            jira.scan(["Planned"])

    def test_epic_cannot_be_configured_as_child_issue_type(self):
        namespace = load_definitions(
            "Jira", "JIRA_PROJECT_KEY=PROJ\nJIRA_TASK_ISSUE_TYPE=Epic\n")
        jira = namespace["Jira"]()
        jira.api = lambda *_args, **_kwargs: self.fail(
            "Epic configuration must fail before network access")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            jira.scan(["Planned"])

    def test_enhanced_search_rejects_stalled_or_repeated_tokens(self):
        self.jira.api = lambda *_args, **_kwargs: {
            "issues": [self.issue("PROJ-1")], "isLast": False,
            "nextPageToken": "same-token",
        }
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.jira.search_all("project=PROJ", "summary,status")


class GitHubPaginationTest(unittest.TestCase):
    @staticmethod
    def issue(number, status="status:todo", milestone=None, state="open"):
        return {
            "number": number,
            "title": "Issue %d" % number,
            "body": "body %d" % number,
            "state": state,
            "labels": [{"name": status}],
            "assignees": [{"login": "owner%d" % number}],
            "milestone": milestone,
            "updated_at": "2026-07-%02dT12:00:00Z" % number,
        }

    @staticmethod
    def comment(comment_id, created_at, body="note", updated_at=None):
        return {"id": comment_id, "body": body, "created_at": created_at,
                "updated_at": updated_at or created_at,
                "user": {"login": "octobot"}}

    def setUp(self):
        self.ns = load_definitions("GitHubIssues", "GITHUB_REPO=owner/repo\n")
        self.github = self.ns["GitHubIssues"]()

    def endpoint(self, args):
        self.assertEqual(("api", "--paginate", "--slurp"), args[:3])
        return urlparse(args[3])

    def test_export_exhausts_milestones_issues_and_comments_in_chronology(self):
        target = {"number": 42, "title": "delivery", "state": "open",
                  "description": "feature"}
        calls = []

        def raw_gh(*args, **_kwargs):
            calls.append(args)
            endpoint = self.endpoint(args)
            query = parse_qs(endpoint.query)
            if endpoint.path == "repos/owner/repo/milestones":
                self.assertEqual({"state": ["all"], "per_page": ["100"]}, query)
                return json.dumps([
                    [{"number": 1, "title": "other", "state": "closed"}],
                    [target],
                ])
            if endpoint.path == "repos/owner/repo/issues":
                self.assertEqual(["42"], query.get("milestone"))
                self.assertEqual(["all"], query.get("state"))
                self.assertEqual(["100"], query.get("per_page"))
                return json.dumps([
                    [self.issue(1, milestone=target),
                     {"number": 99, "pull_request": {"url": "pull/99"}}],
                    [self.issue(2, status="status:ready-for-production",
                                milestone=target, state="closed")],
                ])
            if endpoint.path == "repos/owner/repo/issues/1/comments":
                return json.dumps([
                    [self.comment(102, "2026-07-03T00:00:00Z", "later")],
                    [self.comment(101, "2026-07-01T00:00:00Z", "edited later",
                                  updated_at="2026-07-04T00:00:00Z")],
                ])
            if endpoint.path == "repos/owner/repo/issues/2/comments":
                return json.dumps([[]])
            if endpoint.path == "repos/owner/repo/issues/1/dependencies/blocked_by":
                self.assertEqual(["100"], parse_qs(endpoint.query).get("per_page"))
                return json.dumps([[{"number": 8}], [{"number": 9}]])
            if endpoint.path == "repos/owner/repo/issues/2/dependencies/blocked_by":
                return json.dumps([[]])
            self.fail("unexpected GitHub endpoint: %s" % endpoint.geturl())

        self.github.raw_gh = raw_gh
        tasks = self.github.export("delivery")
        self.ns["normalize_task_record"](tasks[0], "GitHub export fixture")

        self.assertEqual([1, 2], [task["taskId"] for task in tasks])
        self.assertEqual([102, 101],
                         [comment["id"] for comment in tasks[0]["comments"]])
        self.assertEqual("Planned", tasks[0]["status"])
        self.assertEqual("Ready to deploy", tasks[1]["status"])
        self.assertEqual("2026-07-03T00:00:00Z",
                         tasks[0]["comments"][0]["createdAt"])
        self.assertEqual("2026-07-04T00:00:00Z",
                         tasks[0]["comments"][-1]["updatedAt"])
        self.assertEqual(tasks[0]["comments"][-1]["updatedAt"],
                         tasks[0]["comments"][-1]["revision"])
        self.assertEqual(["8", "9"], tasks[0]["blockedBy"])
        self.assertEqual([], tasks[1]["blockedBy"])
        self.assertEqual(6, len(calls))

    def test_scan_exhausts_repository_issues_and_excludes_pull_requests(self):
        milestone = {"number": 7, "title": "portfolio", "state": "open"}

        def raw_gh(*args, **_kwargs):
            endpoint = self.endpoint(args)
            if endpoint.path == "repos/owner/repo/issues":
                self.assertNotIn("milestone", parse_qs(endpoint.query))
                return json.dumps([
                    [{"number": 88, "pull_request": {"url": "pull/88"}},
                     self.issue(3, status="status:blocked", milestone=milestone)],
                    [self.issue(4, status="status:todo", milestone=milestone)],
                ])
            if endpoint.path == "repos/owner/repo/issues/3/comments":
                return json.dumps([
                    [self.comment(302, "2026-07-04T00:00:00Z", "second")],
                    [self.comment(301, "2026-07-02T00:00:00Z", "first")],
                ])
            if endpoint.path == "repos/owner/repo/issues/3/dependencies/blocked_by":
                return json.dumps([[{"number": 2}]])
            self.fail("unexpected GitHub endpoint: %s" % endpoint.geturl())

        self.github.raw_gh = raw_gh
        items = self.github.scan(["Blocked"])
        self.ns["normalize_task_record"](items[0], "GitHub scan fixture",
                                         feature_field=True)

        self.assertEqual([3], [item["taskId"] for item in items])
        self.assertEqual(7, items[0]["featureId"])
        self.assertEqual([301, 302],
                         [comment["id"] for comment in items[0]["comments"]])
        self.assertEqual(["2"], items[0]["blockedBy"])

    def test_progress_upsert_finds_marker_on_later_page(self):
        calls = []

        def raw_gh(*args, **_kwargs):
            endpoint = self.endpoint(args)
            self.assertEqual("repos/owner/repo/issues/9/comments", endpoint.path)
            return json.dumps([
                [self.comment(901, "2026-07-01T00:00:00Z", "human note")],
                [self.comment(902, "2026-07-02T00:00:00Z", "[progress]\nold")],
            ])

        self.github.raw_gh = raw_gh
        self.github.update_comment = lambda task, comment, body: calls.append(
            (task, comment, body))
        self.github.comment = lambda *_args, **_kwargs: self.fail(
            "upsert created a duplicate progress comment")

        self.assertEqual("902", self.github.upsert_progress(9, "[progress]\nnew"))
        self.assertEqual([(9, "902", "[progress]\nnew")], calls)

    def test_malformed_paginated_page_fails_closed(self):
        self.github.raw_gh = lambda *_args, **_kwargs: json.dumps(
            [{"not": "a page array"}])

        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit):
                self.github.repository_issues()
        self.assertIn("malformed page 1", stderr.getvalue())

    def test_unavailable_dependency_endpoint_fails_closed(self):
        def unavailable(*_args, **_kwargs):
            raise SystemExit(1)

        self.github.raw_gh = unavailable
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit):
                self.github.issue_blocked_by(7)
        self.assertIn("unavailable, unsupported, unauthorized, or incomplete",
                      stderr.getvalue())


class NormalizationContractTest(unittest.TestCase):
    def setUp(self):
        self.ns = load_definitions("Markdown")

    @staticmethod
    def record():
        return {
            "taskId": "feature.md#1", "title": "Task", "status": "Planned",
            "statusRaw": "[Planned]", "assignee": None, "description": None,
            "comments": [
                {"id": "c1", "body": "first", "createdAt": None,
                 "updatedAt": None, "revision": "markdown-offset:1",
                 "author": None},
                {"id": "c2", "body": "second", "createdAt": None,
                 "updatedAt": None, "revision": "markdown-offset:2",
                 "author": None},
            ],
            "blockedBy": [], "labels": [],
            "updatedAt": "2026-07-14T00:00:00+00:00", "revision": "3",
        }

    def refuses(self, record):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.ns["normalize_task_record"](record, "fixture")

    def test_normalization_accepts_documented_markdown_null_timestamps(self):
        normalized = self.ns["normalize_task_record"](self.record(), "fixture")
        self.assertEqual(["c1", "c2"],
                         [comment["id"] for comment in normalized["comments"]])

    def test_normalization_rejects_unknown_status_and_missing_shape(self):
        unknown = self.record()
        unknown["status"] = None
        self.refuses(unknown)
        missing = self.record()
        del missing["blockedBy"]
        self.refuses(missing)

    def test_normalization_rejects_duplicate_ids_and_nonchronological_comments(self):
        duplicate = self.record()
        duplicate["comments"][1]["id"] = "c1"
        self.refuses(duplicate)
        missing_id = self.record()
        del missing_id["comments"][0]["id"]
        self.refuses(missing_id)
        reversed_comments = self.record()
        reversed_comments["comments"].reverse()
        self.refuses(reversed_comments)


if __name__ == "__main__":
    unittest.main()
