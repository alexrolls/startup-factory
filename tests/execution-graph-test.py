#!/usr/bin/env python3
"""Offline contract tests for the backend-neutral execution graph."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "startup_factory_execution_graph", ROOT / "bin" / "execution_graph.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load execution graph module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

DependencyEdge = MODULE.DependencyEdge
ExecutionGraph = MODULE.ExecutionGraph
ExecutionGraphError = MODULE.ExecutionGraphError
GraphValidation = MODULE.GraphValidation
graph_digest = MODULE.graph_digest
ready_task_ids = MODULE.ready_task_ids


ALLOWED = {"Queued", "Working", "Blocked", "Done"}
TERMINAL = {"Done"}


def task(task_id: str, status: str = "Queued", blocked_by=None, dependencies=None):
    value = {
        "taskId": task_id,
        "status": status,
        "blockedBy": list(blocked_by or []),
    }
    if dependencies is not None:
        value["dependencies"] = dependencies
    return value


def dependency(target: str, kind: str = "requires", affects=True):
    return {
        "targetTaskId": target,
        "kind": kind,
        "affectsReadiness": affects,
    }


def snapshot(tasks):
    return {
        "snapshotSchemaVersion": 2,
        "snapshotComplete": True,
        "tasks": tasks,
    }


class ExecutionGraphTests(unittest.TestCase):
    def graph(self, value):
        return ExecutionGraph.from_snapshot(value, ALLOWED, TERMINAL)

    def assert_invalid(self, value, message):
        with self.assertRaisesRegex(ExecutionGraphError, message):
            self.graph(value)

    def test_legacy_blocked_by_derives_requires_edges_and_readiness(self):
        graph = self.graph(snapshot([
            task("build", "Done"),
            task("test", blocked_by=["build"]),
            task("ship", blocked_by=["test"]),
        ]))
        self.assertEqual(graph.blocker_task_ids("test"), ("build",))
        self.assertEqual(graph.blocker_task_ids("ship"), ("test",))
        self.assertEqual(ready_task_ids(graph, {"Queued"}), ("test",))
        self.assertIsInstance(graph.validation, GraphValidation)
        self.assertEqual(
            graph.validation.edges[0],
            DependencyEdge("ship", "test", "requires", True),
        )

    def test_non_blocking_kinds_are_preserved_without_affecting_readiness(self):
        graph = self.graph(snapshot([
            task("a", dependencies=[
                dependency("b", "parent", False),
                dependency("b", "related", False),
                dependency("b", "derived-from", False),
            ]),
            task("b", "Working"),
        ]))
        self.assertEqual(graph.blocker_task_ids("a"), ())
        self.assertEqual(ready_task_ids(graph, {"Queued"}), ("a",))
        self.assertEqual(len(graph.validation.edges), 3)

    def test_distinct_kinds_on_the_same_pair_are_distinct(self):
        graph = self.graph(snapshot([
            task("a", blocked_by=["b"], dependencies=[
                dependency("b"),
                dependency("b", "related", False),
            ]),
            task("b", "Done"),
        ]))
        self.assertEqual(len(graph.validation.edges), 2)

    def test_custom_status_profile_is_supplied_by_the_caller(self):
        graph = ExecutionGraph.from_snapshot(
            snapshot([task("a", "Complete"), task("b", "Waiting", ["a"])]),
            {"Waiting", "Complete"},
            {"Complete"},
        )
        self.assertEqual(ready_task_ids(graph, {"Waiting"}), ("b",))

    def test_digest_is_order_independent_and_uses_full_edge_tuple(self):
        first = snapshot([
            task("a", blocked_by=["b"], dependencies=[
                dependency("b", "related", False),
                dependency("b"),
            ]),
            task("b", "Done"),
        ])
        second = snapshot(list(reversed(copy.deepcopy(first["tasks"]))))
        second["tasks"][1]["dependencies"].reverse()
        graph_a = self.graph(first)
        graph_b = self.graph(second)
        self.assertEqual(graph_digest(graph_a), graph_digest(graph_b))

        changed_status = copy.deepcopy(first)
        changed_status["tasks"][1]["status"] = "Working"
        self.assertNotEqual(graph_digest(graph_a), graph_digest(self.graph(changed_status)))

        changed_edge = copy.deepcopy(first)
        changed_edge["tasks"][0]["dependencies"][0]["kind"] = "parent"
        self.assertNotEqual(graph_digest(graph_a), graph_digest(self.graph(changed_edge)))

        canonical = graph_a.validation.canonical_payload
        self.assertEqual(canonical["snapshotSchemaVersion"], 2)
        self.assertIs(canonical["snapshotComplete"], True)
        self.assertEqual(
            canonical["edges"][0],
            ["a", "b", "related", False],
        )
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def test_schema_and_completeness_fail_closed(self):
        base = snapshot([task("a")])
        for field in ("snapshotSchemaVersion", "snapshotComplete"):
            value = copy.deepcopy(base)
            del value[field]
            self.assert_invalid(value, field)
        for bad in (1, 3, True, "2"):
            value = copy.deepcopy(base)
            value["snapshotSchemaVersion"] = bad
            self.assert_invalid(value, "snapshotSchemaVersion")
        for bad in (False, 1, "true", None):
            value = copy.deepcopy(base)
            value["snapshotComplete"] = bad
            self.assert_invalid(value, "snapshotComplete")

    def test_root_task_and_identity_shapes_fail_closed(self):
        with self.assertRaisesRegex(ExecutionGraphError, "snapshot must be an object"):
            ExecutionGraph.from_snapshot([], ALLOWED, TERMINAL)
        self.assert_invalid({"snapshotSchemaVersion": 2, "snapshotComplete": True}, "tasks")
        self.assert_invalid(snapshot({}), "tasks")
        self.assert_invalid(snapshot(["bad"]), "task 1")
        for bad in (None, True, "", " spaced "):
            value = snapshot([task("a")])
            value["tasks"][0]["taskId"] = bad
            self.assert_invalid(value, "taskId")

    def test_duplicate_nodes_and_unknown_status_fail_closed(self):
        self.assert_invalid(snapshot([task("a"), task("a")]), "duplicate taskId")
        self.assert_invalid(snapshot([task("a", "Mystery")]), "unknown status")

    def test_allowed_and_terminal_status_contract_is_strict(self):
        with self.assertRaisesRegex(ExecutionGraphError, "allowed statuses"):
            ExecutionGraph.from_snapshot(snapshot([task("a")]), [], TERMINAL)
        with self.assertRaisesRegex(ExecutionGraphError, "terminal statuses"):
            ExecutionGraph.from_snapshot(snapshot([task("a")]), ALLOWED, {"Mystery"})

    def test_blocked_by_and_dependencies_shapes_fail_closed(self):
        value = snapshot([task("a")])
        value["tasks"][0]["blockedBy"] = "b"
        self.assert_invalid(value, "blockedBy")
        self.assert_invalid(snapshot([task("a", blocked_by=["b", "b"]), task("b")]), "duplicate")
        value = snapshot([task("a")])
        value["tasks"][0]["dependencies"] = {}
        self.assert_invalid(value, "dependencies")
        value["tasks"][0]["dependencies"] = None
        self.assert_invalid(value, "dependencies")
        value = snapshot([task("a", dependencies=["bad"])])
        self.assert_invalid(value, "dependency 1")

    def test_unknown_kind_and_readiness_mismatches_fail_closed(self):
        self.assert_invalid(
            snapshot([task("a", dependencies=[dependency("b", "blocks", True)]), task("b")]),
            "unknown kind",
        )
        for kind, readiness in (("requires", False), ("related", True), ("parent", 0)):
            value = snapshot([
                task("a", blocked_by=["b"] if kind == "requires" else [],
                     dependencies=[dependency("b", kind, readiness)]),
                task("b"),
            ])
            self.assert_invalid(value, "affectsReadiness")

    def test_duplicate_edges_fail_but_blocker_equivalence_is_set_based(self):
        duplicate = snapshot([
            task("a", blocked_by=["b"], dependencies=[dependency("b"), dependency("b")]),
            task("b"),
        ])
        self.assert_invalid(duplicate, "duplicate dependency edge")
        conflict = snapshot([
            task("a", blocked_by=["b"], dependencies=[dependency("c")]),
            task("b"), task("c"),
        ])
        self.assert_invalid(conflict, "does not match blockedBy")

    def test_missing_targets_self_edges_and_requires_cycles_fail_closed(self):
        self.assert_invalid(snapshot([task("a", blocked_by=["missing"])]), "unknown target")
        self.assert_invalid(snapshot([task("a", blocked_by=["a"])]), "self-edge")
        self.assert_invalid(
            snapshot([task("a", blocked_by=["b"]), task("b", blocked_by=["a"])]),
            "cycle",
        )

    def test_unknown_task_queries_and_candidate_statuses_fail_closed(self):
        graph = self.graph(snapshot([task("a")]))
        with self.assertRaisesRegex(ExecutionGraphError, "unknown taskId"):
            graph.blocker_task_ids("missing")
        with self.assertRaisesRegex(ExecutionGraphError, "candidate statuses"):
            ready_task_ids(graph, {"Mystery"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
