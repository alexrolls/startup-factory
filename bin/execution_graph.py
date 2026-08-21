#!/usr/bin/env python3
"""Backend-neutral validation and queries for normalized [task] graphs.

The graph is deliberately pure: callers provide the complete snapshot and the
configured status sets.  Adapter-specific relation names, I/O, claims, and the
human Blocked-clearance overlay remain outside this module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Mapping


SNAPSHOT_SCHEMA_VERSION = 2
EDGE_KIND_READINESS = {
    "requires": True,
    "parent": False,
    "related": False,
    "derived-from": False,
}
_MISSING = object()


class ExecutionGraphError(ValueError):
    """Raised when a snapshot or graph query cannot be interpreted safely."""


@dataclass(frozen=True, order=True)
class DependencyEdge:
    """A dependent/source [task] pointing to a dependency/target [task]."""

    source_task_id: str
    target_task_id: str
    kind: str
    affects_readiness: bool

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.source_task_id, self.target_task_id, self.kind)

    def canonical_tuple(self) -> list[object]:
        return [
            self.source_task_id,
            self.target_task_id,
            self.kind,
            self.affects_readiness,
        ]


@dataclass(frozen=True)
class GraphValidation:
    """Immutable canonical view produced only after complete validation."""

    snapshot_schema_version: int
    snapshot_complete: bool
    nodes: tuple[tuple[str, str], ...]
    edges: tuple[DependencyEdge, ...]
    digest: str

    @property
    def canonical_payload(self) -> dict[str, object]:
        return {
            "snapshotSchemaVersion": self.snapshot_schema_version,
            "snapshotComplete": self.snapshot_complete,
            "nodes": [list(node) for node in self.nodes],
            "edges": [edge.canonical_tuple() for edge in self.edges],
        }


def _strict_status_set(values: Iterable[str], label: str) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ExecutionGraphError(f"{label} must be a non-empty set of status names")
    try:
        items = list(values)
    except TypeError as exc:
        raise ExecutionGraphError(f"{label} must be a non-empty set of status names") from exc
    if not items:
        raise ExecutionGraphError(f"{label} must be a non-empty set of status names")
    if any(not isinstance(item, str) or not item or item != item.strip() for item in items):
        raise ExecutionGraphError(f"{label} contains a malformed status name")
    return frozenset(items)


def _identity(value: object, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ExecutionGraphError(f"{label} must be a string or integer identity")
    result = str(value)
    if not result or result != result.strip():
        raise ExecutionGraphError(f"{label} must be a non-empty canonical identity")
    return result


def _identity_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ExecutionGraphError(f"{label} must be a list")
    result: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(value, start=1):
        item = _identity(raw, f"{label} entry {index}")
        if item in seen:
            raise ExecutionGraphError(f"{label} contains duplicate identity '{item}'")
        seen.add(item)
        result.append(item)
    return tuple(result)


def _dependency_edges(
    source: str,
    blocked_by: tuple[str, ...],
    raw_dependencies: object,
) -> tuple[DependencyEdge, ...]:
    if raw_dependencies is _MISSING:
        return tuple(
            DependencyEdge(source, target, "requires", True)
            for target in blocked_by
        )
    if not isinstance(raw_dependencies, list):
        raise ExecutionGraphError(f"task '{source}' dependencies must be a list")
    edges: list[DependencyEdge] = []
    identities: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_dependencies, start=1):
        label = f"task '{source}' dependency {index}"
        if not isinstance(raw, dict):
            raise ExecutionGraphError(f"{label} must be an object")
        expected_fields = {"targetTaskId", "kind", "affectsReadiness"}
        if set(raw) != expected_fields:
            missing = sorted(expected_fields - set(raw))
            extra = sorted(set(raw) - expected_fields)
            detail = []
            if missing:
                detail.append("missing " + ", ".join(missing))
            if extra:
                detail.append("unexpected " + ", ".join(extra))
            raise ExecutionGraphError(f"{label} fields are malformed ({'; '.join(detail)})")
        target = _identity(raw["targetTaskId"], f"{label} targetTaskId")
        kind = raw["kind"]
        if not isinstance(kind, str) or kind not in EDGE_KIND_READINESS:
            raise ExecutionGraphError(f"{label} has unknown kind")
        affects = raw["affectsReadiness"]
        if type(affects) is not bool or affects is not EDGE_KIND_READINESS[kind]:
            raise ExecutionGraphError(
                f"{label} affectsReadiness does not match kind '{kind}'"
            )
        edge = DependencyEdge(source, target, kind, affects)
        if edge.identity in identities:
            raise ExecutionGraphError(
                "task '%s' contains duplicate dependency edge (%s,%s,%s)"
                % (source, source, target, kind)
            )
        identities.add(edge.identity)
        edges.append(edge)
    requires = {edge.target_task_id for edge in edges if edge.affects_readiness}
    if requires != set(blocked_by):
        raise ExecutionGraphError(
            f"task '{source}' readiness dependency set does not match blockedBy"
        )
    return tuple(edges)


def _assert_acyclic_requires(
    node_ids: set[str], edges: tuple[DependencyEdge, ...]
) -> None:
    adjacency: dict[str, list[str]] = {task_id: [] for task_id in node_ids}
    indegree = {task_id: 0 for task_id in node_ids}
    for edge in edges:
        if not edge.affects_readiness:
            continue
        adjacency[edge.source_task_id].append(edge.target_task_id)
        indegree[edge.target_task_id] += 1
    ready = sorted(task_id for task_id, degree in indegree.items() if degree == 0)
    visited = 0
    position = 0
    while position < len(ready):
        current = ready[position]
        position += 1
        visited += 1
        for target in sorted(adjacency[current]):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if visited != len(node_ids):
        raise ExecutionGraphError("readiness dependency graph contains a cycle")


def _digest_payload(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


class ExecutionGraph:
    """Validated execution graph for exactly one exhaustive snapshot."""

    def __init__(
        self,
        validation: GraphValidation,
        allowed_statuses: frozenset[str],
        terminal_statuses: frozenset[str],
    ) -> None:
        self.validation = validation
        self._statuses = dict(validation.nodes)
        self._allowed_statuses = allowed_statuses
        self._terminal_statuses = terminal_statuses
        blockers: dict[str, list[str]] = {task_id: [] for task_id in self._statuses}
        for edge in validation.edges:
            if edge.affects_readiness:
                blockers[edge.source_task_id].append(edge.target_task_id)
        self._blockers = {
            task_id: tuple(sorted(targets)) for task_id, targets in blockers.items()
        }

    @classmethod
    def from_snapshot(
        cls,
        snapshot: object,
        allowed_statuses: Iterable[str],
        terminal_statuses: Iterable[str],
    ) -> "ExecutionGraph":
        allowed = _strict_status_set(allowed_statuses, "allowed statuses")
        terminal = _strict_status_set(terminal_statuses, "terminal statuses")
        if not terminal.issubset(allowed):
            raise ExecutionGraphError("terminal statuses must be a subset of allowed statuses")
        if not isinstance(snapshot, dict):
            raise ExecutionGraphError("snapshot must be an object")
        version = snapshot.get("snapshotSchemaVersion")
        if type(version) is not int or version != SNAPSHOT_SCHEMA_VERSION:
            raise ExecutionGraphError(
                f"snapshotSchemaVersion must be integer {SNAPSHOT_SCHEMA_VERSION}"
            )
        complete = snapshot.get("snapshotComplete")
        if complete is not True or type(complete) is not bool:
            raise ExecutionGraphError("snapshotComplete must be literal true")
        tasks = snapshot.get("tasks")
        if not isinstance(tasks, list):
            raise ExecutionGraphError("snapshot tasks must be a list")

        nodes: list[tuple[str, str]] = []
        edges: list[DependencyEdge] = []
        node_ids: set[str] = set()
        for index, raw in enumerate(tasks, start=1):
            if not isinstance(raw, dict):
                raise ExecutionGraphError(f"snapshot task {index} must be an object")
            if "taskId" not in raw:
                raise ExecutionGraphError(f"snapshot task {index} omits taskId")
            task_id = _identity(raw["taskId"], f"snapshot task {index} taskId")
            if task_id in node_ids:
                raise ExecutionGraphError(f"snapshot contains duplicate taskId '{task_id}'")
            node_ids.add(task_id)
            status = raw.get("status")
            if not isinstance(status, str) or status not in allowed:
                raise ExecutionGraphError(f"task '{task_id}' has unknown status")
            if "blockedBy" not in raw:
                raise ExecutionGraphError(f"task '{task_id}' omits blockedBy")
            blocked_by = _identity_list(raw["blockedBy"], f"task '{task_id}' blockedBy")
            task_edges = _dependency_edges(
                task_id, blocked_by, raw.get("dependencies", _MISSING)
            )
            nodes.append((task_id, status))
            edges.extend(task_edges)

        for edge in edges:
            if edge.target_task_id not in node_ids:
                raise ExecutionGraphError(
                    f"task '{edge.source_task_id}' dependency has unknown target '{edge.target_task_id}'"
                )
            if edge.source_task_id == edge.target_task_id:
                raise ExecutionGraphError(
                    f"task '{edge.source_task_id}' dependency contains a self-edge"
                )
        ordered_nodes = tuple(sorted(nodes))
        ordered_edges = tuple(sorted(edges))
        _assert_acyclic_requires(node_ids, ordered_edges)
        canonical_payload = {
            "snapshotSchemaVersion": SNAPSHOT_SCHEMA_VERSION,
            "snapshotComplete": True,
            "nodes": [list(node) for node in ordered_nodes],
            "edges": [edge.canonical_tuple() for edge in ordered_edges],
        }
        validation = GraphValidation(
            snapshot_schema_version=SNAPSHOT_SCHEMA_VERSION,
            snapshot_complete=True,
            nodes=ordered_nodes,
            edges=ordered_edges,
            digest=_digest_payload(canonical_payload),
        )
        return cls(validation, allowed, terminal)

    def blocker_task_ids(self, task_id: str) -> tuple[str, ...]:
        if task_id not in self._blockers:
            raise ExecutionGraphError(f"unknown taskId '{task_id}'")
        return self._blockers[task_id]

    def task_status(self, task_id: str) -> str:
        if task_id not in self._statuses:
            raise ExecutionGraphError(f"unknown taskId '{task_id}'")
        return self._statuses[task_id]

    def blockers_are_terminal(self, task_id: str) -> bool:
        return all(
            self.task_status(blocker) in self._terminal_statuses
            for blocker in self.blocker_task_ids(task_id)
        )


def ready_task_ids(
    graph: ExecutionGraph, candidate_statuses: Iterable[str]
) -> tuple[str, ...]:
    candidates = _strict_status_set(candidate_statuses, "candidate statuses")
    if not candidates.issubset(graph._allowed_statuses):
        raise ExecutionGraphError("candidate statuses must be a subset of allowed statuses")
    return tuple(
        task_id
        for task_id, status in graph.validation.nodes
        if status in candidates and graph.blockers_are_terminal(task_id)
    )


def graph_digest(graph: ExecutionGraph | GraphValidation) -> str:
    validation = graph.validation if isinstance(graph, ExecutionGraph) else graph
    if not isinstance(validation, GraphValidation):
        raise ExecutionGraphError("graph_digest requires an ExecutionGraph or GraphValidation")
    return validation.digest
