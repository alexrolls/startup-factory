#!/usr/bin/env python3
"""Check protected Docker task imports before review publication/integration."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "bin")]
from startup_factory_cli.sandbox_deployment import decode_object
from startup_factory_cli.config_values import read_config_file, value_for
from sandbox_acceptance import ImportPending, task_key, verify_configured_execution
from sandbox_execution_data import regular_data
from sandbox_completion import CompletionPending, verify_gate_completion

CODE_MARKERS = {"review-request", "review-approval", "team-lead-approval", "architecture-approval",
                "sceptical-architecture-approval", "security-approval"}
POSITIVE_GATE_MARKERS = (CODE_MARKERS - {"review-request"}) | {
    "design-approved", "sceptical-design-approved", "resume-review", "resume-plan", "product-approval"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--team", required=True)
    parser.add_argument("--feature", required=True)
    parser.add_argument("--task")
    parser.add_argument("--publication-entry", type=Path)
    args = parser.parse_args(argv)
    try:
        pending = False
        task = args.task
        if args.publication_entry is not None:
            path = args.publication_entry
            entry = decode_object(regular_data(path, 1024 * 1024), maximum=1024 * 1024)
            if entry.get("marker") not in CODE_MARKERS | POSITIVE_GATE_MARKERS:
                return 0
            task = entry.get("taskId")
            pending = True
        if not isinstance(task, str) or not task or len(task) > 1024:
            raise ValueError("invalid task")
        config = read_config_file(ROOT / "config/team.config.md", label="team config")
        backend = value_for(config, "AGENT_EXECUTION_BACKEND") or "protected-runner"
        if backend not in {"protected-runner", "docker-sandboxes"}:
            raise ValueError("unsupported configured backend")
        if args.publication_entry is not None and entry.get("marker") in POSITIVE_GATE_MARKERS and backend == "docker-sandboxes":
            deployment = value_for(config, "AGENT_SANDBOX_DEPLOYMENT")
            if not deployment or value_for(config, "AGENT_SANDBOX_ENFORCED") != "true":
                raise ValueError("Docker approval has no enforced protected deployment")
            completion = verify_gate_completion(Path(deployment), args.repo, args.workspace,
                args.team, args.feature, task, entry, require_review_binding=entry["marker"] in CODE_MARKERS)
        if args.publication_entry is not None and entry.get("marker") not in CODE_MARKERS:
            return 0  # Design/resume/product gates need no implementation record.
        record_path = args.workspace / "executions" / (task_key(task) + ".json")
        try:
            record = decode_object(regular_data(record_path, 1024 * 1024), maximum=1024 * 1024)
        except FileNotFoundError:
            if backend != "docker-sandboxes":
                return 0  # Preserve the existing native gate/publication rules.
            raise ImportPending("sandbox task assignment is pending")
        verify_configured_execution(record, args.repo, args.workspace, args.team, args.feature,
                                    task, ROOT, allow_pending=pending)
        if args.publication_entry is not None and entry.get("marker") != "review-request" and backend == "docker-sandboxes":
            if completion["binding"]["reviewBinding"]["head"] != record["sandbox"]["acceptedCommit"] or completion["binding"]["scope"]["attempt"] != record.get("attempt"):
                raise ValueError("completed review does not name the current accepted source")
        return 0
    except (ImportPending, CompletionPending):
        print("sandbox-execution: waiting for protected sandbox source import or gate completion", file=sys.stderr)
        return 75
    except Exception:
        print("sandbox-execution: protected task import verification failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
