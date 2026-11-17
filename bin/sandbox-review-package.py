#!/usr/bin/env python3
"""Create an exact accepted-commit review package without a host checkout."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "bin")]
from delivery_profile import _atomic_write, _git, _repository_root, _resolve_commit, build_review_package
from sandbox_acceptance import task_key, verify_configured_execution
from sandbox_execution_data import read_execution


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--team", required=True)
    parser.add_argument("--task", required=True)
    args = parser.parse_args(argv)
    record = read_execution(args.workspace, args.task)
    receipt = verify_configured_execution(record, args.repo, args.workspace, args.team,
        record["featureId"], args.task, ROOT)
    if receipt is None:
        raise ValueError("raw sandbox review packaging requires a protected sandbox import")
    repo = _repository_root(args.repo)
    head = receipt["sandbox"]["acceptedCommit"]
    base_tip = _resolve_commit(repo, "refs/heads/" + args.team)
    base = _git(repo, "merge-base", base_tip, head).decode("ascii").strip()
    package, base, head = build_review_package(repo, args.task, base, head)
    directory = args.workspace / "artifacts" / task_key(args.task)
    leaf = "review-" + base + ".." + head
    path = _atomic_write(directory, leaf + ".diff", package)
    bindings = {"schemaVersion": 1, "reviewBaseCommit": base, "taskBranchHead": head,
                "reviewPackagePath": str(path), "reviewPackageSha256": "sha256:" + hashlib.sha256(package).hexdigest()}
    _atomic_write(directory, leaf + ".bindings.json", (json.dumps(bindings, sort_keys=True) + "\n").encode())
    print(path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("sandbox-review-package: accepted task import could not be verified", file=sys.stderr)
        raise SystemExit(1)
