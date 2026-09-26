#!/usr/bin/env python3
"""Fail closed unless a GitHub release environment has independent reviewers.

The workflow pipes the response from GitHub's environment API to this helper.
It never accepts repository-controlled configuration as a substitute for the
live protection rules.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


MAX_RESPONSE_BYTES = 1_000_000
ENVIRONMENT_NAMES = ("release", "pypi")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate_environment(payload: object, expected_name: str) -> None:
    """Require a live, named environment with non-self approval authority."""
    if expected_name not in ENVIRONMENT_NAMES:
        raise ValueError("unsupported release environment")
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("name"), str)
        or payload["name"].casefold() != expected_name
    ):
        raise ValueError("release environment identity mismatch")
    if payload.get("can_admins_bypass") is not False:
        raise ValueError("release environment must disable administrator bypass")
    rules = payload.get("protection_rules")
    if not isinstance(rules, list):
        raise ValueError("release environment has no protection rules")
    reviewer_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        raise ValueError("release environment requires one reviewer rule")
    rule = reviewer_rules[0]
    if rule.get("prevent_self_review") is not True:
        raise ValueError("release environment must prevent self-review")
    reviewers = rule.get("reviewers")
    if not isinstance(reviewers, list) or not 1 <= len(reviewers) <= 6:
        raise ValueError("release environment needs human reviewers")
    for entry in reviewers:
        if not isinstance(entry, dict) or entry.get("type") not in ("User", "Team"):
            raise ValueError("release environment has an invalid reviewer")
        reviewer = entry.get("reviewer")
        if not isinstance(reviewer, dict):
            raise ValueError("release environment has an invalid reviewer")
        reviewer_id = reviewer.get("id")
        if type(reviewer_id) is not int or reviewer_id <= 0:
            raise ValueError("release environment has an invalid reviewer")
        identity_key = "login" if entry["type"] == "User" else "slug"
        identity = reviewer.get(identity_key)
        if not isinstance(identity, str) or not identity.strip():
            raise ValueError("release environment has an invalid reviewer")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, choices=ENVIRONMENT_NAMES)
    args = parser.parse_args(argv)
    raw = sys.stdin.buffer.read(MAX_RESPONSE_BYTES + 1)
    try:
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("release environment response is too large")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        validate_environment(payload, args.name)
    except (UnicodeError, ValueError) as exc:
        print(f"release environment {args.name}: {exc}", file=sys.stderr)
        return 1
    print(f"release environment {args.name}: independent reviewers verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
