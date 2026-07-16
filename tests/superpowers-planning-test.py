#!/usr/bin/env python3
"""Focused tests for the optional Claude/Superpowers planning boundary."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "superpowers-planning.py"


def run(*arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        [os.fspath(SCRIPT), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert process.returncode == expected, (
        process.returncode,
        process.stdout,
        process.stderr,
    )
    return process


def git(repo: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", "-C", os.fspath(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    return process.stdout.strip()


def write_config(path: Path, enabled: bool) -> None:
    path.write_text(
        "```\n"
        f"USE_SUPERPOWERS={'true' if enabled else 'false'}\n"
        "SUPERPOWERS_PLUGIN_ID=superpowers@claude-plugins-official\n"
        "SUPERPOWERS_SPEC_ROOT=docs/superpowers/specs\n"
        "SUPERPOWERS_PLAN_ROOT=docs/superpowers/plans\n"
        "```\n",
        encoding="utf-8",
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        enabled = temp / "enabled.md"
        disabled = temp / "disabled.md"
        write_config(enabled, True)
        write_config(disabled, False)

        shipped = json.loads(
            run(
                "--config",
                os.fspath(ROOT / "config" / "planning.config.md"),
                "show-config",
            ).stdout
        )
        assert shipped["enabled"] is True

        missing_config = json.loads(
            run(
                "--config",
                os.fspath(temp / "missing.md"),
                "show-config",
            ).stdout
        )
        assert missing_config["enabled"] is True

        shown = json.loads(run("--config", os.fspath(enabled), "show-config").stdout)
        assert shown["enabled"] is True
        assert shown["pluginId"] == "superpowers@claude-plugins-official"

        disabled_result = json.loads(
            run(
                "--config",
                os.fspath(disabled),
                "preflight",
                "--runtime",
                "claude",
            ).stdout
        )
        assert disabled_result["status"] == "disabled"

        other_result = json.loads(
            run(
                "--config",
                os.fspath(enabled),
                "preflight",
                "--runtime",
                "other",
            ).stdout
        )
        assert other_result["status"] == "not-applicable"

        plugins = temp / "plugins.json"
        plugins.write_text(
            json.dumps(
                [
                    {
                        "id": "superpowers@claude-plugins-official",
                        "enabled": True,
                        "version": "6.1.1",
                    }
                ]
            ),
            encoding="utf-8",
        )
        ready = json.loads(
            run(
                "--config",
                os.fspath(enabled),
                "preflight",
                "--runtime",
                "claude",
                "--plugin-list-json",
                os.fspath(plugins),
            ).stdout
        )
        assert ready["status"] == "ready"
        assert ready["version"] == "6.1.1"

        plugins.write_text("[]\n", encoding="utf-8")
        missing = run(
            "--config",
            os.fspath(enabled),
            "preflight",
            "--runtime",
            "claude",
            "--plugin-list-json",
            os.fspath(plugins),
            expected=1,
        )
        assert "required Claude plugin is not installed" in missing.stderr

        repo = temp / "repo"
        repo.mkdir()
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "test@example.com")
        git(repo, "config", "user.name", "Test")
        spec = repo / "docs" / "superpowers" / "specs" / "feature-design.md"
        plan = repo / "docs" / "superpowers" / "plans" / "feature.md"
        spec.parent.mkdir(parents=True)
        plan.parent.mkdir(parents=True)
        spec.write_text("# Approved design\n", encoding="utf-8")
        plan.write_text("# Implementation plan\n", encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "planning inputs")

        handoff = (
            repo / ".teamwork" / "feature" / "planning" / "superpowers-handoff.json"
        )
        created = json.loads(
            run(
                "--config",
                os.fspath(enabled),
                "create-handoff",
                "--repo",
                os.fspath(repo),
                "--team",
                "feature",
                "--spec",
                spec.relative_to(repo).as_posix(),
                "--plan",
                plan.relative_to(repo).as_posix(),
                "--output",
                os.fspath(handoff),
            ).stdout
        )
        assert Path(created["handoff"]) == handoff.resolve()
        manifest = json.loads(handoff.read_text(encoding="utf-8"))
        assert manifest["executionOwner"] == "startup-factory"
        assert (
            "superpowers:subagent-driven-development"
            in manifest["blockedExecutionSkills"]
        )

        validated = json.loads(
            run(
                "--config",
                os.fspath(enabled),
                "validate-handoff",
                "--repo",
                os.fspath(repo),
                "--handoff",
                os.fspath(handoff),
                "--team",
                "feature",
                "--require-head",
            ).stdout
        )
        assert validated["valid"] is True

        (repo / "README.md").write_text("# Descendant commit\n", encoding="utf-8")
        git(repo, "add", "README.md")
        git(repo, "commit", "-qm", "continue after planning")
        descendant = json.loads(
            run(
                "--config",
                os.fspath(enabled),
                "validate-handoff",
                "--repo",
                os.fspath(repo),
                "--handoff",
                os.fspath(handoff),
            ).stdout
        )
        assert descendant["valid"] is True
        stale_head = run(
            "--config",
            os.fspath(enabled),
            "validate-handoff",
            "--repo",
            os.fspath(repo),
            "--handoff",
            os.fspath(handoff),
            "--require-head",
            expected=1,
        )
        assert "not the current HEAD" in stale_head.stderr

        spec.write_text("# Changed design\n", encoding="utf-8")
        stale = run(
            "--config",
            os.fspath(enabled),
            "validate-handoff",
            "--repo",
            os.fspath(repo),
            "--handoff",
            os.fspath(handoff),
            expected=1,
        )
        assert "digest does not match" in stale.stderr

        disabled_create = run(
            "--config",
            os.fspath(disabled),
            "create-handoff",
            "--repo",
            os.fspath(repo),
            "--team",
            "feature",
            "--spec",
            spec.relative_to(repo).as_posix(),
            "--plan",
            plan.relative_to(repo).as_posix(),
            "--output",
            os.fspath(handoff),
            expected=1,
        )
        assert "disabled" in disabled_create.stderr

    print("ALL PASS")


if __name__ == "__main__":
    main()
