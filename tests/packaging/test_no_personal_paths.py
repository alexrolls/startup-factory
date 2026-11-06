#!/usr/bin/env python3
"""Tracked files must not leak a maintainer's machine-specific home paths."""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

# Generic placeholder accounts that documentation and fixtures may use.
PLACEHOLDER_USERS = frozenset({"example", "me", "operator", "runner", "user", "you", "your-user", "<user>"})

HOME_PATH = re.compile(
    r"(?:/Users/|/home/|[A-Za-z]:\\\\?Users\\\\?)(?P<user><user>|[A-Za-z0-9._-]+)"
)


def _tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / name for name in result.stdout.decode().split("\0") if name]


@unittest.skipUnless(shutil.which("git") and (ROOT / ".git").exists(), "requires a git checkout")
class NoPersonalPathsTest(unittest.TestCase):
    def test_tracked_files_have_no_personal_home_paths(self) -> None:
        offenders = []
        for path in _tracked_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                for match in HOME_PATH.finditer(line):
                    if match.group("user").lower() not in PLACEHOLDER_USERS:
                        offenders.append(f"{path.relative_to(ROOT)}:{line_number}: {match.group(0)}")
        self.assertEqual(
            offenders,
            [],
            "personal home paths found; use repo-relative paths, $HOME, or a placeholder user",
        )


if __name__ == "__main__":
    unittest.main()
