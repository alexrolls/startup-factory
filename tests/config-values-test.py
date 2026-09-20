#!/usr/bin/env python3
"""Contract tests for the one inert Startup Factory assignment grammar."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli.config_values import (  # noqa: E402
    ConfigValueError,
    parse_config_bytes,
    read_config_file,
    state_for,
    value_for,
)


class ConfigValuesTest(unittest.TestCase):
    def test_documented_forms_have_one_normalized_meaning(self) -> None:
        parsed = parse_config_bytes(
            b"""
PLAIN=alpha#literal
COMMENT=alpha  # removed
DOUBLE="command --arg \\\"two words\\\" \\\\path" # note
SINGLE='two words # literal'
SPACED_NULL=  null  # absent
QUOTED_NULL="null"
""",
            "fixture",
        )
        self.assertEqual(value_for(parsed, "PLAIN"), "alpha#literal")
        self.assertEqual(value_for(parsed, "COMMENT"), "alpha")
        self.assertEqual(
            value_for(parsed, "DOUBLE"), 'command --arg "two words" \\path'
        )
        self.assertEqual(value_for(parsed, "SINGLE"), "two words # literal")
        self.assertIsNone(value_for(parsed, "SPACED_NULL"))
        self.assertIsNone(value_for(parsed, "QUOTED_NULL"))
        self.assertEqual(state_for(parsed, "SPACED_NULL"), "null")
        self.assertEqual(state_for(parsed, "ABSENT"), "missing")

    def test_whole_file_validation_rejects_ambiguity_and_guessing(self) -> None:
        failures = (
            (b"SAFE=true\nSAFE=false\n", "duplicate configuration key SAFE"),
            (b" SAFE=true\n", "malformed configuration assignment"),
            (b"safe=true\n", "malformed configuration assignment"),
            (b"SAFE =true\n", "malformed configuration assignment"),
            (b"SAFE=\"unterminated\n", "unmatched outer quote"),
            (b"SAFE=\"bad\\n\"\n", "unsupported escape"),
            (b"SAFE=\"ok\"garbage\n", "trailing bytes"),
            (b"SAFE=\x00\n", "control character"),
            (b"SAFE=\n", "empty value"),
        )
        for raw, message in failures:
            with self.subTest(raw=raw), self.assertRaisesRegex(
                ConfigValueError, message
            ):
                parse_config_bytes(raw, "fixture")

    def test_secure_reader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("SAFE=true\n", encoding="utf-8")
            alias = root / "alias"
            alias.symlink_to(target)
            with self.assertRaisesRegex(ConfigValueError, "non-symlink regular"):
                read_config_file(alias, "fixture")

    def test_secure_reader_rejects_same_inode_truncation_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "team.config.md"
            config.write_text("SAFE=true\n", encoding="utf-8")
            real_open = os.open

            def truncate_then_open(path: object, flags: int) -> int:
                writer = real_open(path, os.O_WRONLY)
                try:
                    os.ftruncate(writer, 0)
                finally:
                    os.close(writer)
                return real_open(path, flags)

            with mock.patch(
                "startup_factory_cli.config_values.os.open",
                side_effect=truncate_then_open,
            ), self.assertRaisesRegex(ConfigValueError, "changed while being opened"):
                read_config_file(config, "fixture")

    def test_cli_validates_whole_file_before_returning_requested_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "team.config.md"
            config.write_text("SAFE=true\nOTHER='unterminated\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "bin/config-value.py"),
                    "--config",
                    str(config),
                    "--prefix",
                    "fixture",
                    "value",
                    "SAFE",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fixture: malformed configuration value for OTHER", result.stderr)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
