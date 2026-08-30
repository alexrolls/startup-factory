#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("promote_outbox", ROOT / "bin/promote-outbox-ingress.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(module)


class OutboxIngressTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.ingress = self.root / "ingress"
        self.pending = self.root / "pending"
        self.bodies = self.root / "bodies"
        for directory in (self.ingress, self.pending, self.bodies):
            directory.mkdir(mode=0o700)
        self.capability = "cap-" + "a" * 32
        self.capability_dir = self.ingress / self.capability
        self.capability_dir.mkdir(mode=0o700)
        self.identifier = "12345678-1234-4123-8123-123456789abc"
        self.body = self.capability_dir / f"{self.identifier}.md"
        self.body.write_text("[review-request]\nready\n")
        self.body.chmod(0o600)
        self.entry = self.capability_dir / f"{self.identifier}.json"
        self.entry.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "id": self.identifier,
                    "team": "feature-runtime",
                    "featureId": "F-1",
                    "taskId": "T-1",
                    "attempt": 1,
                    "actor": "backend",
                    "marker": "review-request",
                    "bodyPath": str(self.body),
                    "targetStatus": "Review",
                    "phase": "pending",
                    "createdAt": "2026-08-21T00:00:00+00:00",
                    "producerCapability": {"id": self.capability},
                },
                indent=2,
            )
            + "\n"
        )
        self.entry.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_promotes_exact_capability_entry_and_rewrites_only_body_path(self) -> None:
        destination = module.promote(
            self.entry, self.ingress, self.pending, self.bodies, "feature-runtime", "F-1"
        )
        promoted = json.loads(destination.read_text())
        self.assertEqual(promoted["bodyPath"], str(self.bodies / f"{self.identifier}.md"))
        self.assertEqual((self.bodies / f"{self.identifier}.md").read_text(), "[review-request]\nready\n")
        self.assertTrue(self.entry.with_suffix(".promoted").is_file())
        self.assertEqual(promoted["producerCapability"], {"id": self.capability})

    def test_wrong_capability_symlink_and_collision_fail_closed(self) -> None:
        data = json.loads(self.entry.read_text())
        data["producerCapability"]["id"] = "cap-" + "b" * 32
        self.entry.write_text(json.dumps(data) + "\n")
        with self.assertRaisesRegex(module.PromotionError, "capability binding"):
            module.promote(self.entry, self.ingress, self.pending, self.bodies, "feature-runtime", "F-1")

        data["producerCapability"]["id"] = self.capability
        self.entry.write_text(json.dumps(data) + "\n")
        self.body.unlink()
        outside = self.root / "outside.md"
        outside.write_text("[review-request]\noutside\n")
        self.body.symlink_to(outside)
        with self.assertRaisesRegex(module.PromotionError, "unsafe"):
            module.promote(self.entry, self.ingress, self.pending, self.bodies, "feature-runtime", "F-1")

    def test_retry_completes_a_durable_body_only_promotion(self) -> None:
        original = module.exclusive
        calls = 0

        def fail_after_body(path: Path, content: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected crash before canonical entry")
            original(path, content)

        with mock.patch.object(module, "exclusive", side_effect=fail_after_body):
            with self.assertRaisesRegex(OSError, "injected crash"):
                module.promote(
                    self.entry, self.ingress, self.pending, self.bodies,
                    "feature-runtime", "F-1",
                )
        destination_body = self.bodies / f"{self.identifier}.md"
        destination_entry = self.pending / f"{self.identifier}.json"
        self.assertTrue(destination_body.is_file())
        self.assertFalse(destination_entry.exists())
        self.assertTrue(self.entry.is_file())

        promoted = module.promote(
            self.entry, self.ingress, self.pending, self.bodies, "feature-runtime", "F-1"
        )
        self.assertEqual(promoted, destination_entry)
        self.assertTrue(destination_entry.is_file())
        self.assertTrue(self.entry.with_suffix(".promoted").is_file())

    def test_entry_without_body_is_rejected_and_preserved(self) -> None:
        destination_entry = self.pending / f"{self.identifier}.json"
        destination_entry.write_text("{}\n")
        destination_entry.chmod(0o600)
        with self.assertRaisesRegex(module.PromotionError, "entry without its body"):
            module.promote(
                self.entry, self.ingress, self.pending, self.bodies,
                "feature-runtime", "F-1",
            )
        self.assertEqual(destination_entry.read_text(), "{}\n")
        self.assertTrue(self.entry.is_file())


if __name__ == "__main__":
    unittest.main()
