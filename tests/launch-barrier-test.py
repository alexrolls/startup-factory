#!/usr/bin/env python3
"""Deterministic FIFO scheduling regressions for the real launcher reader."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class LaunchBarrierReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = (ROOT / "bin/launch-team.sh").read_text(encoding="utf-8")
        start = (
            "    descriptor = os.open(\n"
            "        barrier,\n"
            '        os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),\n'
            "    )\n"
        )
        token_check = '    if released != b"go\\n":\n        raise SystemExit(1)\n'
        end = token_check + "    os.chdir(workdir)\n    os.execvp(command[0], command)\n"
        if source.count(start) != 1 or source.count(end) != 1:
            raise AssertionError("managed background FIFO reader extraction drifted")
        reader = source.split(start, 1)[1].split(end, 1)[0]
        cls.reader = compile(
            textwrap.dedent(start + reader + token_check),
            "launch-team.sh:background-barrier",
            "exec",
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fifo = Path(self.temporary.name) / "go"
        os.mkfifo(self.fifo, 0o600)

    def read_release(self) -> None:
        exec(self.reader, {"os": os, "time": time, "barrier": str(self.fifo)})

    def test_connected_writer_can_publish_after_reader_observes_no_data(self) -> None:
        connected = threading.Event()
        empty_read = threading.Event()
        writer_errors: list[BaseException] = []
        original_read = os.read

        def delayed_writer() -> None:
            try:
                descriptor = os.open(self.fifo, os.O_WRONLY)
                try:
                    connected.set()
                    if not empty_read.wait(2):
                        raise AssertionError("reader never observed the connected empty FIFO")
                    os.write(descriptor, b"go\n")
                finally:
                    os.close(descriptor)
            except BaseException as exc:
                writer_errors.append(exc)

        def read_connected_fifo(descriptor: int, count: int) -> bytes:
            self.assertTrue(connected.wait(2), "writer did not connect to the FIFO")
            try:
                return original_read(descriptor, count)
            except BlockingIOError:
                empty_read.set()
                raise

        writer = threading.Thread(target=delayed_writer, daemon=True)
        writer.start()
        try:
            with mock.patch.object(os, "read", side_effect=read_connected_fifo):
                self.read_release()
        finally:
            writer.join(3)
        self.assertFalse(writer.is_alive(), "barrier writer did not finish")
        self.assertEqual(writer_errors, [])
        self.assertTrue(empty_read.is_set(), "EAGAIN schedule was not exercised")

    def test_malformed_release_token_is_rejected(self) -> None:
        # O_RDWR holds both ends open while we seed the invalid token. The
        # production reader still opens and closes its own nonblocking fd.
        writer = os.open(self.fifo, os.O_RDWR | os.O_NONBLOCK)
        try:
            os.write(writer, b"bad\n")
            with self.assertRaises(SystemExit) as raised:
                self.read_release()
            self.assertEqual(raised.exception.code, 1)
        finally:
            os.close(writer)

    def test_missing_or_partial_release_keeps_the_existing_deadline(self) -> None:
        for token in (None, b"", b"go"):
            with self.subTest(token=token):
                writer = (
                    os.open(self.fifo, os.O_RDWR | os.O_NONBLOCK)
                    if token is not None
                    else None
                )
                try:
                    if token:
                        os.write(writer, token)
                    # Advance past the production 15-second deadline without
                    # sleeping, while retaining real FIFO EOF/EAGAIN behavior.
                    with mock.patch.object(
                        time, "monotonic", side_effect=(100.0, 114.999, 115.001)
                    ), mock.patch.object(time, "sleep") as sleep, self.assertRaises(
                        SystemExit
                    ) as raised:
                        self.read_release()
                    self.assertEqual(raised.exception.code, 1)
                    sleep.assert_called_once()
                finally:
                    if writer is not None:
                        os.close(writer)


if __name__ == "__main__":
    unittest.main()
