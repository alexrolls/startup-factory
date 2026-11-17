#!/usr/bin/env python3
"""Exec-fixture contract tests; run only in the assigned isolated test runner.

These subprocess tests do not establish Docker or hypervisor containment.
They intentionally execute only the shipped fixture, without target projects,
network operations, shell commands, or credential/environment inheritance.
"""

from __future__ import annotations

import fcntl
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest


FIXTURE = Path(__file__).resolve().parents[1] / "bin/sandbox_qualification_fixture.py"
MAX_FRAME_BYTES = 64 * 1024


def frame(raw: bytes) -> bytes:
    return struct.pack("!I", len(raw)) + raw


def request(
    identifier: str = "request-1", operation: str = "ping", payload: bytes = b""
) -> bytes:
    return frame(json.dumps({
        "schemaVersion": 1,
        "id": identifier,
        "operation": operation,
        "payloadHex": payload.hex(),
    }, separators=(",", ":")).encode("utf-8"))


def responses(raw: bytes) -> list[dict]:
    result = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise AssertionError("unframed stdout or partial response header")
        size = struct.unpack("!I", raw[offset:offset + 4])[0]
        offset += 4
        if size == 0 or size > MAX_FRAME_BYTES or size > len(raw) - offset:
            raise AssertionError("invalid response frame size")
        result.append(json.loads(raw[offset:offset + size]))
        offset += size
    return result


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="sf-fixture-test-")
        self.addCleanup(self.scratch.cleanup)
        self.environment = {
            "HOME": self.scratch.name,
            "TMPDIR": self.scratch.name,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "LC_ALL": "C",
        }

    def command(self, *arguments):
        return [sys.executable, "-I", "-B", str(FIXTURE), *arguments]

    def run_fixture(self, content: bytes, *arguments):
        return subprocess.run(
            self.command(*arguments), input=content, capture_output=True,
            timeout=5, cwd=self.scratch.name, env=self.environment, check=False,
        )

    def start_fixture(self, *arguments):
        child = subprocess.Popen(
            self.command(*arguments), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.scratch.name, env=self.environment,
        )
        self.addCleanup(self.stop_fixture, child)
        return child

    @staticmethod
    def stop_fixture(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()

    def assert_rejected(self, content: bytes):
        result = self.run_fixture(content)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertLessEqual(len(result.stderr), 128)
        return result

    def test_ping_binary_echo_and_multiple_frames(self):
        payload = bytes(range(256)) * 100
        result = self.run_fixture(
            request("ping") + request("binary", "echo", payload)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        decoded = responses(result.stdout)
        self.assertEqual([value["id"] for value in decoded], ["ping", "binary"])
        self.assertEqual(decoded[1], {
            "schemaVersion": 1, "fixtureVersion": 1, "id": "binary",
            "operation": "echo", "payloadHex": payload.hex(),
        })

    def test_stderr_is_not_a_control_frame(self):
        result = self.run_fixture(request("separate", "stderr"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"SF_QUALIFICATION_STDERR\n")
        self.assertEqual(responses(result.stdout)[0]["id"], "separate")

    def test_exit_status_is_acknowledged_before_exit(self):
        result = self.run_fixture(request("ending", "exit", b"\x07"))
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(responses(result.stdout)[0]["payloadHex"], "07")

    def test_zero_and_oversized_lengths_are_rejected_before_payload_read(self):
        for size in (0, MAX_FRAME_BYTES + 1, 0xFFFFFFFF):
            with self.subTest(size=size):
                self.assert_rejected(struct.pack("!I", size))

    def test_response_overhead_cannot_exceed_the_frame_limit(self):
        overhead = len(request("limit", "echo")) - 4
        payload = b"x" * ((MAX_FRAME_BYTES - overhead) // 2)
        content = request("limit", "echo", payload)
        self.assertLessEqual(len(content) - 4, MAX_FRAME_BYTES)
        result = self.assert_rejected(content)
        self.assertIn(b"response frame limit", result.stderr)

    def test_truncated_header_and_body_are_rejected(self):
        for content in (b"\x00", struct.pack("!I", 10) + b"{}"):
            with self.subTest(content=content):
                self.assert_rejected(content)

    def test_duplicate_nonfinite_deep_and_invalid_json_are_rejected(self):
        malformed = [
            b'{"schemaVersion":1,"schemaVersion":1,"id":"x",'
            b'"operation":"ping","payloadHex":""}',
            b'{"schemaVersion":NaN,"id":"x","operation":"ping","payloadHex":""}',
            b'{"schemaVersion":Infinity,"id":"x","operation":"ping","payloadHex":""}',
            b"[" * 20 + b"0" + b"]" * 20,
            b"\xff", b"{", b"{} {}",
        ]
        for content in malformed:
            with self.subTest(content=content):
                self.assert_rejected(frame(content))

    def test_closed_schema_and_operations_reject_authority_and_path_fields(self):
        base = {"schemaVersion": 1, "id": "x", "operation": "echo", "payloadHex": ""}
        invalid = [
            {**base, "hostPath": "/tmp/unapproved"},
            {**base, "command": "unapproved"},
            {**base, "operation": "read"},
            {**base, "schemaVersion": True},
            {**base, "schemaVersion": 1.0},
            {**base, "payloadHex": "FF"},
            {**base, "payloadHex": "aa bb"},
            {**base, "payloadHex": "a"},
            {**base, "id": "../outside"},
            {**base, "id": "x" * 65},
            {**base, "operation": "exit", "payloadHex": "ff"},
            {**base, "operation": "ping", "payloadHex": "00"},
        ]
        for value in invalid:
            with self.subTest(value=value):
                self.assert_rejected(frame(json.dumps(value).encode("utf-8")))

    def test_fragmented_request_preserves_frame_integrity(self):
        child = self.start_fixture("--frame-timeout", "1")
        content = request("fragmented", "echo", b"\x00\xff{}[]\\\n")
        for offset in range(0, len(content), 3):
            child.stdin.write(content[offset:offset + 3])
            child.stdin.flush()
        child.stdin.close()
        child.stdin = None
        stdout, stderr = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(responses(stdout)[0]["payloadHex"], "00ff7b7d5b5d5c0a")

    def test_slow_partial_frame_has_a_monotonic_deadline(self):
        child = self.start_fixture("--frame-timeout", "0.15")
        child.stdin.write(struct.pack("!I", 100) + b"{")
        child.stdin.flush()
        started = time.monotonic()
        child.wait(timeout=2)
        elapsed = time.monotonic() - started
        self.assertEqual(child.returncode, 124)
        self.assertLess(elapsed, 1.5)
        self.assertEqual(child.stdout.read(), b"")
        self.assertIn(b"deadline", child.stderr.read())

    def test_output_backpressure_cannot_block_forever(self):
        if not hasattr(fcntl, "F_SETPIPE_SZ"):
            self.skipTest("requires Linux pipe sizing in the isolated test runner")
        child = self.start_fixture("--frame-timeout", "0.15")
        capacity = fcntl.fcntl(child.stdout.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        # Force the response to exceed actual pipe capacity, then leave stdout
        # unread. Timing out on a subsequent input read would be a false pass.
        content = request("backpressure", "echo", b"x" * 32000)
        child.stdin.write(content)
        child.stdin.flush()
        child.wait(timeout=2)
        self.assertEqual(child.returncode, 124)
        self.assertIn(b"deadline", child.stderr.read())
        partial = child.stdout.read()
        self.assertGreater(len(partial), 4)
        self.assertLessEqual(len(partial), capacity)
        declared = struct.unpack("!I", partial[:4])[0]
        self.assertGreater(declared, len(partial) - 4)

    def test_invalid_limit_arguments_cannot_remove_bounds(self):
        for arguments in (
            ("--frame-timeout", "nan"), ("--frame-timeout", "inf"),
            ("--frame-timeout", "0"), ("--frame-timeout", "11"),
            ("--max-requests", "0"), ("--max-requests", "65"),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_fixture(b"", *arguments)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")

    def test_clean_eof_and_explicit_request_cap(self):
        result = self.run_fixture(b"")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_fixture(request("first") + request("ignored"), "--max-requests", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([item["id"] for item in responses(result.stdout)], ["first"])


if __name__ == "__main__":
    unittest.main()
