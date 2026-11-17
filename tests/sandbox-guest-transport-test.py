#!/usr/bin/env python3
"""Exercise guest helpers only inside the assigned disposable test container."""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from sandbox_guest_client import GuestProtocolError, body_bytes, decode  # noqa: E402


class GuestTransportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-guest-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.socket = self.root / "g.sock"

    def bridge(self, code: str, *, wall: int = 3):
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(ROOT / "bin/sandbox_guest_bridge.py"),
             "--guest-only", "--socket", str(self.socket), "--wall-seconds", str(wall),
             "--", sys.executable, "-I", "-B", "-c", code, str(ROOT / "bin")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.addCleanup(self.close, process)
        return process

    @staticmethod
    def close(process):
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()

    @staticmethod
    def frame(value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        return struct.pack("!I", len(raw)) + raw

    def read(self, stream, size):
        result = bytearray()
        deadline = time.monotonic() + 3
        while len(result) < size:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0)
            self.assertTrue(select.select([stream], [], [], remaining)[0], "frame timed out")
            chunk = os.read(stream.fileno(), size - len(result))
            self.assertTrue(chunk, "unexpected channel EOF")
            result.extend(chunk)
        return bytes(result)

    def test_agent_logs_cannot_become_control_frames_and_receipt_round_trips(self):
        code = """import json,os,sys
sys.path.insert(0,sys.argv[1])
from sandbox_guest_client import submit
print('agent stdout diagnostic',flush=True)
print('agent stderr diagnostic',file=sys.stderr,flush=True)
request={'schemaVersion':1,'id':'a'*32,'operation':'artifact.submit','marker':'task-complete','bodyHex':b'[task-complete]\\n'.hex(),'targetStatus':None}
response=submit(os.environ['STARTUP_FACTORY_GUEST_SOCKET'],request)
assert response['status']=='admitted'
"""
        process = self.bridge(code)
        size = struct.unpack("!I", self.read(process.stdout, 4))[0]
        request = decode(self.read(process.stdout, size))
        self.assertEqual(request["operation"], "artifact.submit")
        self.assertEqual(request["id"], "a" * 32)
        receipt = {"schemaVersion": 1, "id": request["id"], "operation": "artifact.submit",
                   "entryId": "b" * 32, "status": "admitted"}
        raw = self.frame(receipt)
        for chunk in (raw[:1], raw[1:3], raw[3:]):
            process.stdin.write(chunk)
            process.stdin.flush()
        process.stdin.close()
        result = process.wait(timeout=4)
        logs = process.stderr.read(4096)
        self.assertEqual(result, 0, logs)
        self.assertEqual(process.stdout.read(), b"")
        self.assertIn(b"agent stdout diagnostic", logs)
        self.assertIn(b"agent stderr diagnostic", logs)
        self.assertFalse(self.socket.exists())

    def test_mismatched_host_receipt_closes_bridge(self):
        process = self.bridge("""import os,sys
sys.path.insert(0,sys.argv[1]);from sandbox_guest_client import submit
submit(os.environ['STARTUP_FACTORY_GUEST_SOCKET'],{'schemaVersion':1,'id':'a'*32,'operation':'artifact.submit'})
""")
        size = struct.unpack("!I", self.read(process.stdout, 4))[0]
        self.read(process.stdout, size)
        process.stdin.write(self.frame({"id": "wrong", "operation": "artifact.submit"}))
        process.stdin.flush()
        self.assertEqual(process.wait(timeout=4), 1)
        self.assertFalse(self.socket.exists())

    def test_agent_exit_status_is_preserved(self):
        process = self.bridge("raise SystemExit(7)")
        self.assertEqual(process.wait(timeout=3), 7)
        self.assertEqual(process.stdout.read(), b"")

    def test_wall_deadline_bounds_idle_agent(self):
        start = time.monotonic()
        process = self.bridge("import time;time.sleep(60)", wall=1)
        self.assertEqual(process.wait(timeout=3), 1)
        self.assertLess(time.monotonic() - start, 3)

    def test_diagnostic_flood_is_bounded_and_never_uses_stdout(self):
        process = self.bridge("import os;\nwhile True:os.write(1,b'x'*8192)")
        self.assertEqual(process.wait(timeout=4), 1)
        self.assertEqual(process.stdout.read(), b"")
        self.assertLessEqual(len(process.stderr.read()), 1024 * 1024 + 100)

    def test_preexisting_socket_path_is_preserved(self):
        self.socket.write_bytes(b"host-assigned fixture")
        process = self.bridge("raise SystemExit(0)")
        self.assertEqual(process.wait(timeout=3), 1)
        self.assertEqual(self.socket.read_bytes(), b"host-assigned fixture")

    def test_client_body_refuses_symlinks_fifos_empty_and_oversized_files(self):
        regular = self.root / "regular"
        regular.write_bytes(b"hello\0binary")
        self.assertEqual(body_bytes(regular), b"hello\0binary")
        link = self.root / "link"
        link.symlink_to(regular)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        empty = self.root / "empty"
        empty.touch()
        big = self.root / "big"
        big.write_bytes(b"x" * (65536 + 1))
        for path in (link, fifo, empty, big):
            with self.subTest(path=path.name), self.assertRaises((OSError, GuestProtocolError)):
                body_bytes(path)

    def test_submit_tool_retry_retains_identity_after_lost_receipt_without_shared_git(self):
        body = self.root / "body.md"
        body.write_bytes(b"[task-complete]\nguest fixture\n")
        observed = []
        failures = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.socket))
            server.listen(1)
            server.settimeout(3)
            def receive():
                try:
                    for attempt in range(2):
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(3)
                            stream = connection.makefile("rb", buffering=0)
                            try:
                                header = stream.read(4)
                                size = struct.unpack("!I", header)[0]
                                raw = bytearray()
                                while len(raw) < size:
                                    chunk = stream.read(size - len(raw))
                                    if not chunk:
                                        raise AssertionError("truncated local request")
                                    raw.extend(chunk)
                                request = decode(bytes(raw))
                                observed.append(request)
                                if attempt:
                                    connection.sendall(self.frame({"schemaVersion": 1, "id": request["id"],
                                        "operation": "artifact.submit", "entryId": "b" * 32, "status": "admitted"}))
                            finally:
                                stream.close()
                except BaseException as exc:
                    failures.append(exc)
            thread = threading.Thread(target=receive, daemon=True)
            thread.start()
            results = [subprocess.run(["/bin/bash", str(ROOT / "bin/submit-artifact.sh"),
                    "team-one", "FEATURE-1", "TASK-1", "1", "developer", "task-complete", str(body), "-"],
                    cwd=self.root, env={"PATH": "/usr/bin:/bin", "STARTUP_FACTORY_GUEST_SOCKET": str(self.socket)},
                    capture_output=True, timeout=5) for _ in range(2)]
            thread.join(timeout=4)
            self.assertFalse(thread.is_alive())
        self.assertFalse(failures, failures)
        self.assertEqual(results[0].returncode, 1)
        self.assertEqual(results[1].returncode, 0, results[1].stderr)
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0], observed[1])
        self.assertEqual(set(observed[0]), {"schemaVersion", "id", "operation", "marker", "bodyHex", "targetStatus"})
        self.assertEqual(bytes.fromhex(observed[0]["bodyHex"]), body.read_bytes())
        self.assertFalse((self.root / ".teamwork").exists())

    def test_submit_tool_refuses_mixed_guest_and_host_authority(self):
        body = self.root / "body.md"
        body.write_bytes(b"[task-complete]\nfixture\n")
        result = subprocess.run(["/bin/bash", str(ROOT / "bin/submit-artifact.sh"),
            "team", "feature", "task", "1", "developer", "task-complete", str(body), "-"],
            cwd=self.root, env={"PATH": "/usr/bin:/bin", "STARTUP_FACTORY_GUEST_SOCKET": str(self.socket),
                "STARTUP_FACTORY_OUTBOX_TRANSPORT": "/dummy/unreachable"}, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"cannot be combined", result.stderr)

    def test_protocol_rejects_duplicate_nonfinite_deep_and_nonobject_json(self):
        for raw in (b'{"id":1,"id":2}', b'{"x":NaN}', b'{"x":1e999}',
                    b'[]', b'{} trailing', b'{"x":' + b'[' * 10 + b'0' + b']' * 10 + b'}'):
            with self.subTest(raw=raw[:40]), self.assertRaises(GuestProtocolError):
                decode(raw)


if __name__ == "__main__":
    unittest.main()
