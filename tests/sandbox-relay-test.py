#!/usr/bin/env python3
"""Native relay fixtures; execute only in the assigned isolated test runner.

Set SF_REGISTRY_TEST_ROOT to a private writable location with protected
ancestors, such as /scratch. Subprocesses execute only the fixed shipped relay
or the fixed framing harness below, with an explicit fixture environment.
There are no Docker, tracker, external network, or real credential operations.
"""

from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
sys.path.insert(0, str(ROOT / "src"))
import outbox_capability as capability  # noqa: E402
from sandbox_transport import (  # noqa: E402
    ArtifactRelay, ERROR_RESPONSE, MAX_REQUEST_FRAME_BYTES, RelayContext,
    RelayError, RelayLimits, project_id_for_repository, response_frame,
)
from startup_factory_cli.sandbox_registry import RegistryError, SandboxRegistry  # noqa: E402


CREATED = "2026-11-17T10:00:00Z"
HARNESS = r"""import json,sys,time
sys.path.insert(0,sys.argv[1])
from sandbox_transport import RelayLimits,serve_framed
mode=sys.argv[2]
limits=RelayLimits(wall_seconds=float(sys.argv[3]),frame_seconds=float(sys.argv[4]),write_seconds=float(sys.argv[5]),max_requests=int(sys.argv[6]),max_output_bytes=int(sys.argv[7]))
def handler(raw):
    if mode=='slow':time.sleep(10)
    if mode=='exception':raise Exception('never-emit-host-private-details')
    request=json.loads(raw)
    value={'schemaVersion':1,'id':request['id'],'operation':'artifact.submit','entryId':'11111111-1111-4111-8111-111111111111','status':'admitted'}
    if mode=='leak':value['producerCapability']={'secret':'never-emit-host-private-details'}
    return value
raise SystemExit(serve_framed(handler,limits))
"""


def request(identifier: str = "a" * 32, marker: str = "task-complete", target: str | None = None) -> dict:
    return {"schemaVersion": 1, "id": identifier, "operation": "artifact.submit", "marker": marker, "bodyHex": ("[" + marker + "]\nfixture body\n").encode().hex(), "targetStatus": target}


def frame(value: dict | bytes) -> bytes:
    raw = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
    return struct.pack("!I", len(raw)) + raw


def responses(raw: bytes) -> list[dict]:
    result = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise AssertionError("partial response header")
        size = struct.unpack("!I", raw[offset:offset + 4])[0]
        offset += 4
        if not 0 < size <= 16 * 1024 or size > len(raw) - offset:
            raise AssertionError("partial or oversized response")
        result.append(json.loads(raw[offset:offset + size]))
        offset += size
    return result


class RegistryRelayTest(unittest.TestCase):
    def setUp(self) -> None:
        base = Path(os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd()))
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-relay-", dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name).resolve()
        self.scratch.chmod(0o700)
        self.repo = self.scratch / "r"
        self.repo.mkdir(mode=0o700)
        self.workspace = self.repo / "w"
        self.workspace.mkdir(mode=0o700)
        self.common = self.repo / ".git"
        self.common.mkdir(mode=0o700)
        self.registry_root = self.scratch / "registry"
        self.registry_root.mkdir(mode=0o700)
        self.registry = SandboxRegistry(self.registry_root, "sf-qualification")
        self.addCleanup(self.registry.close)
        self.scope = {"projectId": project_id_for_repository(self.repo), "team": "team-one", "featureId": "FEATURE-1", "role": "developer", "taskId": "TASK-1", "attempt": 1}
        with self.registry.locked() as transaction:
            self.epoch = transaction.takeover()
            record = transaction.reserve(self.scope, epoch=self.epoch)
            self.record = transaction.bind(record["name"], record["generation"], self.epoch, sandbox_id=str(uuid.uuid4()), created_at=CREATED)
            transaction.transition(record["name"], record["generation"], self.epoch, state="ready")
            transaction.transition(record["name"], record["generation"], self.epoch, state="running")
            registry_id = transaction.registry_id
        for patch in (mock.patch.object(capability, "_repo", return_value=self.repo), mock.patch.object(capability, "git_common_dir", return_value=self.common)):
            patch.start()
            self.addCleanup(patch.stop)
        self.producer = capability.mint(str(self.repo), str(self.workspace), "team-one", "FEATURE-1", "developer", "task", "TASK-1", 1, "task:TASK-1")
        leaf = hashlib.sha256((str(self.repo) + "\0" + self.producer["id"]).encode()).hexdigest()[:32]
        self.data = {
            "schemaVersion": 1, "registryRoot": str(self.registry_root), "registryId": registry_id,
            "namespace": "sf-qualification", "name": self.record["name"],
            "generation": self.record["generation"], "epoch": self.epoch,
            "sandboxId": self.record["sandboxId"], "createdAt": CREATED,
            "scope": self.scope,
            "boundContext": {"repository": str(self.repo), "workspace": str(self.workspace), "team": "team-one", "feature": "FEATURE-1", "role": "developer", "task": "TASK-1", "attempt": 1, "generation": self.record["generation"], "transport": str(self.scratch / "p" / leaf)},
            "allowedArtifacts": {"task-complete": [None]},
            "limits": RelayLimits(wall_seconds=2).as_dict(),
            "watchdog": {"deploymentPath": "/fixture/deployment.json", "leaseId": "1" * 32, "deadline": 2524608000},
        }
        watch = mock.patch("sandbox_transport.verify_watchdog_lease", return_value=True)
        self.watchdog = watch.start()
        self.addCleanup(watch.stop)
        self.context = RelayContext.from_dict(self.data)
        self.context_path = self.registry_root / "relay-context.json"
        self.context_path.write_text(json.dumps(self.data))
        self.context_path.chmod(0o600)
        self.signatures = 0

    def signer(self, locator: str, entry: dict, body: bytes) -> dict:
        self.assertEqual(locator, self.context.bound.transport)
        self.signatures += 1
        return capability.sign_active_entry(str(self.repo), str(self.workspace), self.producer["id"], entry, body)

    def relay(self, **arguments) -> ArtifactRelay:
        result = ArtifactRelay(self.context, signer=self.signer, **arguments)
        self.addCleanup(result.close)
        return result

    def fence(self) -> None:
        with self.registry.locked() as transaction:
            transaction.fence(self.record["name"], self.record["generation"], self.epoch)
        capability.revoke_exact(str(self.repo), str(self.workspace), self.producer["id"])

    def environment(self) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "HOME": str(self.scratch), "TMPDIR": str(self.scratch), "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1", "PRIVATE_FIXTURE_TOKEN": "never-emit-host-private-details"}

    def cli(self, content: bytes, path: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-I", "-B", str(ROOT / "bin/sandbox-relay.py"), "--context", str(path or self.context_path)], input=content, capture_output=True, timeout=4, cwd=self.scratch, env=self.environment(), check=False)

    def test_context_roundtrip_and_protected_file_loading(self) -> None:
        self.assertEqual(RelayContext.from_file(self.context_path), self.context)
        self.assertEqual(RelayContext.from_dict(self.context.as_dict()), self.context)
        self.assertEqual(self.context.scope.project_id, "sha256:" + hashlib.sha256(str(self.repo).encode()).hexdigest())

    def test_fresh_request_requires_registry_generation_scope_and_allowlist(self) -> None:
        relay = self.relay()
        receipt = relay.handle(json.dumps(request()).encode())
        self.assertEqual(receipt["status"], "admitted")
        for value in (request("b" * 32, marker="review-approved"), request("c" * 32, target="Done")):
            with self.assertRaises(RelayError):
                relay.handle(json.dumps(value).encode())
        self.assertEqual(self.signatures, 1)
        self.fence()
        with self.assertRaises(RelayError):
            relay.handle(json.dumps(request("d" * 32)).encode())
        self.assertEqual(relay.handle(json.dumps(request()).encode()), receipt)
        self.assertEqual(self.signatures, 1)

    def test_takeover_fences_fresh_requests_but_preserves_exact_admitted_receipt(self) -> None:
        relay = self.relay()
        first = relay.handle(json.dumps(request()).encode())
        with self.registry.locked() as transaction:
            transaction.takeover()
        self.assertEqual(relay.handle(json.dumps(request()).encode()), first)
        with self.assertRaises(RelayError):
            relay.handle(json.dumps(request("b" * 32)).encode())
        self.assertEqual(self.signatures, 1)

    def test_expired_watchdog_denies_fresh_without_namespace_lock_and_allows_exact_retry(self):
        relay = self.relay()
        receipt = relay.handle(json.dumps(request()).encode())
        self.watchdog.return_value = False
        with self.registry.locked():
            self.assertEqual(relay.handle(json.dumps(request()).encode()), receipt)
            with self.assertRaises(RelayError):
                relay.handle(json.dumps(request("b" * 32)).encode())
        self.assertEqual(self.signatures, 1)

    def test_lost_signature_response_recovers_after_namespace_fence(self) -> None:
        def lost(locator: str, entry: dict, body: bytes) -> dict:
            self.signer(locator, entry, body)
            raise ConnectionError("lost fixture response")
        relay = ArtifactRelay(self.context, signer=lost)
        self.addCleanup(relay.close)
        with self.assertRaises(RelayError):
            relay.handle(json.dumps(request()).encode())
        self.fence()
        receipt = relay.handle(json.dumps(request()).encode())
        self.assertEqual(receipt["status"], "admitted")
        self.assertEqual(self.signatures, 1)

    def test_namespace_lock_is_held_during_signing_but_not_after_handler_returns(self) -> None:
        contender = SandboxRegistry(self.registry_root, "sf-qualification")
        self.addCleanup(contender.close)
        def guarded(locator: str, entry: dict, body: bytes) -> dict:
            with self.assertRaises(RegistryError):
                with contender.locked():
                    pass
            return self.signer(locator, entry, body)
        relay = ArtifactRelay(self.context, signer=guarded)
        self.addCleanup(relay.close)
        relay.handle(json.dumps(request()).encode())
        with contender.locked() as transaction:
            self.assertEqual(transaction.epoch, self.epoch)

    def test_context_rejects_extra_authority_wrong_repo_and_mismatched_task(self) -> None:
        invalid = [
            {**self.data, "producerSecret": "never-emit-host-private-details"},
            {**self.data, "scope": {**self.scope, "projectId": "sha256:" + "0" * 64}},
            {**self.data, "boundContext": {**self.data["boundContext"], "task": "OTHER"}},
            {**self.data, "boundContext": {**self.data["boundContext"], "generation": "gen-" + "0" * 32}},
            {**self.data, "epoch": True},
            {**self.data, "allowedArtifacts": {"task-complete": [None, None]}},
        ]
        for value in invalid:
            with self.subTest(fields=str(value)[:80]):
                with self.assertRaises(RelayError):
                    RelayContext.from_dict(value)

    def test_gate_scope_still_pins_one_concrete_review_task(self) -> None:
        data = {**self.data, "scope": {**self.scope, "taskId": "-", "attempt": 0}}
        context = RelayContext.from_dict(data)
        self.assertEqual((context.bound.task, context.bound.attempt), ("TASK-1", 1))
        with self.assertRaises(RelayError):
            RelayContext.from_dict({**data, "boundContext": {**data["boundContext"], "task": "-", "attempt": 0}})

    def test_direct_context_cannot_bypass_host_binding_or_marker_policy(self) -> None:
        mismatches = [
            dataclasses.replace(self.context.bound, task="OTHER"),
            dataclasses.replace(self.context.bound, role="reviewer"),
            dataclasses.replace(self.context.bound, generation="gen-" + "0" * 32),
        ]
        for bound in mismatches:
            with self.subTest(bound=bound):
                with self.assertRaises(RelayError):
                    ArtifactRelay(dataclasses.replace(self.context, bound=bound), signer=self.signer)
        for marker in ("production-approval", "deployment"):
            with self.subTest(marker=marker):
                with self.assertRaises(RelayError):
                    RelayContext.from_dict({**self.data, "allowedArtifacts": {marker: [None]}})
                with self.assertRaises(RelayError):
                    ArtifactRelay(dataclasses.replace(self.context, allowed_artifacts=((marker, (None,)),)), signer=self.signer)
        self.assertEqual(self.signatures, 0)

    def test_context_permissions_links_and_duplicate_keys_are_rejected(self) -> None:
        self.context_path.chmod(0o644)
        with self.assertRaises(RelayError):
            RelayContext.from_file(self.context_path)
        self.context_path.chmod(0o600)
        link = self.registry_root / "alias.json"
        link.symlink_to(self.context_path)
        with self.assertRaises(RelayError):
            RelayContext.from_file(link)
        link.unlink()
        os.link(self.context_path, link)
        with self.assertRaises(RelayError):
            RelayContext.from_file(self.context_path)
        link.unlink()
        self.context_path.write_text(json.dumps(self.data)[:-1] + ',"epoch":1}')
        with self.assertRaises(RelayError):
            RelayContext.from_file(self.context_path)

    def test_actual_cli_replays_admitted_request_after_fence_without_signing(self) -> None:
        relay = self.relay()
        receipt = relay.handle(json.dumps(request()).encode())
        self.fence()
        result = self.cli(frame(request()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(responses(result.stdout), [receipt])
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(str(self.scratch).encode(), result.stdout)
        self.assertNotIn(self.producer["secret"].encode(), result.stdout)

    def test_actual_cli_denial_is_generic_and_does_not_sign_or_read_guest_path(self) -> None:
        self.fence()
        result = self.cli(frame(request()))
        self.assertEqual(result.returncode, 64)
        self.assertEqual(responses(result.stdout), [ERROR_RESPONSE])
        self.assertNotIn(str(self.scratch).encode(), result.stdout + result.stderr)
        self.assertNotIn(b"never-emit-host-private-details", result.stdout + result.stderr)
        self.assertEqual(self.signatures, 0)


class FramedTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-framing-")
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name)

    def command(self, mode: str = "normal", *, wall: float = 2, partial: float = 0.15, write: float = 0.15, count: int = 64, output: int = 1024 * 1024) -> list[str]:
        return [sys.executable, "-I", "-B", "-c", HARNESS, str(ROOT / "bin"), mode, str(wall), str(partial), str(write), str(count), str(output)]

    def environment(self) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "HOME": str(self.scratch), "TMPDIR": str(self.scratch), "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}

    def run_harness(self, content: bytes, **arguments) -> subprocess.CompletedProcess:
        return subprocess.run(self.command(**arguments), input=content, capture_output=True, timeout=4, cwd=self.scratch, env=self.environment(), check=False)

    def start(self, **arguments) -> subprocess.Popen:
        child = subprocess.Popen(self.command(**arguments), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.scratch, env=self.environment())
        self.addCleanup(self.stop, child)
        return child

    @staticmethod
    def stop(child: subprocess.Popen) -> None:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()

    def test_fragmented_request_and_multiple_correlated_frames(self) -> None:
        child = self.start()
        content = frame(request()) + frame(request("b" * 32))
        for offset in range(0, len(content), 7):
            child.stdin.write(content[offset:offset + 7])
            child.stdin.flush()
        child.stdin.close()
        child.stdin = None
        stdout, stderr = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual([value["id"] for value in responses(stdout)], ["a" * 32, "b" * 32])
        self.assertEqual(stderr, b"")

    def test_idle_time_does_not_start_partial_frame_deadline(self) -> None:
        child = self.start(wall=1.5, partial=0.1)
        time.sleep(0.25)
        child.stdin.write(frame(request()))
        child.stdin.flush()
        child.stdin.close()
        child.stdin = None
        stdout, stderr = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(responses(stdout)[0]["status"], "admitted")

    def test_partial_header_and_body_have_short_deadlines(self) -> None:
        for partial in (b"\x00", struct.pack("!I", 100) + b"{"):
            with self.subTest(partial=partial):
                child = self.start()
                child.stdin.write(partial)
                child.stdin.flush()
                child.wait(timeout=2)
                self.assertEqual(child.returncode, 124)
                self.assertEqual(child.stdout.read(), b"")

    def test_overall_deadline_interrupts_idle_and_synchronous_handler(self) -> None:
        child = self.start(wall=0.2)
        child.wait(timeout=2)
        self.assertEqual(child.returncode, 124)
        result = self.run_harness(frame(request()), mode="slow", wall=0.2)
        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_malformed_frames_and_json_are_terminal_generic_denials(self) -> None:
        raw = json.dumps(request()).encode()
        malformed = [
            struct.pack("!I", 0), struct.pack("!I", MAX_REQUEST_FRAME_BYTES + 1),
            b"\x00", struct.pack("!I", 100) + b"{}",
            frame(raw[:-1] + b',"id":"' + b"b" * 32 + b'"}'),
            frame(b'{"schemaVersion":NaN}'), frame(b"[" * 40 + b"0" + b"]" * 40),
            frame({**request(), "hostPath": "/private/fixture"}),
        ]
        for content in malformed:
            with self.subTest(content=content[:60]):
                result = self.run_harness(content)
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertEqual(responses(result.stdout), [ERROR_RESPONSE])
                self.assertEqual(result.stderr, b"")

    def test_response_schema_and_exceptions_do_not_leak_host_details(self) -> None:
        for mode in ("leak", "exception"):
            result = self.run_harness(frame(request()), mode=mode)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(responses(result.stdout), [ERROR_RESPONSE])
            self.assertNotIn(b"never-emit-host-private-details", result.stdout + result.stderr)
        with self.assertRaises(RelayError):
            response_frame({"schemaVersion": True, "error": "artifact admission denied"})

    def test_output_budget_and_request_count_are_enforced(self) -> None:
        result = self.run_harness(frame(request()), output=64)
        self.assertEqual(result.returncode, 64)
        self.assertLessEqual(len(result.stdout), 64)
        self.assertEqual(responses(result.stdout), [ERROR_RESPONSE])
        result = self.run_harness(frame(request()) + frame(request("b" * 32)), count=1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(responses(result.stdout)), 1)

    def test_stdout_backpressure_has_a_write_deadline(self) -> None:
        if not hasattr(fcntl, "F_SETPIPE_SZ"):
            self.skipTest("requires Linux pipe capacity control in the isolated runner")
        content = b"".join(frame(request("%032x" % index)) for index in range(256))
        source = self.scratch / "requests.bin"
        source.write_bytes(content)
        with source.open("rb") as handle:
            child = subprocess.Popen(self.command(count=256, wall=3, write=0.1), stdin=handle, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.scratch, env=self.environment())
        self.addCleanup(self.stop, child)
        fcntl.fcntl(child.stdout.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        child.wait(timeout=2)
        self.assertEqual(child.returncode, 124)
        self.assertLessEqual(len(child.stdout.read()), 4096)
        self.assertEqual(child.stderr.read(), b"")


if __name__ == "__main__":
    unittest.main()
