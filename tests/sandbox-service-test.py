#!/usr/bin/env python3
"""Real account-private job RPC, client provenance plumbing and replay fences."""
from __future__ import annotations

import copy
import contextlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "bin")]
from startup_factory_cli.execution_backend import GuestCommand, LaunchScope, parse_profile
from startup_factory_cli.sandbox_deployment import canonical_bytes
from startup_factory_cli.sandbox_registry import SandboxRegistry
import sandbox_client as client
import sandbox_service as service

DIGEST = "sha256:" + "a" * 64


class FakeExecutor:
    def __init__(self, profile):
        self.profile = profile
        self.calls = 0
        self.cancels = []
        self.hold = False
        self.started = threading.Event()

    def run(self, request, channel, cancel):
        self.calls += 1
        self.started.set()
        binding = {"schemaVersion": 1, "backend": "docker-sandboxes", "namespace": "sf-test",
            "name": "sf-" + "1" * 32, "sandboxId": "02418900-048d-44e9-86dc-9e036e546554",
            "createdAt": "2026-11-17T10:08:29+01:00", "generation": "gen-" + "2" * 32,
            "epoch": 1, "profileDigest": self.profile.digest, "policyDigest": self.profile.policy_digest,
            "image": self.profile.image, "inputDigest": DIGEST, "baseCommit": "1" * 40,
            "state": "ready", "acceptedCommit": None, "acceptedTree": None, "acceptedExportDigest": None}
        if self.hold:
            if not cancel.wait(3):
                raise AssertionError("disconnected native client did not cancel independently")
            self.cancels.append(request.id)
            raise service.ServiceError("cancelled")
        response = channel.request("bound", binding=binding, relayContext=None)
        if response["raw"] != b"ack":
            raise AssertionError("bound generation not acknowledged")
        channel.diagnostic(b"fixture task output\n")
        channel.emit("progress", stage="test", message="fixture progress")
        return {"schemaVersion": 1, "jobId": request.id, "exitCode": 0,
                "status": "validated", "binding": binding, "promotionReceipt": None,
                "diagnosticDigest": service.sha(b"fixture task output\n")}

    def close(self):
        pass


class SandboxServiceTest(unittest.TestCase):
    def setUp(self):
        # Keep real AF_UNIX sockets and derived publication locators under a
        # short protected account root, independent of checkout/TMPDIR length.
        self.temp = tempfile.TemporaryDirectory(prefix="sf-rpc-",
            dir=os.environ.get("SF_REGISTRY_TEST_ROOT", str(Path.home())))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.repo = self.root / "repo"; self.repo.mkdir(mode=0o700)
        self.workspace_root = self.repo / ".teamwork"; self.workspace_root.mkdir(mode=0o700)
        self.workspace = self.workspace_root / "team-one"; self.workspace.mkdir(mode=0o700)
        self.jobs = self.root / "jobs"; self.jobs.mkdir(mode=0o700)
        self.profile = parse_profile(json.dumps({"schemaVersion": 1, "backend": "docker-sandboxes",
            "protocolVersion": 1, "controllerUid": os.geteuid(), "sbxPath": "/opt/sbx",
            "sbxSha256": "a" * 64, "namespace": "sf-test", "image": "registry.example.com/factory/agent@" + DIGEST,
            "guestWorkdir": "/workspace/project", "limits": {"cpus": 1, "memoryMiB": 512,
                "rootDiskMiB": 512, "dockerDiskMiB": 512, "wallSeconds": 5, "maxOutputBytes": 1048576},
            "policyDigest": DIGEST, "qualificationDigest": DIGEST}).encode())
        self.deployment = SimpleNamespace(controller_uid=os.geteuid(), controller_gid=os.getegid(),
            job_root=str(self.jobs), socket_path=str(self.root / "s"), profile_path="/opt/profile.json",
            registry_root=str(self.root / "registry"), source_path=Path("/opt/deployment.json"),
            max_active_jobs=1, max_queued_jobs=4, job_request_max_bytes=256*1024,
            digest=DIGEST, projects=({"projectId": service.project_id(self.repo), "repository": str(self.repo),
                "workspaceRoot": str(self.workspace_root)},))
        self.executor = FakeExecutor(self.profile)
        self.server = service.JobServer(self.deployment, self.executor)
        self.thread = threading.Thread(target=self.server.serve, daemon=True); self.thread.start()
        self.assertTrue(self.server._ready.wait(2), "job server did not start listening")
        self.addCleanup(self.finish)

    def finish(self):
        self.server.stop(); self.thread.join(timeout=2); self.server.close()

    def request(self, number=1):
        value = {"schemaVersion": 1, "id": "job-" + f"{number:032x}",
            "deploymentDigest": self.deployment.digest, "profileDigest": self.profile.digest,
            "kind": "validation", "repository": str(self.repo), "workspace": str(self.workspace),
            "scope": LaunchScope(service.project_id(self.repo), "team-one", "FEATURE-1", "validator", "-", 0).as_dict(),
            "baseCommit": "1" * 40, "targetRef": "refs/heads/validation/candidate",
            "guestCommand": GuestCommand(("/usr/bin/true",)).as_dict(), "promptHex": "",
            "capabilityId": None, "transport": None, "executionSha256": None}
        raw = canonical_bytes(value)
        path = self.jobs / (value["id"] + ".request.json")
        path.write_bytes(raw); path.chmod(0o600)
        return value, path, service.sha(raw)

    def run_client(self, path, diagnostic=None):
        with mock.patch.object(client, "load_profile", return_value=self.profile), mock.patch.object(client, "verify_deployment"):
            return client.run_client(self.deployment, path, diagnostic=diagnostic)

    def test_real_socket_roundtrip_bound_ack_logs_and_exact_result_replay(self):
        value, path, _digest = self.request()
        output = []
        result = self.run_client(path, output.append)
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(b"".join(output), b"fixture task output\n")
        self.assertEqual(self.executor.calls, 1)
        self.assertEqual(self.run_client(path), result)
        self.assertEqual(self.executor.calls, 1, "completed intent must never execute again")
        self.assertEqual(Path(self.deployment.socket_path).stat().st_mode & 0o777, 0o600)

    def test_disconnect_cancels_without_waiting_for_guest_output(self):
        value, path, digest = self.request()
        self.executor.hold = True
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect(self.deployment.socket_path)
        service.send(connection, {"schemaVersion": 1, "operation": "job.run", "jobId": value["id"], "requestDigest": digest})
        self.assertEqual(service.receive(connection)["operation"], "accepted")
        self.assertTrue(self.executor.started.wait(1))
        connection.close()
        deadline = time.monotonic() + 2
        while not self.executor.cancels and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(self.executor.cancels, [value["id"]])
        with self.assertRaises(service.ServiceError):
            self.run_client(path)
        self.assertEqual(self.executor.calls, 1)

    def test_changed_approved_request_cannot_use_completed_result_or_rerun(self):
        value, path, _digest = self.request()
        self.run_client(path)
        value["guestCommand"] = GuestCommand(("/usr/bin/false",)).as_dict()
        path.write_bytes(canonical_bytes(value))
        with self.assertRaises(service.ServiceError):
            self.run_client(path)
        self.assertEqual(self.executor.calls, 1)

    def test_schema_refuses_host_selectors_tokens_unknown_versions_and_stale_bindings(self):
        value, path, _digest = self.request()
        for field, changed in (("schemaVersion", True), ("profileDigest", "sha256:" + "b"*64),
            ("deploymentDigest", "sha256:" + "b"*64), ("kind", "host-command"),
            ("workspace", str(self.root)), ("targetRef", "HEAD"), ("capabilityId", "cap-" + "1"*32)):
            malformed = copy.deepcopy(value); malformed[field] = changed
            with self.subTest(field=field), self.assertRaises((service.ServiceError, ValueError)):
                service.JobRequest.parse(canonical_bytes(malformed), self.deployment, self.profile)
        for field in ("env", "credentials", "hostCommand", "socketPath"):
            malformed = copy.deepcopy(value); malformed[field] = "untrusted"
            with self.subTest(field=field), self.assertRaises(service.ServiceError):
                service.JobRequest.parse(canonical_bytes(malformed), self.deployment, self.profile)

    def test_symlink_and_group_readable_job_requests_fail_before_dispatch(self):
        value, path, _digest = self.request()
        path.chmod(0o640)
        with self.assertRaises(service.ServiceError):
            self.run_client(path)
        path.chmod(0o600); original = self.jobs / "original"; path.rename(original); path.symlink_to(original)
        with self.assertRaises(OSError):
            self.run_client(path)
        self.assertEqual(self.executor.calls, 0)

    def test_framing_rejects_duplicate_keys_oversize_and_truncated_payloads(self):
        for raw in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"x":1e999}'):
            left, right = socket.socketpair()
            try:
                left.sendall(struct.pack("!I", len(raw)) + raw)
                with self.assertRaises(ValueError):
                    service.receive(right)
            finally:
                left.close(); right.close()
        left, right = socket.socketpair()
        try:
            left.sendall(struct.pack("!I", service.MAX_RPC_BYTES + 1))
            with self.assertRaises(service.ServiceError):
                service.receive(right)
        finally:
            left.close(); right.close()

    def test_receive_uses_one_deadline_for_a_dribbling_frame(self):
        left, right = socket.socketpair()
        def dribble():
            try:
                for byte in struct.pack("!I", 2) + b"{}":
                    left.sendall(bytes([byte])); time.sleep(.025)
            except OSError:
                pass
        writer = threading.Thread(target=dribble, daemon=True)
        try:
            with mock.patch.object(service, "RPC_SECONDS", .07):
                writer.start()
                start = time.monotonic()
                with self.assertRaises((socket.timeout, service.ServiceError)):
                    service.receive(right)
                self.assertLess(time.monotonic() - start, .3)
        finally:
            right.close(); writer.join(1); left.close()

    def test_shutdown_cancels_active_job_before_closing_shared_resources(self):
        value, path, _digest = self.request()
        self.executor.hold = True
        failures = []
        def invoke():
            try:
                self.run_client(path)
            except (service.ServiceError, EOFError):
                failures.append(True)
        worker = threading.Thread(target=invoke, daemon=True); worker.start()
        self.assertTrue(self.executor.started.wait(1))
        self.server.stop(); self.thread.join(2); self.server.close(); worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.executor.cancels, [value["id"]])
        self.assertTrue(failures)
        self.assertFalse(self.server._workers)

    def test_queued_job_has_an_absolute_deadline_even_with_a_live_peer(self):
        value, _path, digest = self.request()
        self.executor.profile = SimpleNamespace(digest=self.profile.digest, limits=SimpleNamespace(wall_seconds=.05))
        self.server._active_slots = SimpleNamespace(acquire=lambda **kwargs: time.sleep(.005) or False)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(self.deployment.socket_path)
            service.send(connection, {"schemaVersion": 1, "operation": "job.run", "jobId": value["id"], "requestDigest": digest})
            self.assertEqual(service.receive(connection)["operation"], "accepted")
            service.send(connection, {"schemaVersion": 1, "operation": "heartbeat"})
            start = time.monotonic()
            while True:
                message = service.receive(connection)
                if message["operation"] == "error":
                    break
            self.assertLess(time.monotonic() - start, 1)
            self.assertEqual(self.executor.calls, 0)
        finally:
            connection.close()

    def test_publication_transport_is_derived_from_exact_capability_and_lifecycle_root(self):
        value, _path, _digest = self.request()
        lifecycle = self.root / "lifecycle"; lifecycle.mkdir(mode=0o700)
        self.deployment.lifecycle_root = str(lifecycle)
        value.update(kind="gate", capabilityId="cap-" + "3" * 32,
            scope=LaunchScope(service.project_id(self.repo), "team-one", "FEATURE-1", "team-lead", "T-1", 1).as_dict())
        supervisor = service._load("_sf_test_supervisor", ROOT / "bin/publication-supervisor.py")
        value["transport"] = supervisor.transport_locator(str(self.repo), value["capabilityId"], str(lifecycle))
        self.assertEqual(service.JobRequest.parse(canonical_bytes(value), self.deployment, self.profile).value, value)
        for transport in (str(lifecycle / "arbitrary.sock"), value["transport"] + "x"):
            bad = dict(value, transport=transport)
            with self.assertRaises(service.ServiceError):
                service.JobRequest.parse(canonical_bytes(bad), self.deployment, self.profile)


class NativeExecutorIntegrationTest(unittest.TestCase):
    """Only authority/VM execution are mocks; raw Git/import/projection are real."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sf-native-rpc-",
            dir=os.environ.get("SF_REGISTRY_TEST_ROOT", str(Path.home())))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.repo = self.root / "repo"; self.repo.mkdir(mode=0o700)
        self.environment = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        self.git("init", "-q", "-b", "main")
        (self.repo / "file.txt").write_bytes(b"original\n")
        self.git("add", "file.txt"); self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.workspace = self.repo / ".teamwork/team-one"
        self.executions = self.workspace / "executions"; self.executions.mkdir(mode=0o700, parents=True)
        self.key = service.task_key("T-1")
        self.ref = "refs/heads/agent-task/team-one/" + self.key
        self.worktree = self.workspace / "worktrees" / ("backend#1-" + self.key)
        self.worktree.parent.mkdir(mode=0o700)
        self.git("worktree", "add", "-qb", self.ref[len("refs/heads/"):], str(self.worktree), self.base)
        self.profile = parse_profile((ROOT / "config/sandbox.config.example.json").read_bytes())
        from startup_factory_cli.sandbox_network_policy import parse_network_policy
        self.network_policy = parse_network_policy(canonical_bytes({"schemaVersion": 1, "namespace": self.profile.namespace,
            "preset": "deny-all", "provider": "openai", "rules": [{"host": "api.openai.com:443", "method": "POST", "path": "/v1/responses"}]}))
        self.profile = parse_profile(canonical_bytes({**self.profile.as_dict(), "policyDigest": self.network_policy.digest}))
        self.registry_root = self.root / "registry"; self.registry_root.mkdir(mode=0o700)
        self.registry = SandboxRegistry(self.registry_root, self.profile.namespace); self.addCleanup(self.registry.close)
        with self.registry.locked() as tx:
            self.epoch = tx.takeover()
        self.scope = LaunchScope(service.project_id(self.repo), "team-one", "F-1", "backend", "T-1", 1)
        self.record = service.expected_execution_identity({"schemaVersion": 1, "role": "backend", "attempt": 1},
            workspace=self.workspace, team="team-one", feature="F-1", task="T-1", key=self.key)
        self.record.update(claimLineage={}, lineageDigest=DIGEST)
        path = self.executions / (self.key + ".json"); path.write_bytes(canonical_bytes(self.record)); path.chmod(0o600)
        (self.workspace / "tasks.json").write_bytes(canonical_bytes({"featureId": "F-1", "tasks": [{"taskId": "T-1", "title": "Implement",
            "status": "Active", "comments": [{"body": "Human clarification: retain binary data", "author": "human"}]}]}))
        self.deployment = SimpleNamespace(registry_root=str(self.registry_root), receipt_path="/protected/receipt.json",
            bundle_root=str(ROOT), digest=DIGEST)
        self.executor = service.NativeJobExecutor.__new__(service.NativeJobExecutor)
        self.executor.deployment = self.deployment; self.executor.profile = self.profile; self.executor.registry = self.registry
        self.executor.credentials = SimpleNamespace(assert_ready=mock.Mock()); self.executor.controller = object(); self.executor.programs = object()
        self.executor.network_policy = self.network_policy  # Actual Docker activation remains a fixture seam.
        self.executor._scope_lock = threading.Lock(); self.executor._scopes = set()
        self.executor._monitors = set(); self.executor._uncertain = threading.Event()
        self.executor.watchdog = mock.Mock(); self.executor.custody = mock.Mock()
        self.executor.validate_request = mock.Mock()
        self.value = {"schemaVersion": 1, "id": "job-" + "7" * 32, "deploymentDigest": DIGEST,
            "profileDigest": self.profile.digest, "kind": "task", "repository": str(self.repo), "workspace": str(self.workspace),
            "scope": self.scope.as_dict(), "baseCommit": self.base, "targetRef": self.ref,
            "guestCommand": GuestCommand(("/usr/bin/true",)).as_dict(), "promptHex": "",
            "capabilityId": "cap-" + "8" * 32, "transport": "/fixed-native-locator", "executionSha256": service.sha(canonical_bytes(self.record))}
        # Explicit fixture-only authority. Real operations use protected native
        # capabilities, task holds, enrollment, custody and watchdog evidence.
        self.authority = mock.patch.object(service, "task_authority", lambda request: contextlib.nullcontext())
        self.authority.start(); self.addCleanup(self.authority.stop)
        self.current = mock.patch.object(service, "assert_current", return_value=dict(self.record))
        self.current.start(); self.addCleanup(self.current.stop)
        self.policy = mock.patch.object(service, "publication_policy", return_value=(("review-request", (None, "Review")),))
        self.policy.start(); self.addCleanup(self.policy.stop)

    def git(self, *args, path=None):
        return subprocess.check_output(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(path or self.repo), *args],
            env=self.environment, stderr=subprocess.PIPE, timeout=5).decode().strip()

    def _runner(self, *, fail_readonly=False):
        import sandbox_artifacts as artifacts
        from sandbox_jobs import JobResult
        from host_git import object_id
        owner = self
        class Runner:
            def __init__(self, controller, git, programs, **callbacks):
                self.git, self.callbacks = git, callbacks
                owner.assertIs(callbacks["network_policy"], owner.network_policy)
            def run(self, job):
                owner.job = job
                with owner.registry.locked() as tx:
                    row = tx.reserve(job.scope.as_dict(), epoch=owner.epoch)
                    row = tx.bind(row["name"], row["generation"], owner.epoch,
                        sandbox_id="02418900-048d-44e9-86dc-9e036e546554", created_at="2026-11-17T10:08:29+01:00")
                    row = tx.transition(row["name"], row["generation"], owner.epoch, state="ready")
                binding = {"schemaVersion": 1, "backend": "docker-sandboxes", "namespace": owner.profile.namespace,
                    **{key: row[key] for key in ("name", "generation", "epoch", "sandboxId", "createdAt")},
                    "profileDigest": owner.profile.digest, "policyDigest": owner.profile.policy_digest, "image": owner.profile.image,
                    "inputDigest": DIGEST, "baseCommit": job.base_commit, "state": "ready",
                    "acceptedCommit": None, "acceptedTree": None, "acceptedExportDigest": None}
                self.callbacks["on_bound"](binding, None)
                content = b"accepted replacement\n"
                entries = self.git.entries(job.base_commit); entries["file.txt"] = ("100644", object_id("blob", content))
                manifest = {"schemaVersion": 1, "id": "9" * 32, "baseCommit": job.base_commit,
                    "resultingTree": artifacts.tree_objects(entries)[0], "changes": [{"operation": "replace", "path": "file.txt",
                        "mode": "100644", "size": len(content), "sha256": service.sha(content)}]}
                receipt = None
                if job.collect_changes:
                    with artifacts.ArtifactStore(self.git, self.callbacks["quarantine_root"], assignment_digest=DIGEST,
                            target_ref=job.target_ref, expected_base=job.base_commit) as store:
                        receipt = store.collect(manifest, {service.sha(content): content})
                with owner.registry.locked() as tx:
                    for state in ("running", "collecting", "work-complete", "fenced", "stopping", "stopped", "removing", "removed"):
                        observation = {"sandboxId": row["sandboxId"], "createdAt": row["createdAt"], "state": "absent"} if state in {"stopped", "removed"} else None
                        tx.transition(row["name"], row["generation"], owner.epoch, state=state, observation=observation)
                return JobResult("collected", 0, dict(binding, state="removed"), receipt, DIGEST, DIGEST)
        return Runner

    def test_real_import_materialization_private_receipt_and_v2_projection(self):
        import sandbox_jobs
        from sandbox_acceptance import AcceptanceStore
        request = service.JobRequest(canonical_bytes(self.value), self.value)
        channel = mock.Mock(); channel.request.return_value = {"raw": b"ack"}
        with mock.patch.object(sandbox_jobs, "SandboxJobRunner", self._runner()):
            answer = self.executor.run(request, channel, threading.Event())
        self.executor.credentials.assert_ready.assert_called_once()
        self.assertEqual(answer["status"], "imported")
        self.assertEqual(self.git("rev-parse", self.ref), answer["binding"]["acceptedCommit"])
        self.assertEqual((self.worktree / "file.txt").read_bytes(), b"accepted replacement\n")
        self.assertEqual(self.git("status", "--porcelain", path=self.worktree), "")
        self.assertEqual((self.repo / "file.txt").read_bytes(), b"original\n")
        projection = json.loads((self.executions / (self.key + ".json")).read_bytes())
        self.assertEqual(projection["schemaVersion"], 2)
        self.assertEqual(projection["sandbox"], answer["binding"])
        receipt = AcceptanceStore(self.registry).verify(self.scope, answer["binding"])
        self.assertEqual(receipt["schemaVersion"], 2)
        self.assertEqual(receipt["deploymentDigest"], self.deployment.digest)
        context = json.loads(dict(self.job.context_files)["task-context.json"])
        self.assertIn("Human clarification", context["task"]["comments"][0]["body"])
        self.assertFalse(self.job.verify_unchanged)

    def test_fresh_doctor_needs_no_execution_or_task_hold_directory(self):
        import sandbox_jobs
        (self.executions / (self.key + ".json")).unlink(); self.executions.rmdir()
        value = dict(self.value, kind="doctor", capabilityId=None, transport=None, executionSha256=None,
            scope=LaunchScope(self.scope.project_id, "team-one", "F-1", "doctor", "-", 0).as_dict())
        request = service.JobRequest(canonical_bytes(value), value)
        channel = mock.Mock(); channel.request.return_value = {"raw": b"ack"}
        self.policy.stop()
        self.authority.stop()
        with mock.patch.object(sandbox_jobs, "SandboxJobRunner", self._runner()):
            answer = self.executor.run(request, channel, threading.Event())
        self.assertEqual(answer["exitCode"], 0)
        self.assertIsNone(answer["promotionReceipt"])
        self.assertFalse(self.job.collect_changes)
        self.assertFalse(self.job.allowed_artifacts)
        self.assertFalse(self.executions.exists())

    def test_preclaim_transaction_creates_fixed_lock_directory_but_no_execution_authority(self):
        (self.executions / (self.key + ".json")).unlink(); self.executions.rmdir()
        request = service.JobRequest(canonical_bytes(self.value), self.value)
        self.authority.stop()
        with mock.patch.object(service, "authority_lock", lambda repository: contextlib.nullcontext()):
            with service.task_authority(request):
                self.assertEqual({path.name for path in self.executions.iterdir()}, {"." + self.key + ".transaction.lock"})
        for path in self.executions.iterdir(): path.unlink()
        self.executions.rmdir(); self.executions.symlink_to(self.root)
        with mock.patch.object(service, "authority_lock", lambda repository: contextlib.nullcontext()), self.assertRaises(ValueError):
            with service.task_authority(request):
                self.fail("symlink execution control directory was adopted")

    def test_reviewer_context_rebuilds_latest_diff_and_keeps_human_history(self):
        self.test_real_import_materialization_private_receipt_and_v2_projection()
        from delivery_profile import build_review_package
        import team_policy
        accepted = json.loads((self.executions / (self.key + ".json")).read_bytes())["sandbox"]["acceptedCommit"]
        package, base, head = build_review_package(self.repo, "T-1", self.base, accepted)
        body = ("[review-request]\nHuman clarification and evidence remain required.\n"
            f"Review-Base-Commit: {base}\nTask-Branch-Head: {head}\nReview-Package-SHA256: {service.sha(package)}\nReview-Gates: none\n")
        snapshot = {"featureId": "F-1", "tasks": [{"taskId": "T-1", "status": "Review", "comments": [
            {"body": "Human clarification before implementation"}, {"body": body}]}]}
        (self.workspace / "tasks.json").write_bytes(canonical_bytes(snapshot))
        value = dict(self.value, kind="review", baseCommit=accepted, executionSha256=None,
            scope=LaunchScope(self.scope.project_id, "team-one", "F-1", "custom-qa", "T-1", 1).as_dict())
        request = service.JobRequest(canonical_bytes(value), value)
        real_open = service.open_directory
        with mock.patch.object(service, "open_directory", side_effect=lambda path, **kwargs: real_open(path)):
            with self.registry.locked() as tx:
                files, binding = self.executor._context(request, service.HostGit(self.repo), tx)
            context = json.loads(dict(files)["task-context.json"])
            self.assertEqual(context["task"]["comments"], snapshot["tasks"][0]["comments"])
            self.assertEqual(dict(files)["review.diff"], package)
            self.assertEqual(binding["head"], accepted)
            protocol = "\n".join(("PROTOCOL_TEAM_LEAD=custom-lead", "PROTOCOL_PRINCIPAL_ARCHITECT=custom-architect",
                "PROTOCOL_SCEPTICAL_ARCHITECT=custom-sceptic", "PROTOCOL_SECURITY_REVIEWER=custom-security", "PROTOCOL_QA=custom-qa"))
            self.policy.stop()
            with mock.patch.object(team_policy, "load_team_policy", return_value=SimpleNamespace(text=protocol)):
                grants = dict(service.publication_policy(request, ROOT))
            self.assertIn("review-approval", grants)
            self.assertIn("review-findings", grants)
            for denied in ("team-lead-approval", "architecture-approval", "security-approval", "production-approval", "deployment", "resume-plan", "review-request"):
                self.assertNotIn(denied, grants)
            snapshot["tasks"][0]["comments"][-1]["body"] = body.replace(service.sha(package), "sha256:" + "b" * 64)
            (self.workspace / "tasks.json").write_bytes(canonical_bytes(snapshot))
            with self.registry.locked() as tx, self.assertRaises(service.ServiceError):
                self.executor._context(request, service.HostGit(self.repo), tx)

    def test_resume_barrier_requires_role_filtered_comment_only_gate_marker(self):
        value = dict(self.value, kind="gate", scope=LaunchScope(self.scope.project_id, "team-one", "F-1", "team-lead", "T-1", 1).as_dict())
        request = service.JobRequest(canonical_bytes(value), value)
        holds = SimpleNamespace(check=lambda args: 0 if args.marker in service.RESUME_MARKERS else 3)
        cap = {"team": "team-one", "featureId": "F-1", "role": "team-lead", "executionKind": "gate", "taskId": "-", "attempt": 0}
        # Use the actual helper, overriding only the protected capability/hold IO.
        self.current.stop()
        with mock.patch.object(service, "_load", return_value=holds), mock.patch.object(service, "active_record", return_value=cap):
            self.assertIsNone(service.assert_current(request, allowed_artifacts=(("resume-plan", (None,)),)))
            for allowed in ((), (("resume-plan", ("Review",)),), (("team-lead-approval", (None,)),)):
                with self.assertRaises(service.ServiceError):
                    service.assert_current(request, allowed_artifacts=allowed)

    def test_product_context_binds_canonical_anchor_and_current_feature_commit(self):
        from product_acceptance import request_payload
        snapshot = {"featureId": "F-1", "tasks": [{"taskId": "T-1", "status": "Ready to deploy", "comments": [{"body": "Customer condition"}]}]}
        (self.workspace / "tasks.json").write_bytes(canonical_bytes(snapshot))
        product = request_payload(snapshot, feature_id="F-1", commit=self.base, integration_evidence_digest=DIGEST, reason="fixture")
        (self.workspace / "product-acceptance-request.json").write_bytes(canonical_bytes(product))
        self.git("update-ref", "refs/heads/team-one", self.base)
        value = dict(self.value, kind="gate", executionSha256=None,
            scope=LaunchScope(self.scope.project_id, "team-one", "F-1", "team-lead", "T-1", 1).as_dict())
        request = service.JobRequest(canonical_bytes(value), value)
        real_open = service.open_directory
        with mock.patch.object(service, "open_directory", side_effect=lambda path, **kwargs: real_open(path)):
            with self.registry.locked() as tx:
                files, _binding = self.executor._context(request, service.HostGit(self.repo), tx, (("product-approval", (None,)),))
            packet = json.loads(dict(files)["task-context.json"])
            self.assertEqual(packet["productAcceptanceRequest"]["canonicalBody"], product["canonicalBody"])
            product["canonicalBody"] += "modified"
            (self.workspace / "product-acceptance-request.json").write_bytes(canonical_bytes(product))
            with self.registry.locked() as tx, self.assertRaises(RuntimeError):
                self.executor._context(request, service.HostGit(self.repo), tx, (("product-approval", (None,)),))

    def test_resume_context_uses_authenticated_fixed_generation_and_full_snapshots(self):
        holds = service._load("_sf_test_context_holds", ROOT / "bin/task-hold.py")
        task = {"taskId": "T-1", "title": "Human update", "status": "Planned", "comments": [{"id": "c1", "body": "Complete human clarification"}]}
        snapshot = {"featureId": "F-1", "tasks": [task]}
        (self.workspace / "tasks.json").write_bytes(canonical_bytes(snapshot))
        blocked_task = dict(task, status="Blocked", title="Original requirement")
        blocked, resumed = holds.full_snapshot("F-1", blocked_task), holds.full_snapshot("F-1", task)
        # Observation time can differ without changing current task material.
        resumed["capturedAt"] = "2000-01-01T00:00:00+00:00"
        directory = self.workspace / "holds" / self.key / "generation-1"; directory.mkdir(parents=True, mode=0o700)
        entry = {"taskId": "T-1", "state": "resume-review-pending", "generation": 1, "holdId": "hold-" + "a" * 32,
            "blockedSnapshotPath": str(directory / "blocked-snapshot.json"), "blockedSnapshotDigest": holds.digest(blocked),
            "resumeSnapshotPath": str(directory / "resume-snapshot.json"), "resumeSnapshotDigest": holds.digest(resumed),
            "resumeRequestPath": str(directory / "resume-review-request.md"), "previousWorktreeClean": True,
            "blockedCommunicationDigest": holds.communication_digest(blocked_task), "resumeCommunicationDigest": holds.communication_digest(task)}
        resume_request = {"schemaVersion": 1, "taskId": "T-1", "holdId": entry["holdId"],
            "blockedCommunicationDigest": entry["blockedCommunicationDigest"], "currentCommunicationDigest": entry["resumeCommunicationDigest"]}
        for name, data in (("blocked-snapshot.json", blocked), ("resume-snapshot.json", resumed), ("resume-review-request.json", resume_request)):
            (directory / name).write_bytes(canonical_bytes(data))
        value = dict(self.value, kind="gate", executionSha256=None,
            scope=LaunchScope(self.scope.project_id, "team-one", "F-1", "team-lead", "T-1", 1).as_dict())
        request = service.JobRequest(canonical_bytes(value), value)
        real_open = service.open_directory
        with mock.patch.object(service, "open_directory", side_effect=lambda path, **kwargs: real_open(path)), \
                mock.patch.object(service, "_load", return_value=holds), \
                mock.patch.object(holds, "protected_hold_authority", return_value=object()), \
                mock.patch.object(holds, "load_protected_registry", return_value={"tasks": {self.key: entry}}), \
                mock.patch.object(holds, "authenticated_resolution_comment_ids", return_value=set()):
            with self.registry.locked() as tx:
                files, _binding = self.executor._context(request, service.HostGit(self.repo), tx, (("resume-plan", (None,)),))
            packet = json.loads(dict(files)["task-context.json"])
            self.assertEqual(packet["resumeReview"]["blockedSnapshot"], blocked)
            self.assertEqual(packet["resumeReview"]["currentSnapshot"], resumed)
            self.assertEqual(packet["task"]["comments"], task["comments"])
            entry["blockedSnapshotPath"] = str(self.root / "unapproved.json")
            with self.registry.locked() as tx, self.assertRaises(service.ServiceError):
                self.executor._context(request, service.HostGit(self.repo), tx, (("resume-plan", (None,)),))

    def test_native_shutdown_uncertainty_is_reported_after_all_resources_are_closed(self):
        resources = [SimpleNamespace(close=mock.Mock()) for _ in range(4)]
        resources[1].close.side_effect = RuntimeError("fixture uncertain native history")
        self.executor.credentials, self.executor.custody, self.executor.watchdog, self.executor.registry = resources
        with self.assertRaises(service.ServiceError):
            self.executor.close()
        for resource in resources:
            resource.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
