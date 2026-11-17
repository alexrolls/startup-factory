#!/usr/bin/env python3
"""Job transfer fixtures; run only in a bounded offline nonroot runner.

Fake VM paths are mapped into this test's private scratch directory. Actual
bootstrap, guest bridge/client, export, raw Git and bounded native pipes run;
no Docker, tracker, credential or production authority is used.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "bin"), str(ROOT / "src")]
import sandbox_jobs as jobs  # noqa: E402
from sandbox_export import export_workspace, quiesce_agent  # noqa: E402
from sandbox_source import build_source_package, initialize_guest, parse_source_package, SourceError  # noqa: E402
from sandbox_artifacts import ArtifactLimits, ArtifactError  # noqa: E402
from sandbox_guest_review import bind_review  # noqa: E402
from review_evidence import request_binding, finalize_bound_approval  # noqa: E402
from startup_factory_cli.execution_backend import DockerProfile, GuestCommand, LaunchScope  # noqa: E402
from startup_factory_cli.sandbox_registry import SandboxRegistry  # noqa: E402
from startup_factory_cli.sandbox_controller import GenerationHandle  # noqa: E402
from startup_factory_cli.docker_backend import NativeSession, _OwnedProcess  # noqa: E402

ARTIFACT_FIXTURE = runpy.run_path(str(ROOT / "tests/sandbox-artifacts-test.py"), run_name="job_artifact_fixture")


def profile_data():
    return {"schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
        "controllerUid": 501, "sbxPath": "/opt/startup-factory/sbx", "sbxSha256": "2" * 64,
        "namespace": "sf-fixture", "image": "registry.example.com/factory/agent@sha256:" + "3" * 64,
        "guestWorkdir": "/workspace/project", "limits": {"cpus": 2, "memoryMiB": 4096,
        "rootDiskMiB": 16384, "dockerDiskMiB": 16384, "wallSeconds": 1800, "maxOutputBytes": 1048576},
        "policyDigest": "sha256:" + "4" * 64, "qualificationDigest": "sha256:" + "0" * 64}


def framed(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack("!I", len(raw)) + raw


def session(argv, *, cwd, environment, output=44 * 1024 * 1024):
    process = _OwnedProcess(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=cwd, env=environment, close_fds=True, start_new_session=True)
    return NativeSession(process, timeout=15, output_limit=output,
        input_limit=44 * 1024 * 1024, lease=contextlib.ExitStack())


class FakeVMController:
    def __init__(self, fixture):
        self.fixture = fixture
        self.profile = DockerProfile.from_dict(profile_data())
        self.root = fixture.scratch / "vm"
        self.root.mkdir(mode=0o700)
        self.app = self.root / "app"
        self.workspace = self.root / "workspace"
        registry = fixture.scratch / "registry"
        registry.mkdir(mode=0o700)
        self.registry = SandboxRegistry(registry, self.profile.namespace)
        fixture.addCleanup(self.registry.close)
        self.provisioner = jobs.StreamProvisioner()
        self.epoch = None
        self.watchdog = SimpleNamespace(binding=lambda _handle: {"deploymentPath": "/fixture/deployment.json", "leaseId": "1" * 32, "deadline": 2524608000})
        self.events = []
        self.sessions = []

    def start(self):
        with self.registry.locked() as transaction:
            self.epoch = transaction.takeover()
            self.enrollment = SimpleNamespace(registry_id=transaction.registry_id)

    def allocate(self, spec):
        self.command = spec.command
        with self.registry.locked() as transaction:
            record = transaction.reserve(spec.scope.as_dict(), epoch=self.epoch)
            self.record = transaction.bind(record["name"], record["generation"], self.epoch, sandbox_id=str(uuid.uuid4()), created_at="2026-11-17T12:00:00Z")
        self.events.append("allocate")
        return GenerationHandle(self.record["name"], self.record["generation"], self.epoch)

    def _identity(self, record):
        from startup_factory_cli.execution_backend import BackendIdentity
        return BackendIdentity(record["name"], record["sandboxId"], record["createdAt"])

    def _start(self, argv, *, cwd="/"):
        result = session(argv, cwd=cwd, environment={"PATH": "/usr/bin:/bin", "HOME": str(self.root),
            "TMPDIR": str(self.fixture.scratch), "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"})
        self.sessions.append(result)
        self.fixture.addCleanup(result.close)
        return result

    def open_provision_session(self, handle, command):
        self.events.append("provision")
        # This nonroot fixture cannot provision OS accounts or chown to the
        # production guest UID/GID2000. Map only fixed identity operations to
        # the actual test UID/GID; real provisioning remains a live VM gate.
        uid, gid = os.geteuid(), os.getegid()
        code = jobs.BOOTSTRAP.replace("initialize_agent_identity()", "None").replace(
            ",2000,2000", f",{uid},{gid}").replace("{0,2000}", "{0," + str(uid) + "}").replace(
            "'/opt/startup-factory'", repr(str(self.app))).replace("'/workspace'", repr(str(self.workspace))).replace(
            "'/home/sf-agent'", repr(str(self.root / "home")))
        return self._start([sys.executable, "-I", "-B", "-c", code])

    def install_credentials(self, handle, broker, lease):
        self.events.append("credential-set")
        return broker.install(self.profile, handle, self._identity(self.record),
            LaunchScope.from_dict(self.record["scope"]), lease=lease, permit=object())

    def remove_credentials(self, handle, broker, lease):
        self.events.append("credential-remove")
        return broker.remove(self.profile, handle, self._identity(self.record), lease, permit=object())

    def _transition(self, handle, state):
        with self.registry.locked() as transaction:
            transaction.transition(handle.name, handle.generation, handle.epoch, state=state)

    def complete_provision(self, handle, manifest, proof):
        self._transition(handle, "ready")

    def activate(self, handle):
        self.events.append("activate")
        self._transition(handle, "running")

    def open_session(self, handle):
        self.events.append("agent")
        argv = [value.replace(jobs.GUEST_BIN, str(self.app / "bin")).replace(jobs.GUEST_SOCKET, str(self.workspace / ".sf-agent/artifacts.sock")) for value in self.command.argv]
        if "--agent-uid" in argv:
            argv[argv.index("--agent-uid") + 1] = str(os.geteuid())
        return self._start(argv, cwd=self.workspace / "project")

    def begin_collection(self, handle):
        self._transition(handle, "collecting")

    def open_collection_session(self, handle, command):
        self.events.append("collect")
        self.collection_command = command
        code = """import json,struct,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]);from sandbox_export import export_workspace
value=export_workspace(Path(sys.argv[2]),Path(sys.argv[3]).read_bytes(),export_id=sys.argv[4])
raw=json.dumps(value,separators=(',',':')).encode();sys.stdout.buffer.write(struct.pack('!I',len(raw))+raw)
"""
        return self._start([sys.executable, "-I", "-B", "-c", code, str(self.app / "bin"),
            str(self.workspace / "project"), str(self.app / "input.json"), command.argv[-1]])

    def cancel(self, handle):
        self.events.append("cancel")
        for native in self.sessions:
            native.close()
        with self.registry.locked() as transaction:
            args = handle.name, handle.generation, handle.epoch
            transaction.fence(*args)
            observation = {"sandboxId": self.record["sandboxId"], "createdAt": self.record["createdAt"], "state": "absent"}
            transaction.transition(*args, state="stopping")
            transaction.transition(*args, state="stopped", observation=observation)
            transaction.transition(*args, state="removing")
            transaction.transition(*args, state="removed", observation=observation)


class SandboxJobTest(unittest.TestCase):
    for _method in ("fixture_git", "authority_lock", "authorize", "store", "manifest"):
        locals()[_method] = ARTIFACT_FIXTURE["ArtifactTests"].__dict__[_method]

    def setUp(self):
        # The shared raw-Git fixture normally permits checkout-local storage.
        # These tests also bind real guest sockets, so choose a short private
        # fixture root even when CI has a long checkout and TMPDIR.
        base = os.environ.get("SF_ARTIFACT_TEST_ROOT", os.environ.get("SF_REGISTRY_TEST_ROOT", str(Path.home())))
        with mock.patch.dict(os.environ, {"SF_ARTIFACT_TEST_ROOT": base}):
            ARTIFACT_FIXTURE["ArtifactTests"].setUp(self)

    def source(self):
        return build_source_package(self.base, self.git.read_object, contains_secret=lambda _text: False)

    def guest(self):
        parent = self.scratch / "guest"
        parent.mkdir(mode=0o700)
        destination = parent / "project"
        initialize_guest(self.source(), destination)
        return destination

    def test_export_collect_candidate_source_and_raw_task_ref_import(self):
        guest = self.guest()
        (guest / "hello.txt").write_bytes(b"changed\0\xff\n")
        packet = export_workspace(guest, self.source(), export_id="1" * 64)
        manifest, blobs = jobs.decode_export(framed(packet), base_commit=self.base, base_tree=self.git.commit_tree(self.base), limits=ArtifactLimits())
        store = self.store()
        receipt = store.collect(manifest, blobs)
        candidate = store.candidate_source(manifest["id"], contains_secret=lambda _text: False)
        base, tree, _objects, files = parse_source_package(candidate)
        self.assertEqual(base, receipt["commit"])
        self.assertEqual(tree, receipt["tree"])
        self.assertEqual(files["hello.txt"][2], b"changed\0\xff\n")
        self.assertEqual(self.git.read_ref(ARTIFACT_FIXTURE["TARGET"]), self.base)
        promoted = store.promote(manifest["id"])
        self.assertEqual(self.git.read_ref(ARTIFACT_FIXTURE["TARGET"]), promoted["commit"])
        self.assertEqual((self.repo / "hello.txt").read_bytes(), b"hello\n")

    def test_unchanged_export_is_still_an_authorized_unique_raw_commit(self):
        packet = export_workspace(self.guest(), self.source(), export_id="2" * 64)
        manifest, blobs = jobs.decode_export(framed(packet), base_commit=self.base, base_tree=self.git.commit_tree(self.base), limits=ArtifactLimits())
        self.assertEqual(manifest["changes"], [])
        store = self.store()
        receipt = store.collect(manifest, blobs)
        self.assertEqual(receipt["tree"], self.git.commit_tree(self.base))
        self.assertNotEqual(receipt["commit"], self.base)
        self.allowed = False
        with self.assertRaises(ArtifactError):
            store.promote(manifest["id"])

    def test_export_rejects_guest_links_and_reserved_control_paths(self):
        guest = self.guest()
        link = guest / "outside"
        link.symlink_to(self.scratch)
        with self.assertRaises(SourceError):
            export_workspace(guest, self.source(), export_id="3" * 64)
        link.unlink()
        control = guest / ".sf-control"
        control.mkdir()
        with self.assertRaises(SourceError):
            export_workspace(guest, self.source(), export_id="3" * 64)

    def test_export_packet_rejects_extra_authority_wrong_base_and_body(self):
        guest = self.guest()
        (guest / "hello.txt").write_bytes(b"change")
        packet = export_workspace(guest, self.source(), export_id="4" * 64)
        values = [{**packet, "hostPath": "/outside"},
                  {**packet, "manifest": {**packet["manifest"], "baseCommit": "0" * 40}},
                  {**packet, "blobs": {key: "00" for key in packet["blobs"]}}]
        for value in values:
            with self.subTest(value=str(value)[:80]), self.assertRaises((jobs.JobError, ArtifactError)):
                jobs.decode_export(framed(value), base_commit=self.base, base_tree=self.git.commit_tree(self.base), limits=ArtifactLimits())

    def test_binary_native_transfer_drains_both_pipes_and_acknowledges_real_eof(self):
        raw = b"\0\xffdata" * 50000
        code = "import sys,hashlib;data=sys.stdin.buffer.read();sys.stdout.write(hashlib.sha256(data).hexdigest());sys.stderr.write('diagnostic')"
        native = session([sys.executable, "-I", "-B", "-c", code], cwd=self.scratch, environment={"PATH": "/usr/bin:/bin"})
        self.addCleanup(native.close)
        status, output, errors = jobs._communicate(native, raw, maximum=128, deadline=time.monotonic() + 5)
        self.assertEqual(status, 0)
        self.assertEqual(output.decode(), hashlib.sha256(raw).hexdigest())
        self.assertEqual(errors, b"diagnostic")
        self.assertTrue(native._closed)

    def test_native_transfer_output_overflow_cancels_owned_process(self):
        native = session([sys.executable, "-I", "-B", "-c", "import os,time;os.write(1,b'x'*1000);time.sleep(30)"], cwd=self.scratch, environment={"PATH": "/usr/bin:/bin"})
        self.addCleanup(native.close)
        with self.assertRaises(jobs.JobError):
            jobs._communicate(native, b"", maximum=64, deadline=time.monotonic() + 5)
        self.assertIsNotNone(native.process.returncode)

    def runner(self, controller, *, on_state=lambda _value: None):
        programs = jobs.GuestPrograms(tuple((name, (ROOT / "bin" / name).read_bytes()) for name in sorted(jobs.PROGRAM_NAMES)))
        self.checkpoints, self.bindings = [], []
        def publish(raw):
            request = json.loads(raw)
            self.checkpoints.append(request)
            return json.dumps({"schemaVersion": 1, "id": request["id"], "operation": "artifact.submit", "entryId": "11111111-1111-4111-8111-111111111111", "status": "admitted"}).encode()
        return jobs.SandboxJobRunner(controller, self.git, programs, contains_secret=lambda _text: False,
            publish=publish, on_bound=lambda binding, context: self.bindings.append((binding, context)),
            on_state=on_state, quarantine_root=self.quarantine)

    def bound_job(self, agent):
        workspace = self.repo / ".teamwork/team-one"
        workspace.mkdir(parents=True)
        return jobs.BoundJob(self.repo, workspace,
            LaunchScope(jobs._sha(str(self.repo).encode()), "team-one", "FEATURE-1", "developer", "TASK-1", 1),
            self.base, ARTIFACT_FIXTURE["TARGET"], GuestCommand((sys.executable, "-I", "-B", str(agent))), b"fixture prompt\n",
            str(self.scratch / "p" / ("1" * 32)), (("task-complete", (None,)),), "sha256:" + "7" * 64)

    def test_job_bootstraps_runs_actual_bridge_checkpoints_and_quarantines_changes(self):
        controller = FakeVMController(self)
        agent = self.scratch / "agent.py"
        agent.write_text("""import os,pathlib,sys
assert not os.environ.get('STARTUP_FACTORY_OUTBOX_TRANSPORT')
assert not os.environ.get('STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET')
pathlib.Path('hello.txt').write_bytes(b'job changed\\n')
sys.path.insert(0,sys.argv[0].rsplit('/',1)[0]+'/vm/app/bin')
from sandbox_guest_client import submit
response=submit(os.environ['STARTUP_FACTORY_GUEST_SOCKET'],{'schemaVersion':1,'id':'a'*32,'operation':'artifact.submit','marker':'task-complete','bodyHex':b'[task-complete]\\njob fixture\\n'.hex(),'targetStatus':None})
assert response['status']=='admitted'
print('fixture agent finished',flush=True)
""")
        runner = self.runner(controller)
        result = runner.run(self.bound_job(agent))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.status, "collected")
        self.assertEqual(result.quarantine_receipt["kind"], "sandbox-quarantine")
        self.assertEqual(len(self.checkpoints), 1)
        self.assertEqual(self.bindings[0][0]["state"], "ready")
        self.assertEqual(self.bindings[0][1]["watchdog"]["leaseId"], "1" * 32)
        self.assertEqual(controller.events, ["allocate", "provision", "activate", "agent", "collect", "cancel"])
        self.assertEqual(self.git.read_ref(ARTIFACT_FIXTURE["TARGET"]), self.base)

    def test_native_state_callback_failure_cannot_skip_generation_cleanup(self):
        controller = FakeVMController(self)
        agent = self.scratch / "unused-agent.py"
        agent.write_text("raise SystemExit(0)\n")
        def fail(_binding):
            raise OSError("fixture client disconnected")
        runner = self.runner(controller, on_state=fail)
        with self.assertRaises(OSError):
            runner.run(self.bound_job(agent))
        self.assertEqual(controller.events[-1], "cancel")

    def test_no_publication_gate_job_streams_diagnostics_without_native_relay(self):
        controller = FakeVMController(self)
        agent = self.scratch / "doctor-agent.py"
        agent.write_text("print('doctor-fixture-token',flush=True)\n")
        runner = self.runner(controller)
        runner.publish = None
        logs = []
        runner.on_diagnostic = logs.append
        task = self.bound_job(agent)
        job = dataclasses.replace(task, scope=dataclasses.replace(task.scope, task_id="-", attempt=0),
            outbox_transport=None, allowed_artifacts=(), collect_changes=False)
        result = runner.run(job)
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.quarantine_receipt)
        self.assertIsNone(self.bindings[0][1])
        self.assertEqual(self.checkpoints, [])
        self.assertIn(b"doctor-fixture-token", b"".join(logs))
        self.assertNotIn("collect", controller.events)

    def test_readonly_check_rejects_changed_tracked_source_even_after_successful_exit(self):
        controller = FakeVMController(self)
        agent = self.scratch / "mutating-validator.py"
        agent.write_text("import pathlib\npathlib.Path('hello.txt').write_text('silently changed')\npathlib.Path('dir/keep.bin').unlink()\n")
        job = dataclasses.replace(self.bound_job(agent), outbox_transport=None,
            allowed_artifacts=(), collect_changes=False, verify_unchanged=True)
        with self.assertRaisesRegex(jobs.JobError, "tracked source"):
            self.runner(controller).run(job)
        self.assertIn("collect", controller.events)
        self.assertEqual(controller.events[-1], "cancel")
        self.assertEqual(self.git.read_ref(job.target_ref), self.base)

    def test_readonly_check_allows_bounded_untracked_build_outputs_without_import_receipt(self):
        controller = FakeVMController(self)
        agent = self.scratch / "readonly-validator.py"
        agent.write_text("import pathlib\npathlib.Path('build-output').write_text('generated')\n")
        job = dataclasses.replace(self.bound_job(agent), outbox_transport=None,
            allowed_artifacts=(), collect_changes=False, verify_unchanged=True)
        result = self.runner(controller).run(job)
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.quarantine_receipt, "read-only exports must never reach task import")
        self.assertRegex(result.verification_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertIn("--quiesce-agent", controller.collection_command.argv)
        self.assertEqual(controller.collection_command.argv[controller.collection_command.argv.index("--quiesce-agent") + 1], str(jobs.AGENT_UID))
        self.assertEqual(controller.events[-1], "cancel")

    def test_guest_process_retirement_requires_root_and_two_clean_pidfd_censuses(self):
        with mock.patch("sandbox_export.os.geteuid", return_value=1000):
            with self.assertRaises(SourceError):
                quiesce_agent(1000)
        with mock.patch("sandbox_export.os.geteuid", return_value=0), \
             mock.patch("sandbox_export.os.pidfd_open", create=True) as pidfd, \
             mock.patch("sandbox_export.signal.pidfd_send_signal", create=True) as signal_pidfd, \
             mock.patch("sandbox_export.time.monotonic", return_value=0), \
             mock.patch("sandbox_export.time.sleep"), \
             mock.patch("sandbox_export._retire_agent_processes", side_effect=[True, False, False]) as census:
            quiesce_agent(1000)
        self.assertEqual(census.call_count, 3)
        pidfd.assert_not_called(); signal_pidfd.assert_not_called()
        with mock.patch("sandbox_export.os.geteuid", return_value=0), \
             mock.patch("sandbox_export.os.pidfd_open", create=True), \
             mock.patch("sandbox_export.signal.pidfd_send_signal", create=True), \
             mock.patch("sandbox_export.time.monotonic", side_effect=[0, 0, 0, 2]), \
             mock.patch("sandbox_export.time.sleep"), \
             mock.patch("sandbox_export._retire_agent_processes", return_value=True):
            with self.assertRaises(SourceError):
                quiesce_agent(1000, seconds=1)

    def test_context_and_progress_are_fixed_scope_watchdog_authorized_operations(self):
        controller = FakeVMController(self)
        runner = self.runner(controller)
        runner.watchdog_verify = lambda *_args, **_kwargs: True
        context_calls, progress = [], []
        runner.context_read = lambda: context_calls.append(True) or {"task": {"title": "Approved fixture"}}
        runner.progress_report = lambda stage, message: progress.append((stage, message))
        handle = GenerationHandle("sf-" + "1" * 32, "gen-" + "2" * 32, 1)
        request = {"schemaVersion": 1, "id": "a" * 32, "operation": "context.read"}
        response = runner._local_request(request, handle)
        self.assertEqual(json.loads(response[4:])["context"]["task"]["title"], "Approved fixture")
        with self.assertRaises(jobs.JobError):
            runner._local_request({**request, "taskId": "OTHER"}, handle)
        runner._local_request({**request, "operation": "progress.report", "stage": "working", "message": "fixture"}, handle)
        self.assertEqual(progress, [("working", "fixture")])
        self.assertEqual(len(context_calls), 1)
        runner.watchdog_verify = lambda *_args, **_kwargs: False
        with self.assertRaises(jobs.JobError):
            runner._local_request(request, handle)
        self.assertEqual(len(context_calls), 1)

    def test_actual_guest_context_and_progress_clis_round_trip_without_publication(self):
        controller = FakeVMController(self)
        agent = self.scratch / "context-agent.py"
        agent.write_text("""import json,pathlib,subprocess,sys
tools=pathlib.Path(sys.argv[0]).parent/'vm/app/bin'
context=subprocess.check_output([sys.executable,'-I','-B',str(tools/'sandbox_guest_context.py')],timeout=5)
assert json.loads(context)['task']['title']=='Approved fixture'
subprocess.run([sys.executable,'-I','-B',str(tools/'sandbox_guest_progress.py'),'working','fixture update'],check=True,timeout=5)
print('local helper fixture finished',flush=True)
""")
        runner = self.runner(controller)
        runner.publish = None
        runner.watchdog_verify = lambda *_args, **_kwargs: True
        runner.context_read = lambda: {"task": {"title": "Approved fixture"}}
        progress = []
        runner.progress_report = lambda stage, message: progress.append((stage, message))
        task = self.bound_job(agent)
        task = dataclasses.replace(task, outbox_transport=None, allowed_artifacts=(), collect_changes=False)
        result = runner.run(task)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(self.checkpoints, [])
        self.assertEqual(progress, [("working", "fixture update")])

    def test_partial_model_credential_install_always_removes_before_vm_cleanup(self):
        controller = FakeVMController(self)
        agent = self.scratch / "unused-agent.py"
        agent.write_text("raise SystemExit(0)\n")
        calls = []
        lease = object()
        def prepare(*_args, **_kwargs):
            calls.append("prepared")
            return lease
        def install(*_args, **kwargs):
            self.assertIs(kwargs["lease"], lease)
            calls.append("partial-set")
            raise OSError("fixture scoped credential set response lost")
        def remove(*args, **kwargs):
            self.assertIs(args[-1], lease)
            calls.append("removed")
        runner = self.runner(controller)
        runner.credentials = SimpleNamespace(assert_ready=lambda: None, prepare=prepare, install=install, remove=remove)
        with self.assertRaises(OSError):
            runner.run(self.bound_job(agent))
        self.assertEqual(calls, ["prepared", "partial-set", "removed"])
        self.assertEqual(controller.events, ["allocate", "credential-set", "credential-remove", "cancel"])
        self.assertFalse(controller.app.exists(), "source must not transfer before model scope succeeds")

    def test_network_activation_precedes_credential_intent_and_guest_source(self):
        controller = FakeVMController(self)
        agent = self.scratch / "network-ordered-agent.py"
        agent.write_text("print('network ordering fixture')\n")
        policy, lease = object(), object()
        def network(handle, supplied):
            self.assertIs(supplied, policy)
            self.assertFalse(controller.app.exists())
            controller.events.append("policy-activate")
        controller.configure_network = network
        def prepare(*_args, **_kwargs):
            self.assertFalse(controller.app.exists())
            self.assertIn("policy-activate", controller.events)
            controller.events.append("credential-prepare")
            return lease
        runner = self.runner(controller)
        runner.network_policy = policy
        runner.credentials = SimpleNamespace(assert_ready=lambda: None, prepare=prepare,
            install=lambda *_args, **_kwargs: None, remove=lambda *_args, **_kwargs: None)
        job = dataclasses.replace(self.bound_job(agent), outbox_transport=None, allowed_artifacts=(), collect_changes=False)
        self.assertEqual(runner.run(job).exit_code, 0)
        self.assertLess(controller.events.index("policy-activate"), controller.events.index("credential-prepare"))
        self.assertLess(controller.events.index("credential-prepare"), controller.events.index("credential-set"))
        self.assertLess(controller.events.index("credential-set"), controller.events.index("provision"))

    def test_network_activation_failure_cleans_vm_before_any_source_or_model_intent(self):
        controller = FakeVMController(self)
        agent = self.scratch / "unstarted-network-agent.py"
        agent.write_text("raise AssertionError('must not run')\n")
        def fail(*_args):
            raise OSError("fixture effective policy did not match")
        controller.configure_network = fail
        runner = self.runner(controller); runner.network_policy = object()
        prepare = mock.Mock()
        runner.credentials = SimpleNamespace(assert_ready=lambda: None, prepare=prepare)
        with self.assertRaises(OSError): runner.run(self.bound_job(agent))
        prepare.assert_not_called()
        self.assertFalse(controller.app.exists())
        self.assertEqual(controller.events, ["allocate", "cancel"])

    def test_model_credential_remove_failure_cannot_skip_vm_cleanup(self):
        controller = FakeVMController(self)
        agent = self.scratch / "unused-agent.py"
        agent.write_text("raise SystemExit(0)\n")
        lease = object()
        def install(*_args, **_kwargs):
            raise OSError("fixture partial set")
        def remove(*_args, **_kwargs):
            raise ValueError("fixture remove uncertain")
        runner = self.runner(controller)
        runner.credentials = SimpleNamespace(assert_ready=lambda: None, prepare=lambda *_args, **_kwargs: lease, install=install, remove=remove)
        with self.assertRaises(ValueError):
            runner.run(self.bound_job(agent))
        self.assertEqual(controller.events[-1], "cancel")

    def test_readonly_review_context_is_streamed_and_bound_into_input_digest(self):
        controller = FakeVMController(self)
        agent = self.scratch / "review-context-agent.py"
        agent.write_text("""import pathlib,stat,sys
root=pathlib.Path(sys.argv[0]).parent/'vm/app/context'
assert (root/'review.diff').read_bytes()==b'approved raw diff\\n'
assert stat.S_IMODE((root/'review.diff').stat().st_mode)==0o444
""")
        runner = self.runner(controller)
        task = self.bound_job(agent)
        contexts = (("review.diff", b"approved raw diff\n"), ("task-context.json", b'{"task":"fixture"}'))
        task = dataclasses.replace(task, outbox_transport=None, allowed_artifacts=(), collect_changes=False, context_files=contexts)
        result = runner.run(task)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.binding["inputDigest"], jobs.input_digest(self.source(), contexts))
        self.assertNotEqual(result.binding["inputDigest"], jobs.input_digest(self.source(), (("review.diff", b"different"),)))
        with self.assertRaises(jobs.JobError):
            dataclasses.replace(task, context_files=(("../outside", b"no"),))

    def test_guest_approval_binding_is_accepted_by_the_real_native_body_validator(self):
        request = "[review-request]\nFiles: none\nReview-Base-Commit: " + "a" * 40 + "\nTask-Branch-Head: " + "b" * 40 + "\nReview-Package-SHA256: sha256:" + "c" * 64 + "\n"
        binding = request_binding(request)
        draft = b"[architecture-approval]\nFiles: none\nApproved fixture\n"
        body = bind_review(draft, binding)
        finalized = finalize_bound_approval(body.decode(), request, "principal-architect", "gate:principal-architect")
        self.assertIn("Reviewer-Role: principal-architect", finalized)
        self.assertIn("Review-Request-SHA256: " + binding["requestDigest"], finalized)
        self.assertEqual(bind_review(body, binding), body)

    def workflow_fixture(self, *, validation_code=0, scanner=lambda _text: False):
        guest = self.guest()
        (guest / "hello.txt").write_bytes(b"workflow candidate\n")
        packet = export_workspace(guest, self.source(), export_id="5" * 64)
        manifest, blobs = jobs.decode_export(framed(packet), base_commit=self.base, base_tree=self.git.commit_tree(self.base), limits=ArtifactLimits())
        store = self.store()
        quarantine = store.collect(manifest, blobs)
        agent = self.scratch / "workflow-agent.py"
        agent.write_text("raise SystemExit(0)\n")
        task = self.bound_job(agent)
        image = "registry.example.com/approved/kit@sha256:" + "8" * 64
        initial_binding = {"generation": "gen-" + "1" * 32, "image": image,
                           "inputDigest": jobs._sha(self.source()), "state": "work-complete"}
        task_result = jobs.JobResult("collected", 0, initial_binding, quarantine,
            ARTIFACT_FIXTURE["ASSIGNMENT"], "sha256:" + "9" * 64)
        observed, accepted = [], []
        def factory(job):
            def run(selected):
                if selected.scope.role == "developer":
                    return task_result
                self.assertEqual(self.git.read_ref(task.target_ref), quarantine["commit"], "checks must use host-accepted task ref")
                observed.append(selected.scope.role)
                return jobs.JobResult("collected", validation_code if selected.scope.role == "validator" else 0,
                    {"generation": "gen-" + ("2" if selected.scope.role == "reviewer" else "3") * 32,
                     "image": image, "inputDigest": jobs._sha(selected.source_package)}, None,
                    selected.assignment_digest, "sha256:" + "a" * 64)
            return SimpleNamespace(run=run, contains_secret=scanner)
        workflow = jobs.SandboxWorkflow(factory,
            promotion_store=lambda _job, _result: self.store(),
            record_acceptance=lambda binding, receipt, evidence: accepted.append((binding, receipt, evidence)))
        def check(role):
            def make(source, binding):
                return dataclasses.replace(task, scope=dataclasses.replace(task.scope, role=role),
                    base_commit=binding["acceptedCommit"], source_package=source, collect_changes=False)
            return make
        return workflow, task, check("reviewer"), check("validator"), observed, accepted

    def test_workflow_imports_task_ref_then_runs_fresh_review_and_native_validations(self):
        workflow, task, review, validate, observed, accepted = self.workflow_fixture()
        result = workflow.run(task, review_job_factory=review, validation_job_factories=(validate,))
        self.assertEqual(observed, ["reviewer", "validator"])
        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0][0]["state"], "accepted")
        self.assertEqual(accepted[0][2]["kind"], "structural-source-import")
        self.assertFalse(result["codeApproved"])
        self.assertFalse(result["featureIntegrated"])
        self.assertEqual(self.fixture_git("rev-parse", "refs/heads/main").strip().decode(), self.base)

    def test_native_validation_failure_does_not_become_code_approval(self):
        workflow, task, review, validate, observed, accepted = self.workflow_fixture(validation_code=7)
        with self.assertRaisesRegex(jobs.JobError, "independent check failed"):
            workflow.run(task, review_job_factory=review, validation_job_factories=(validate,))
        self.assertEqual(observed, ["reviewer", "validator"])
        self.assertEqual(len(accepted), 1, "structural import remains distinct from approval")
        self.assertEqual(self.fixture_git("rev-parse", "refs/heads/main").strip().decode(), self.base)

    def test_workflow_cannot_reuse_task_agent_as_its_own_reviewer(self):
        workflow, task, review, validate, observed, accepted = self.workflow_fixture()
        def self_review(source, binding):
            return dataclasses.replace(task, base_commit=binding["acceptedCommit"], source_package=source, collect_changes=False)
        with self.assertRaisesRegex(jobs.JobError, "independent check differs"):
            workflow.run(task, review_job_factory=self_review, validation_job_factories=(validate,))
        self.assertEqual(observed, [])


if __name__ == "__main__":
    unittest.main()
