#!/usr/bin/env python3
"""Real-entry tests for the secret-free publication supervisor."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))
from outbox_capability import (  # noqa: E402
    CapabilityError,
    mint,
    request_signature,
    verify_entry,
    verify_published_entry,
)
from review_evidence import (  # noqa: E402
    bind_approval_request,
    bind_request,
    latest_review_request,
)
SUPERVISOR_SPEC = importlib.util.spec_from_file_location(
    "publication_supervisor", BIN / "publication-supervisor.py"
)
assert SUPERVISOR_SPEC is not None and SUPERVISOR_SPEC.loader is not None
SUPERVISOR = importlib.util.module_from_spec(SUPERVISOR_SPEC)
sys.modules[SUPERVISOR_SPEC.name] = SUPERVISOR
SUPERVISOR_SPEC.loader.exec_module(SUPERVISOR)
transport_locator = SUPERVISOR.transport_locator


TEAM = "transport-team"
FEATURE = ".workspace/task-manager/feature.md"
ROLE = "principal-architect"
INSTANCE = "gate:principal-architect"
BODY = b"[architecture-approval]\ntransport fixture\n"
BODY_DIGEST = "sha256:" + hashlib.sha256(BODY).hexdigest()


class PublicationSupervisorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.workspace = self.repository / ".teamwork" / TEAM
        self.workspace.mkdir(parents=True)
        subprocess.run(
            ["git", "init", "-q", str(self.repository)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Darwin AF_UNIX paths are short.  Production requires an external,
        # protected lifecycle root too, so use a private short home-directory
        # fixture instead of weakening the locator length check.
        self.lifecycle = Path(
            tempfile.mkdtemp(prefix=".sf-lifecycle-test-", dir=Path.home())
        ).resolve()
        self.addCleanup(shutil.rmtree, self.lifecycle, True)
        self.lifecycle.chmod(0o700)
        subprocess.run(
            [
                sys.executable,
                str(BIN / "process-lifecycle.py"),
                "init",
                "--root",
                str(self.lifecycle),
                "--repo",
                str(self.repository),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.capability = self.mint_gate()
        self.locator = transport_locator(
            str(self.repository), self.capability["id"], str(self.lifecycle)
        )
        self.entry = {
            "schemaVersion": 1,
            "id": "entry-transport",
            "team": TEAM,
            "featureId": FEATURE,
            "taskId": FEATURE + "#1",
            "attempt": 1,
            "actor": ROLE,
            "marker": "architecture-approval",
            "bodyPath": str(self.root / "body.md"),
            "targetStatus": None,
            "phase": "pending",
            "createdAt": "2026-09-19T12:00:00Z",
        }

    def mint_gate(self) -> dict:
        return mint(
            str(self.repository),
            str(self.workspace),
            TEAM,
            FEATURE,
            ROLE,
            "gate",
            "-",
            0,
            INSTANCE,
        )

    def client_script(self, *, wait: bool = False, denial: bool = False) -> Path:
        script = self.root / ("client-%s-%s.py" % (wait, denial))
        script.write_text(
            """import json, os, pathlib, sys, time
sys.path.insert(0, sys.argv[1])
from outbox_capability import CapabilityError, request_signature
entry=json.loads(pathlib.Path(sys.argv[2]).read_text())
body=pathlib.Path(sys.argv[3]).read_bytes()
if any(os.environ.get(name) for name in (
    'STARTUP_FACTORY_OUTBOX_CAPABILITY_ID',
    'STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET',
    'STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT',
)):
    raise SystemExit(80)
if 'wait' in sys.argv[6]:
    while not pathlib.Path(sys.argv[5]).exists():
        time.sleep(0.01)
try:
    value=request_signature(os.environ['STARTUP_FACTORY_OUTBOX_TRANSPORT'], entry, body)
except CapabilityError:
    if 'deny' in sys.argv[6]:
        pathlib.Path(sys.argv[4]).write_text('denied\\n')
        raise SystemExit(0)
    raise
if 'deny' in sys.argv[6]:
    raise SystemExit(81)
pathlib.Path(sys.argv[4]).write_text(json.dumps(value, sort_keys=True))
""",
            encoding="utf-8",
        )
        return script

    def submit_client_script(self) -> Path:
        script = self.root / "submit-client.py"
        script.write_text(
            """import os, pathlib, subprocess, sys, time
for name in (
    'STARTUP_FACTORY_OUTBOX_CAPABILITY_ID',
    'STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET',
    'STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT',
):
    if os.environ.get(name):
        raise SystemExit(80)
subprocess.run([
    os.environ['TEST_SUBMIT_TOOL'], os.environ['STARTUP_FACTORY_TEAM'],
    os.environ['STARTUP_FACTORY_FEATURE_ID'], os.environ['TEST_TASK_ID'], '1',
    os.environ['STARTUP_FACTORY_ROLE'], os.environ.get('TEST_MARKER', 'design-note'),
    os.environ['TEST_BODY'], os.environ.get('TEST_TARGET', '-')
], check=True, stdout=subprocess.DEVNULL)
pathlib.Path(sys.argv[4]).write_text('queued\\n')
wait_file = os.environ.get('TEST_WAIT_FILE')
while wait_file and not pathlib.Path(wait_file).exists():
    time.sleep(0.01)
""",
            encoding="utf-8",
        )
        return script

    def install_markdown_fixture(self) -> tuple[Path, str, str]:
        install = self.repository / ".agent-squad"
        shutil.copytree(ROOT / "bin", install / "bin")
        shutil.copytree(ROOT / "config", install / "config")
        shutil.copytree(ROOT / "src", install / "src")
        feature = FEATURE
        task = feature + "#1"
        feature_path = self.repository / feature
        feature_path.parent.mkdir(parents=True)
        feature_path.write_text(
            """# Transport fixture [Active]

## 1 Final package [Active]

**Assignee:** backend
""",
            encoding="utf-8",
        )
        (install / "config" / "project-management.config.md").write_text(
            """```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
""",
            encoding="utf-8",
        )
        config_path = install / "config" / "team.config.md"
        config = config_path.read_text(encoding="utf-8")
        config, count = re.subn(
            r"(?m)^BROKER_LIFECYCLE_ROOT=.*$",
            'BROKER_LIFECYCLE_ROOT="%s"' % self.lifecycle,
            config,
        )
        self.assertEqual(1, count)
        config_path.write_text(config, encoding="utf-8")
        return install, feature, task

    def start(
        self,
        client: Path,
        output: Path,
        gate: Path,
        mode: str,
        *,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.Popen[bytes]:
        entry_path = self.root / "entry.json"
        body_path = self.root / "body.md"
        entry_path.write_text(json.dumps(self.entry), encoding="utf-8")
        body_path.write_bytes(BODY)
        # A test may launch successive exact generations.  Each launch needs a
        # fresh barrier; reusing a prior release file would let the next
        # supervisor race lifecycle registration and correctly fail closed.
        ready = self.root / ("wrapper-%s.ready" % output.name)
        release = self.root / ("wrapper-%s.go" % output.name)
        supervisor_barrier = self.lifecycle / (".launch-test-%s" % output.name)
        supervisor_barrier.mkdir(mode=0o700)
        supervisor_ready = supervisor_barrier / "supervisor.ready"
        wrapper = (
            "import os,pathlib,sys,time;"
            "os.setsid();pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));"
            "\nwhile not pathlib.Path(sys.argv[2]).exists(): time.sleep(0.01)\n"
            "os.execv(sys.argv[3],sys.argv[3:])"
        )
        command = [
            sys.executable,
            "-c",
            wrapper,
            str(ready),
            str(release),
            sys.executable,
            str(BIN / "publication-supervisor.py"),
            "run",
            "--repo",
            str(self.repository),
            "--workspace",
            str(self.workspace),
            "--handle",
            self.capability["id"],
            "--socket",
            self.locator,
            "--lifecycle-root",
            str(self.lifecycle),
            "--team",
            TEAM,
            "--category",
            "gate",
            "--instance",
            ROLE,
            "--ready-file",
            str(supervisor_ready),
            "--",
            sys.executable,
            str(client),
            str(BIN),
            str(entry_path),
            str(body_path),
            str(output),
            str(gate),
            mode,
        ]
        environment = dict(os.environ)
        environment["STARTUP_FACTORY_OUTBOX_TRANSPORT"] = self.locator
        environment.update(extra_environment or {})
        process = subprocess.Popen(
            command,
            cwd=self.repository,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop_process, process)
        self.wait_for(ready)
        pid = int(ready.read_text(encoding="utf-8"))
        subprocess.run(
            [
                sys.executable,
                str(BIN / "process-lifecycle.py"),
                "register",
                "--root",
                str(self.lifecycle),
                "--repo",
                str(self.repository),
                "--team",
                TEAM,
                "--category",
                "gate",
                "--instance",
                ROLE,
                "--kind",
                "background",
                "--pid",
                str(pid),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        release.touch()
        self.wait_for(supervisor_ready)
        return process

    @staticmethod
    def stop_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    @staticmethod
    def wait_for(path: Path) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.01)
        raise AssertionError("timed out waiting for %s" % path)

    def wait_for_socket(self) -> None:
        self.wait_for(Path(self.locator))

    def finish(self, process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(0, process.returncode, stderr.decode(errors="replace"))
        return stdout, stderr

    def test_ready_receipt_is_not_visible_until_its_write_completes(self) -> None:
        barrier = self.lifecycle / ".launch-ready-atomicity"
        barrier.mkdir(mode=0o700)
        ready = barrier / "supervisor.ready"
        pending = barrier / ".supervisor.ready.pending"
        writer_opened = threading.Event()
        release_writer = threading.Event()
        failures: list[BaseException] = []
        real_fdopen = SUPERVISOR.os.fdopen

        def delayed_fdopen(*args: object, **kwargs: object):
            writer_opened.set()
            if not release_writer.wait(2):
                raise RuntimeError("test did not release ready-receipt writer")
            return real_fdopen(*args, **kwargs)

        def publish() -> None:
            try:
                SUPERVISOR.publish_ready(
                    str(ready),
                    str(self.lifecycle),
                    capability_id=self.capability["id"],
                    supervisor_pid=123,
                    created_at="2026-09-21T00:00:00Z",
                    child=SUPERVISOR.ProcessIdentity(456, "start"),
                    endpoint_identity=(7, 8),
                )
            except BaseException as exc:  # surfaced on the test thread below
                failures.append(exc)

        with mock.patch.object(SUPERVISOR.os, "fdopen", side_effect=delayed_fdopen):
            writer = threading.Thread(target=publish)
            writer.start()
            self.assertTrue(writer_opened.wait(2))
            try:
                self.assertTrue(pending.exists())
                self.assertFalse(
                    ready.exists(),
                    "the launcher-visible receipt appeared before its write completed",
                )
            finally:
                release_writer.set()
                writer.join(2)

        self.assertFalse(writer.is_alive())
        self.assertEqual([], failures)
        self.assertFalse(pending.exists())
        receipt = json.loads(ready.read_bytes())
        self.assertEqual(self.capability["id"], receipt["capabilityId"])

    def test_ready_parent_can_be_retired_after_receipt_publication(self) -> None:
        barrier = self.lifecycle / ".launch-ready-retirement"
        barrier.mkdir(mode=0o700)
        ready = barrier / "supervisor.ready"
        receipt_published = threading.Event()
        barrier_retired = threading.Event()
        failures: list[BaseException] = []
        real_replace = SUPERVISOR.os.replace

        def delayed_replace(*args: object, **kwargs: object) -> None:
            real_replace(*args, **kwargs)
            receipt_published.set()
            if not barrier_retired.wait(2):
                raise RuntimeError("test did not retire ready-receipt directory")

        def publish() -> None:
            try:
                SUPERVISOR.publish_ready(
                    str(ready),
                    str(self.lifecycle),
                    capability_id=self.capability["id"],
                    supervisor_pid=123,
                    created_at="2026-09-21T00:00:00Z",
                    child=SUPERVISOR.ProcessIdentity(456, "start"),
                    endpoint_identity=(7, 8),
                )
            except BaseException as exc:  # surfaced on the test thread below
                failures.append(exc)

        with mock.patch.object(SUPERVISOR.os, "replace", side_effect=delayed_replace):
            writer = threading.Thread(target=publish)
            writer.start()
            try:
                self.assertTrue(receipt_published.wait(2))
                self.assertTrue(ready.exists())
                ready.unlink()
                barrier.rmdir()
            finally:
                barrier_retired.set()
                writer.join(2)

        self.assertFalse(writer.is_alive())
        self.assertEqual([], failures)
        self.assertFalse(barrier.exists())

    def test_worker_exec_waits_for_process_generation_identity(self) -> None:
        real_identity = SUPERVISOR.process_start_identity
        real_write = SUPERVISOR.os.write
        identity_captured = False
        gate_released = False

        def capture_identity(pid: int) -> str:
            nonlocal identity_captured
            value = real_identity(pid)
            identity_captured = True
            return value

        def observe_release(descriptor: int, value: bytes) -> int:
            nonlocal gate_released
            if value == b"1":
                self.assertTrue(
                    identity_captured,
                    "the worker exec gate opened before identity capture",
                )
                gate_released = True
            return real_write(descriptor, value)

        with mock.patch.object(
            SUPERVISOR, "process_start_identity", side_effect=capture_identity
        ), mock.patch.object(SUPERVISOR.os, "write", side_effect=observe_release):
            worker, identity = SUPERVISOR.spawn_identified_worker(["/usr/bin/true"])
        self.addCleanup(self.stop_process, worker)
        self.assertTrue(identity_captured)
        self.assertTrue(gate_released)
        self.assertEqual(identity.pid, worker.pid)
        self.assertEqual(0, worker.wait(timeout=2))

    def test_worker_exec_restores_popen_signal_defaults(self) -> None:
        worker, _identity = SUPERVISOR.spawn_identified_worker(
            ["/bin/sh", "-c", "kill -PIPE $$; exit 42"]
        )
        self.addCleanup(self.stop_process, worker)
        self.assertEqual(-signal.SIGPIPE, worker.wait(timeout=2))

    def test_worker_exec_failure_is_reported_after_identity_capture(self) -> None:
        missing = self.root / "missing-worker-command"
        with mock.patch.object(
            SUPERVISOR,
            "process_start_identity",
            wraps=SUPERVISOR.process_start_identity,
        ) as identity:
            with self.assertRaisesRegex(
                SUPERVISOR.SupervisorError,
                "worker command could not be executed",
            ):
                SUPERVISOR.spawn_identified_worker([str(missing)])
        identity.assert_called_once()

    def test_worker_gate_closes_first_pipe_if_status_pipe_fails(self) -> None:
        real_pipe = SUPERVISOR.os.pipe
        allocated: list[int] = []
        calls = 0

        def fail_second_pipe() -> tuple[int, int]:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected status-pipe failure")
            pair = real_pipe()
            allocated.extend(pair)
            return pair

        with mock.patch.object(SUPERVISOR.os, "pipe", side_effect=fail_second_pipe):
            with self.assertRaisesRegex(OSError, "injected status-pipe failure"):
                SUPERVISOR.spawn_identified_worker(["/usr/bin/true"])
        self.assertEqual(2, len(allocated))
        for descriptor in allocated:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_worker_receives_locator_only_and_published_proof_remains_auditable(self) -> None:
        output = self.root / "signature.json"
        process = self.start(self.client_script(), output, self.root / "unused", "run")
        self.finish(process)
        signed = dict(self.entry)
        signed["producerCapability"] = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            ROLE,
            verify_entry(
                str(self.repository), str(self.workspace), signed, BODY_DIGEST
            )["role"],
        )
        self.assertEqual(
            ROLE,
            verify_published_entry(
                str(self.repository), str(self.workspace), signed, BODY_DIGEST
            )["role"],
        )
        self.assertFalse(Path(self.locator).exists())

    def test_normal_exit_package_is_published_only_from_exact_admission(self) -> None:
        install, feature, task = self.install_markdown_fixture()
        body = self.root / "final.md"
        body.write_bytes(b"[design-note]\nfinal package from worker\n")
        output = self.root / "queued.txt"
        worker_release = self.root / "worker.release"
        environment = {
            "STARTUP_FACTORY_EXECUTION_KIND": "gate",
            "STARTUP_FACTORY_TEAM": TEAM,
            "STARTUP_FACTORY_FEATURE_ID": feature,
            "STARTUP_FACTORY_ROLE": ROLE,
            "STARTUP_FACTORY_TASK_ID": "-",
            "STARTUP_FACTORY_ATTEMPT": "0",
            "STARTUP_FACTORY_INSTANCE": self.capability["instance"],
            "STARTUP_FACTORY_CANONICAL_REPO": str(self.repository),
            "STARTUP_FACTORY_CANONICAL_WORKSPACE": str(self.workspace),
            "TEST_SUBMIT_TOOL": str(install / "bin" / "submit-artifact.sh"),
            "TEST_TASK_ID": task,
            "TEST_BODY": str(body),
            "TEST_WAIT_FILE": str(worker_release),
        }
        process = self.start(
            self.submit_client_script(),
            output,
            self.root / "unused",
            "submit",
            extra_environment=environment,
        )
        self.wait_for(output)
        self.assertEqual("queued\n", output.read_text(encoding="utf-8"))

        pending = sorted((self.workspace / "outbox" / "pending").glob("*.json"))
        self.assertEqual(1, len(pending))
        raw_producer = pending[0].read_bytes()
        queued = json.loads(raw_producer)
        self.assertEqual(self.capability["id"], queued["producerCapability"]["id"])
        copied = pending[0].with_name("copied-" + pending[0].name)
        copied.write_bytes(raw_producer)
        broker_environment = dict(os.environ)
        broker_environment["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = str(
            self.lifecycle
        )
        result = subprocess.run(
            [
                str(install / "bin" / "process-outbox.sh"),
                TEAM,
                feature,
                str(pending[0]),
            ],
            cwd=self.repository,
            env=broker_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        published = (self.repository / feature).read_text(encoding="utf-8")
        self.assertIn("> [design-note]", published)
        self.assertIn("> final package from worker", published)
        self.assertFalse(pending[0].exists())
        replay = subprocess.run(
            [
                str(install / "bin" / "process-outbox.sh"),
                TEAM,
                feature,
                str(copied),
            ],
            cwd=self.repository,
            env=broker_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, replay.returncode, replay.stderr)
        replayed = (self.repository / feature).read_text(encoding="utf-8")
        self.assertEqual(1, replayed.count("delivery-id:"))
        self.assertFalse(copied.exists())
        done = sorted((self.workspace / "outbox" / "done").glob("*.json"))
        self.assertEqual(1, len(done))
        completed = json.loads(done[0].read_text(encoding="utf-8"))
        protected_source = Path(completed["sourceEntryPath"])
        self.assertEqual(Path(completed["stagedBodyPath"]).parent, protected_source.parent)
        self.assertEqual(0o400, protected_source.stat().st_mode & 0o777)
        delivery_records = list(protected_source.parent.glob("*.entry.json"))
        self.assertEqual(1, len(delivery_records))
        admissions = self.repository / ".git" / "startup-factory-broker" / "outbox-admissions"
        receipts = sorted(admissions.glob("admission-*.json"))
        self.assertEqual(1, len(receipts))
        self.assertEqual(0o600, receipts[0].stat().st_mode & 0o777)

        # While the exact producer generation is still current, a raw pending
        # alias converges on the same protected delivery and is idempotent.
        done_digest = hashlib.sha256(done[0].read_bytes()).hexdigest()
        worker_release.touch()
        self.finish(process)
        tombstone = (
            self.repository
            / ".git"
            / "startup-factory-broker"
            / "outbox-revoked"
            / (self.capability["id"] + ".revoked")
        )
        self.assertTrue(tombstone.is_file())

        # JSON whitespace, key order, and pending basename are not package
        # identity.  Once the generation is revoked and D1 is published, a
        # semantically identical alias cannot consume its admission again.
        reserialized = pending[0].with_name("reserialized-alias.json")
        reordered = dict(reversed(list(queued.items())))
        reserialized.write_text(
            json.dumps(reordered, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        denied = subprocess.run(
            [
                str(install / "bin" / "process-outbox.sh"),
                TEAM,
                feature,
                str(reserialized),
            ],
            cwd=self.repository,
            env=broker_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(0, denied.returncode)
        self.assertIn("fenced producer package was already consumed", denied.stderr)
        self.assertFalse(reserialized.exists())
        self.assertEqual(1, len(list(protected_source.parent.glob("*.entry.json"))))
        self.assertEqual(1, len(list(admissions.glob("admission-*.json"))))
        self.assertEqual(1, len(list((self.workspace / "outbox" / "done").glob("*.json"))))
        self.assertEqual(done_digest, hashlib.sha256(done[0].read_bytes()).hexdigest())
        after_denial = (self.repository / feature).read_text(encoding="utf-8")
        self.assertEqual(1, after_denial.count("delivery-id:"))

    def test_delayed_approval_cannot_move_from_request_a_to_same_tree_head_b(self) -> None:
        install, feature, task = self.install_markdown_fixture()
        feature_path = self.repository / feature
        feature_path.write_text(
            feature_path.read_text(encoding="utf-8").replace(
                "## 1 Final package [Active]", "## 1 Final package [Review]"
            ),
            encoding="utf-8",
        )
        git = ["git", "-C", str(self.repository)]
        subprocess.run(git + ["config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(git + ["config", "user.name", "Fixture"], check=True)
        (self.repository / "README.fixture").write_text("base\n", encoding="utf-8")
        subprocess.run(git + ["add", "README.fixture"], check=True)
        subprocess.run(git + ["commit", "-qm", "base"], check=True)
        base = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
        (self.repository / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(git + ["add", "app.py"], check=True)
        subprocess.run(git + ["commit", "-qm", "request A"], check=True)
        head_a = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
        tree_a = subprocess.check_output(
            git + ["rev-parse", head_a + "^{tree}"], text=True
        ).strip()
        subprocess.run(git + ["commit", "--allow-empty", "-qm", "request B"], check=True)
        head_b = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
        tree_b = subprocess.check_output(
            git + ["rev-parse", head_b + "^{tree}"], text=True
        ).strip()
        self.assertNotEqual(head_a, head_b)
        self.assertEqual(tree_a, tree_b)
        self.assertEqual(
            ["app.py"],
            subprocess.check_output(
                git + ["diff", "--name-only", base, head_a], text=True
            ).splitlines(),
        )
        self.assertEqual(
            ["app.py"],
            subprocess.check_output(
                git + ["diff", "--name-only", base, head_b], text=True
            ).splitlines(),
        )

        tracker_environment = dict(os.environ)
        tracker_environment.update(
            {
                "TRACKER_ADAPTER": "Markdown",
                "TRACKER_PROJECT_ROOT": str(self.repository),
            }
        )
        tracker = install / "bin" / "tracker-ops.sh"

        def post_request(label: str, head: str) -> str:
            package = "sha256:" + hashlib.sha256(
                ("review-package-" + label + ":" + head).encode()
            ).hexdigest()
            request_file = self.root / ("request-" + label + ".md")
            request_file.write_text(
                bind_request(
                    "[review-request]\nFiles: app.py\n",
                    base,
                    head,
                    package,
                ),
                encoding="utf-8",
            )
            subprocess.run(
                [
                    str(tracker),
                    "comment-once",
                    task,
                    "delivery-request-" + label,
                    str(request_file),
                ],
                cwd=self.repository,
                env=tracker_environment,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            snapshot_file = self.root / ("snapshot-" + label + ".json")
            subprocess.run(
                [str(tracker), "export", feature, str(snapshot_file)],
                cwd=self.repository,
                env=tracker_environment,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            return latest_review_request(
                json.loads(snapshot_file.read_text(encoding="utf-8")), task
            )

        def submit_approval(label: str, request: str) -> Path:
            approval = self.root / ("approval-" + label + ".md")
            approval.write_text(
                bind_approval_request(
                    "[architecture-approval]\n"
                    "Files: app.py\n"
                    "verdict: approved-" + label + "\n\n"
                    "- principal-architect\n",
                    request,
                ),
                encoding="utf-8",
            )
            output = self.root / ("queued-" + label + ".txt")
            environment = {
                "STARTUP_FACTORY_EXECUTION_KIND": "gate",
                "STARTUP_FACTORY_TEAM": TEAM,
                "STARTUP_FACTORY_FEATURE_ID": feature,
                "STARTUP_FACTORY_ROLE": ROLE,
                "STARTUP_FACTORY_TASK_ID": "-",
                "STARTUP_FACTORY_ATTEMPT": "0",
                "STARTUP_FACTORY_INSTANCE": self.capability["instance"],
                "STARTUP_FACTORY_CANONICAL_REPO": str(self.repository),
                "STARTUP_FACTORY_CANONICAL_WORKSPACE": str(self.workspace),
                "TEST_SUBMIT_TOOL": str(install / "bin" / "submit-artifact.sh"),
                "TEST_TASK_ID": task,
                "TEST_BODY": str(approval),
                "TEST_MARKER": "architecture-approval",
            }
            process = self.start(
                self.submit_client_script(),
                output,
                self.root / ("unused-" + label),
                "submit-" + label,
                extra_environment=environment,
            )
            self.finish(process)
            pending = sorted((self.workspace / "outbox" / "pending").glob("*.json"))
            self.assertEqual(1, len(pending))
            return pending[0]

        broker_environment = dict(os.environ)
        broker_environment["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = str(
            self.lifecycle
        )

        request_a = post_request("a", head_a)
        pending_a = submit_approval("a", request_a)
        request_b = post_request("b", head_b)
        before = feature_path.read_text(encoding="utf-8")
        events = self.workspace / "events.ndjson"
        event_digest = hashlib.sha256(events.read_bytes()).hexdigest()
        publication_root = self.lifecycle / "broker-publications"
        publication_receipts = sorted(publication_root.glob("*.json"))
        denied = subprocess.run(
            [
                str(install / "bin" / "process-outbox.sh"),
                TEAM,
                feature,
                str(pending_a),
            ],
            cwd=self.repository,
            env=broker_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(0, denied.returncode)
        self.assertIn("producer binding does not match", denied.stderr)
        self.assertEqual(before, feature_path.read_text(encoding="utf-8"))
        self.assertNotIn("approved-a", feature_path.read_text(encoding="utf-8"))
        self.assertEqual(event_digest, hashlib.sha256(events.read_bytes()).hexdigest())
        self.assertEqual(publication_receipts, sorted(publication_root.glob("*.json")))

        self.capability = self.mint_gate()
        self.locator = transport_locator(
            str(self.repository), self.capability["id"], str(self.lifecycle)
        )
        pending_b = submit_approval("b", request_b)
        accepted = subprocess.run(
            [
                str(install / "bin" / "process-outbox.sh"),
                TEAM,
                feature,
                str(pending_b),
            ],
            cwd=self.repository,
            env=broker_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        published = feature_path.read_text(encoding="utf-8")
        self.assertNotIn("approved-a", published)
        self.assertEqual(1, published.count("approved-b"))
        self.assertGreater(
            len(list(publication_root.glob("*.json"))), len(publication_receipts)
        )

    def test_successor_fences_stale_supervisor_before_signing(self) -> None:
        output = self.root / "denial.txt"
        gate = self.root / "client.go"
        process = self.start(
            self.client_script(wait=True, denial=True), output, gate, "wait-deny"
        )
        self.wait_for_socket()
        successor = self.mint_gate()
        gate.touch()
        self.finish(process)
        self.assertEqual("denied\n", output.read_text(encoding="utf-8"))
        self.assertNotEqual(self.capability["id"], successor["id"])

    def test_peer_outside_registered_session_is_rejected(self) -> None:
        output = self.root / "client-finished.txt"
        gate = self.root / "finish.go"
        process = self.start(self.client_script(wait=True), output, gate, "wait")
        self.wait_for_socket()
        with self.assertRaises(CapabilityError):
            request_signature(self.locator, self.entry, BODY)
        gate.touch()
        self.finish(process)
        self.assertTrue(output.is_file())

    def test_removed_lifecycle_generation_denies_worker(self) -> None:
        output = self.root / "denial.txt"
        gate = self.root / "client.go"
        process = self.start(
            self.client_script(wait=True, denial=True), output, gate, "wait-deny"
        )
        self.wait_for_socket()
        lifecycle_records = list(self.lifecycle.rglob("*.json"))
        self.assertEqual(1, len(lifecycle_records))
        lifecycle_records[0].unlink()
        gate.touch()
        self.finish(process)
        self.assertEqual("denied\n", output.read_text(encoding="utf-8"))

    def test_cleanup_never_unlinks_a_replaced_endpoint(self) -> None:
        output = self.root / "client-finished.txt"
        gate = self.root / "finish.go"
        process = self.start(self.client_script(wait=True), output, gate, "wait")
        self.wait_for_socket()
        endpoint = Path(self.locator)
        endpoint.unlink()
        endpoint.write_text("replacement", encoding="utf-8")
        gate.touch()
        _stdout, stderr = process.communicate(timeout=10)
        self.assertNotEqual(0, process.returncode)
        self.assertIn("endpoint identity changed", stderr.decode(errors="replace"))
        self.assertEqual("replacement", endpoint.read_text(encoding="utf-8"))

    def test_transport_parser_rejects_duplicate_keys_and_trailing_bytes(self) -> None:
        frames = (
            b'{"schemaVersion":1,"schemaVersion":1,"entry":{},"bodyHex":"00"}',
            json.dumps(
                {"schemaVersion": 1, "entry": self.entry, "bodyHex": BODY.hex()},
                separators=(",", ":"),
            ).encode("utf-8") + b"x",
        )
        for index, payload in enumerate(frames):
            with self.subTest(index=index):
                reader, writer = socket.socketpair()
                self.addCleanup(reader.close)
                self.addCleanup(writer.close)
                if index == 0:
                    writer.sendall(struct.pack("!I", len(payload)) + payload)
                else:
                    writer.sendall(struct.pack("!I", len(payload) - 1) + payload)
                writer.shutdown(socket.SHUT_WR)
                with self.assertRaises(SUPERVISOR.SupervisorError):
                    SUPERVISOR.decode_request(reader, time.monotonic() + 1)

    @unittest.skipUnless(hasattr(socket, "SCM_RIGHTS"), "descriptor passing unavailable")
    def test_transport_parser_rejects_ancillary_data(self) -> None:
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        payload = b"{}"
        writer.sendmsg(
            [struct.pack("!I", len(payload)) + payload],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", read_fd))],
        )
        writer.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(
            SUPERVISOR.SupervisorError, "ancillary"
        ):
            SUPERVISOR.decode_request(reader, time.monotonic() + 1)

    def test_linux_peer_authentication_fails_without_accepted_socket_pidfd(self) -> None:
        class MissingPidfdSocket:
            def getsockopt(self, _level: int, option: int, _size: int) -> bytes:
                if option == SUPERVISOR.LINUX_SO_PEERCRED:
                    return struct.pack("3i", os.getpid(), os.geteuid(), os.getegid())
                raise OSError("SO_PEERPIDFD unavailable")

        with mock.patch.object(SUPERVISOR.sys, "platform", "linux"):
            with self.assertRaisesRegex(
                SUPERVISOR.SupervisorError,
                "accepted-socket Linux peer handles are unavailable",
            ):
                SUPERVISOR.peer_identity(MissingPidfdSocket())


if __name__ == "__main__":
    unittest.main(verbosity=2)
