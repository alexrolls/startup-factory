"""Native gate/custody tests: run only in the assigned isolated test runner.

No Docker, network or credentials are used. Protection checks alone are mocked
so read-only source fixtures and the runner's fixed Python can be exercised;
all process/pipe/session/fsync behavior in the handshake tests is real.
"""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import native_clients as native  # noqa: E402
from startup_factory_cli.execution_backend import DockerProfile  # noqa: E402

DIGEST = "sha256:" + "a" * 64
NAME = "sf-" + "1" * 32
GENERATION = "gen-" + "2" * 32
FIXTURE = '''import os,sys,time
operation=sys.argv[4]
if operation=='stop':
    print('started',flush=True)
    time.sleep(30)
elif operation=='exec' and sys.argv[-1]=='short':
    time.sleep(.25)
    print('executed',flush=True)
elif operation=='exec' and sys.argv[-1]=='echo':
    data=sys.stdin.buffer.read(5)
    sys.stdout.buffer.write(data)
    sys.stderr.buffer.write(b'fixture-stderr')
    sys.exit(7)
else:
    print('executed',flush=True)
'''

CRASH_CONTROLLER = '''import hashlib,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from startup_factory_cli import native_clients as n
from startup_factory_cli.execution_backend import DockerProfile
profile=DockerProfile.from_dict(json.loads(Path(sys.argv[3]).read_bytes()))
n.load_profile=lambda path:profile
def verify(pin,*,executable):
    raw=pin.path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=pin.sha256: raise n.NativeClientError('drift')
    return None if executable else raw
n._verify_pin=verify
tools_value=json.loads(sys.argv[4])
tools=n.GateTools(*[n.ProgramPin(Path(tools_value[key]['path']),tools_value[key]['sha256']) for key in ('python','gate','lifecycleHelper')])
j=n.NativeClientJournal(Path(sys.argv[2]),Path(sys.argv[3]),tools)
intent=n.NativeIntent(profile.namespace,'sf-'+'1'*32,'gen-'+'2'*32,1,'sha256:'+'a'*64,'open-session')
argv=(profile.sbx_path,'--app-name',profile.namespace,'--no-input','exec','-i','--user','root','--workdir',profile.guest_workdir,'--',intent.name,'/usr/bin/python3','short')
c=j.prepare(intent,argv)
if sys.argv[5]=='after': c.release()
print(json.dumps({'clientId':c.client_id,'pid':c.process.pid}),flush=True)
os._exit(0)
'''


def pin(path: Path) -> native.ProgramPin:
    return native.ProgramPin(path.resolve(), hashlib.sha256(path.read_bytes()).hexdigest())


def fixture_verify(selected: native.ProgramPin, *, executable: bool):
    """Test trust seam only; content hashes still checked before every launch."""
    raw = selected.path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != selected.sha256:
        raise native.NativeClientError("fixture digest drift")
    return None if executable else raw


class NativeClientsTest(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd()))
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-native-test-", dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name)
        self.path = self.scratch / "journal"
        self.path.mkdir(mode=0o700)
        self.sbx = self.scratch / "fixed-sbx"
        self.execution_marker = self.scratch / "execution-marker"
        self.sbx.write_text("#!" + str(Path(sys.executable).resolve()) + "\n"
                            + "open(" + repr(str(self.execution_marker)) + ",'ab').write(b'exec\\n')\n" + FIXTURE)
        self.sbx.chmod(0o700)
        self.profile = DockerProfile.from_dict({
            "schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
            "controllerUid": 501, "sbxPath": str(self.sbx), "sbxSha256": pin(self.sbx).sha256,
            "namespace": "sf-unit", "image": "docker.io/sbx/shell@sha256:" + "2" * 64,
            "guestWorkdir": "/workspace/project", "policyDigest": DIGEST,
            "qualificationDigest": "sha256:" + "b" * 64,
            "limits": {"cpus": 1, "memoryMiB": 512, "rootDiskMiB": 2048,
                       "dockerDiskMiB": 512, "wallSeconds": 30, "maxOutputBytes": 65536},
        })
        self.tools = native.GateTools(pin(Path(sys.executable)), pin(ROOT / "bin/sandbox-native-gate.py"),
                                      pin(ROOT / "bin/process-lifecycle.py"))
        self.profile_path = self.scratch / "profile.json"
        self.profile_path.write_text(json.dumps(self.profile.as_dict()))
        self.profile_patch = mock.patch.object(native, "load_profile", return_value=self.profile)
        self.pin_patch = mock.patch.object(native, "_verify_pin", side_effect=fixture_verify)
        self.profile_patch.start()
        self.pin_patch.start()
        self.addCleanup(self.profile_patch.stop)
        self.addCleanup(self.pin_patch.stop)
        self.journals = []
        self.addCleanup(self.cleanup_clients)

    def cleanup_clients(self):
        for journal in self.journals:
            try:
                journal.close()
            except native.NativeClientError:
                # close already attempts every safely owned child even if its
                # durable journal was intentionally poisoned by this test.
                for handle in journal._handles.values():
                    if handle.process.returncode is None:
                        handle._kill_owned()
                    handle._close_io()

    def journal(self):
        result = native.NativeClientJournal(self.path, self.profile_path, self.tools)
        if os.getpid() == 1:
            # A container's test runner can be PID 1; the existing production
            # lifecycle helper deliberately refuses PID 1. Only controller
            # metadata is synthetic here; every child identity remains real.
            identity = result._identity.process_identity
            result._identity.process_identity = lambda pid: "linux:fixture-controller:1" if pid == 1 else identity(pid)
        self.journals.append(result)
        return result

    def intent(self, operation="inspect"):
        return native.NativeIntent(self.profile.namespace, NAME, GENERATION, 1, DIGEST, operation)

    def argv(self, operation="inspect", mode="echo"):
        prefix = (str(self.sbx), "--app-name", self.profile.namespace, "--no-input")
        args = {"inspect": ("inspect", NAME, "--format", "json"), "stop": ("stop", NAME),
                "open-session": ("exec", "-i", "--user", "root", "--workdir", "/workspace/project",
                                 "--", NAME, "/usr/bin/python3", mode)}
        return prefix + args[operation]

    @staticmethod
    def state(journal, client_id):
        return next(value for value in journal.records() if value["clientId"] == client_id)

    def assert_closed(self, client):
        self.assertIsNotNone(client.process.returncode)
        self.assertTrue(all(stream.closed for stream in (client.stdin, client.stdout, client.stderr)))
        self.assertEqual((client._gate, client._status), (-1, -1))

    def test_pure_history_validator_checks_terminal_records_without_storage(self):
        journal = self.journal()
        client = journal.prepare(self.intent(), self.argv())
        client.abort_unreleased()
        state = json.loads((self.path / native.STATE_FILE).read_bytes())
        bindings = dict(profile_basis_digest=native.profile_basis_digest(self.profile),
                        tools_digest=native.canonical_digest(self.tools.as_dict()),
                        journal_id=state["journalId"], namespace=self.profile.namespace)
        with mock.patch.object(native, "load_profile", side_effect=AssertionError("no I/O")):
            checked = native.validate_native_history(state, **bindings)
            self.assertEqual(checked, state)
            checked["records"].clear()
            self.assertTrue(state["records"])
            for field, value in (("responseDigest", DIGEST), ("returncode", True),
                                 ("controllerStart", "linux:unknown-boot:1"), ("extra", "data")):
                bad = copy.deepcopy(state)
                bad["records"][client.client_id][field] = value
                with self.subTest(field=field), self.assertRaises(native.NativeClientError):
                    native.validate_native_history(bad, **bindings)
            bad = copy.deepcopy(state)
            bad["records"][client.client_id]["intent"]["namespace"] = "sf-other"
            with self.assertRaises(native.NativeClientError):
                native.validate_native_history(bad, **bindings)
            with self.assertRaises(native.NativeClientError):
                native.validate_native_history({"cycle": float("nan")}, **bindings)

    def test_intent_is_durable_before_popen_and_child_stays_paused(self):
        journal = self.journal()
        process = native._JournalProcess
        def launch(*args, **kwargs):
            records = journal.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["state"], "intent")
            self.assertIsNone(records[0]["native"])
            self.assertTrue(kwargs["start_new_session"])
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["cwd"], "/")
            self.assertNotIn("PYTHONPATH", kwargs["env"])
            return process(*args, **kwargs)
        with mock.patch.object(native, "_JournalProcess", side_effect=launch):
            client = journal.prepare(self.intent(), self.argv())
        record = self.state(journal, client.client_id)
        self.assertEqual(record["state"], "gated")
        self.assertEqual(record["native"]["processGroupId"], client.process.pid)
        self.assertEqual(record["native"]["sessionId"], client.process.pid)
        self.assertFalse(select.select([client.stdout], [], [], .05)[0])
        output = os.dup(client.stdout.fileno())
        try:
            client.abort_unreleased()
            self.assertEqual(os.read(output, 1024), b"")
        finally:
            os.close(output)
        self.assertEqual(client.process.returncode, 126)
        self.assertEqual(self.state(journal, client.client_id)["state"], "aborted-before-release")
        self.assert_closed(client)

    def test_release_intent_and_identity_are_persisted_before_release_byte(self):
        journal = self.journal()
        client = journal.prepare(self.intent(), self.argv())
        write = native._fd_write
        def checked(fd, raw, **kwargs):
            if raw == b"G":
                record = self.state(journal, client.client_id)
                self.assertEqual(record["state"], "release-intent")
                self.assertEqual(record["native"], client.native)
            return write(fd, raw, **kwargs)
        with mock.patch.object(native, "_fd_write", side_effect=checked):
            client.release()
        self.assertEqual(client.stdout.read(64), b"executed\n")
        self.assertEqual(client.finish(timeout=2), 0)
        self.assertEqual(self.state(journal, client.client_id)["state"], "client-exited")
        client.acknowledge(DIGEST)
        client.acknowledge(DIGEST)
        self.assertEqual(client.finish(timeout=1), 0)
        self.assertEqual(self.state(journal, client.client_id)["state"], "completed-acknowledged")
        with self.assertRaises(native.NativeClientError):
            client.acknowledge("sha256:" + "c" * 64)
        report = journal.recover()
        self.assertTrue(report["poolBlocked"])
        self.assertFalse(report["serverQuiescent"])
        self.assertFalse(report["qualified"])

    def test_binary_pipes_normal_exit_separate_from_ack(self):
        journal = self.journal()
        client = journal.spawn(self.intent("open-session"), self.argv("open-session"))
        client.stdin.write(b"a\x00\xffb\n")
        client.stdin.close()
        self.assertEqual(client.stdout.read(64), b"a\x00\xffb\n")
        self.assertEqual(client.stderr.read(64), b"fixture-stderr")
        self.assertEqual(client.finish(timeout=2), 7)
        self.assertIsNone(self.state(journal, client.client_id)["responseDigest"])
        self.assertEqual(self.state(journal, client.client_id)["state"], "client-exited")
        client.acknowledge(DIGEST)
        self.assert_closed(client)

    def test_cancel_owned_child_is_uncertain_and_cannot_ack(self):
        journal = self.journal()
        client = journal.spawn(self.intent("stop"), self.argv("stop"))
        self.assertEqual(client.stdout.readline(), b"started\n")
        with mock.patch.object(journal, "_snapshot", side_effect=native.NativeClientError("metadata vanished")):
            client.cancel()
        self.assert_closed(client)
        self.assertEqual(self.state(journal, client.client_id)["state"], "delivery-uncertain")
        with self.assertRaises(native.NativeClientError):
            client.acknowledge(DIGEST)

    def test_post_release_commit_failure_still_kills_and_reaps(self):
        journal = self.journal()
        client = journal.prepare(self.intent("stop"), self.argv("stop"))
        update = journal._update
        def fail_after_exec(client_id, **changes):
            if changes.get("state") == "exec-channel-open":
                journal._poisoned = True
                raise native.NativeClientError("simulated fsync uncertainty")
            return update(client_id, **changes)
        with mock.patch.object(journal, "_update", side_effect=fail_after_exec):
            with self.assertRaises(native.NativeClientError):
                client.release()
            with self.assertRaises(native.NativeClientError):
                client.cancel()
        self.assert_closed(client)
        self.assertLess(client.process.returncode, 0)

    def test_close_attempts_all_handles_despite_failed_journal(self):
        journal = self.journal()
        first = journal.spawn(self.intent("stop"), self.argv("stop"))
        second = journal.prepare(self.intent(), self.argv())
        journal._poisoned = True
        with self.assertRaises(native.NativeClientError):
            journal.close()
        self.assert_closed(first)
        self.assert_closed(second)

    def test_profile_change_does_not_block_same_owner_cleanup(self):
        journal = self.journal()
        client = journal.spawn(self.intent("stop"), self.argv("stop"))
        with mock.patch.object(native, "load_profile", side_effect=native.NativeClientError("profile changed")):
            with self.assertRaises(native.NativeClientError):
                client.cancel()
        self.assert_closed(client)

    def test_foreign_owner_or_changed_popen_pid_never_signals(self):
        journal = self.journal()
        client = journal.prepare(self.intent(), self.argv())
        with mock.patch.object(native.os, "getpid", return_value=os.getpid() + 1), mock.patch.object(native.os, "killpg") as kill:
            with self.assertRaises(native.NativeClientError):
                client.cancel()
            kill.assert_not_called()
        original_pid = client.process.pid
        try:
            client.process.pid += 1
            with mock.patch.object(native.os, "killpg") as kill:
                with self.assertRaises(native.NativeClientError):
                    client.cancel()
                kill.assert_not_called()
        finally:
            client.process.pid = original_pid
        client.abort_unreleased()

    def test_identity_change_before_release_refuses_exec(self):
        journal = self.journal()
        client = journal.prepare(self.intent(), self.argv())
        with mock.patch.object(journal, "_snapshot", return_value={**client.native, "processIdentity": "linux:other:1"}):
            with self.assertRaises(native.NativeClientError):
                client.release()
        self.assertFalse(client._released)
        client.abort_unreleased()

    def test_recovery_never_signals_even_matching_persisted_orphan(self):
        journal = self.journal()
        client = journal.prepare(self.intent(), self.argv())
        real_identity = journal._identity.process_identity
        def identities(pid):
            return None if pid == journal._pid else real_identity(pid)
        with mock.patch.object(journal._identity, "process_identity", side_effect=identities), mock.patch.object(journal._identity, "safe_signal_group") as signal_group, mock.patch.object(native.os, "killpg") as kill:
            report = journal.recover()
            signal_group.assert_not_called()
            kill.assert_not_called()
        self.assertEqual(report["observations"][0]["native"], "matching-orphan-uncertain")
        self.assertTrue(report["poolBlocked"])
        client.abort_unreleased()

    def test_missing_leader_recovery_only_probes_group_existence_and_stays_blocked(self):
        journal = self.journal()
        for exists in (False, True):
            with self.subTest(group_exists=exists):
                client = journal.prepare(self.intent(), self.argv())
                def diagnostic_only(group, number):
                    self.assertEqual(group, client.native["processGroupId"])
                    self.assertEqual(number, 0, "recovery must never deliver a signal")
                    if not exists:
                        raise ProcessLookupError
                with mock.patch.object(journal._identity, "process_identity", return_value=None), mock.patch.object(native.os, "killpg", side_effect=diagnostic_only) as kill, mock.patch.object(journal._identity, "safe_signal_group") as old_signal:
                    report = journal.recover()
                    kill.assert_called_once_with(client.native["processGroupId"], 0)
                    old_signal.assert_not_called()
                observation = next(item for item in report["observations"] if item["clientId"] == client.client_id)
                self.assertEqual(observation["native"], "leaderless-uncertain" if exists else "native-absent")
                self.assertTrue(report["poolBlocked"])
                self.assertFalse(report["serverQuiescent"])
                self.assertFalse(report["qualified"])
                self.assertEqual(self.state(journal, client.client_id)["state"], "delivery-uncertain")
                client.abort_unreleased()

    def test_command_scope_and_digest_drift_fail_before_popen(self):
        journal = self.journal()
        bad = [self.argv()[:2] + ("sf-other",) + self.argv()[3:],
               self.argv()[:5] + ("sf-" + "9" * 32, "--format", "json"),
               self.argv("stop"), (str(self.sbx), ";", "echo")]
        with mock.patch.object(native, "_JournalProcess") as launch:
            for argv in bad:
                with self.subTest(argv=argv), self.assertRaises(native.NativeClientError):
                    journal.prepare(self.intent(), argv)
            self.sbx.write_text("changed")
            with self.assertRaises(native.NativeClientError):
                journal.prepare(self.intent(), self.argv())
            launch.assert_not_called()
        self.assertEqual(journal.records(), ())

    def test_popen_failure_has_durable_prelaunch_tombstone(self):
        journal = self.journal()
        with mock.patch.object(native, "_JournalProcess", side_effect=OSError("injected launch failure")):
            with self.assertRaises(OSError):
                journal.prepare(self.intent(), self.argv())
        record = journal.records()[0]
        self.assertEqual(record["state"], "aborted-before-release")
        self.assertNotIn("argv", record)
        self.assertEqual(record["argvDigest"], native.canonical_digest(list(self.argv())))

    def test_policy_native_tree_is_exact_and_never_accepts_global_or_broad_allow(self):
        journal = self.journal()
        prefix = (str(self.sbx), "--app-name", self.profile.namespace, "--no-input", "policy")
        fixed = {
            "policy-inspect": ("ls", NAME, "--json"),
            "policy-allow": ("allow", "network", "--sandbox", NAME, "api.openai.com:443", "--method", "POST", "--path", "/v1/responses"),
            "policy-remove-lock": ("rm", "network", "--sandbox", NAME, "--id", "11111111-1111-4111-8111-111111111111", "--force"),
        }
        for operation, arguments in fixed.items():
            journal._validate_command(self.intent(operation), prefix + arguments)
            for changed in (arguments + ("--global",), arguments[:-1],
                            tuple("sf-other" if part == NAME else part for part in arguments)):
                with self.subTest(operation=operation, changed=changed), self.assertRaises(native.NativeClientError):
                    journal._validate_command(self.intent(operation), prefix + changed)
        args = fixed["policy-allow"]
        for host in ("**", "api.openai.com", "github.com:443"):
            with self.assertRaises(native.NativeClientError):
                journal._validate_command(self.intent("policy-allow"), prefix + args[:4] + (host,) + args[5:])
        with self.assertRaises(native.NativeClientError):
            journal._validate_command(self.intent("policy-allow"), prefix + args[:-1] + ("/v1/organization/admin_api_keys",))
        self.assertEqual(journal.records(), ())

    def test_create_command_must_match_entire_mountless_profile(self):
        journal = self.journal()
        prefix = (str(self.sbx), "--app-name", self.profile.namespace, "--no-input", "create")
        args = ("--name", NAME, "--cpus", str(self.profile.limits.cpus), "--memory", "512m",
                "--skills", "off", "--static-mcp", "none", "--deny-network", "**", "--pull", "missing", self.profile.image)
        with mock.patch.object(native, "_JournalProcess") as launch:
            for argv in (prefix + args + ("--mount", "/dummy"), prefix + args[:-1] + ("docker.io/other:latest",)):
                with self.subTest(argv=argv), self.assertRaises(native.NativeClientError):
                    journal.prepare(self.intent("create"), argv)
            launch.assert_not_called()
        self.assertEqual(journal.records(), ())

    def test_partial_pipe_failure_closes_earlier_descriptors(self):
        journal = self.journal()
        pipe = native.os.pipe
        created = []
        def fail_second():
            if created:
                raise OSError("injected pipe failure")
            values = pipe()
            created.extend(values)
            return values
        with mock.patch.object(native.os, "pipe", side_effect=fail_second):
            with self.assertRaises(OSError):
                journal.prepare(self.intent(), self.argv())
        for descriptor in created:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_unfinished_commit_blocks_reopen_and_closes_constructor_storage(self):
        journal = self.journal()
        (self.path / native.PENDING_FILE).write_bytes(b"interrupted")
        (self.path / native.PENDING_FILE).chmod(0o600)
        storage = native.SandboxRegistry
        opened = []
        def capture(*args, **kwargs):
            result = storage(*args, **kwargs)
            opened.append(result)
            return result
        with mock.patch.object(native, "SandboxRegistry", side_effect=capture):
            with self.assertRaises(native.NativeClientError):
                self.journal()
        self.assertEqual(opened[0]._root_fd, -1)

    def test_history_cannot_reset_and_record_quota_retains_tombstones(self):
        journal = self.journal()
        with mock.patch.object(native, "MAX_RECORDS", 1):
            client = journal.prepare(self.intent(), self.argv())
            client.abort_unreleased()
            with self.assertRaises(native.NativeClientError):
                journal.prepare(self.intent(), self.argv())
        (self.path / native.STATE_FILE).unlink()
        with self.assertRaises(native.NativeClientError):
            self.journal()

    def test_receipt_renewal_preserves_closed_history_and_original_profile_provenance(self):
        journal = self.journal()
        client = journal.prepare(self.intent(), self.argv())
        client.abort_unreleased()
        original = journal.records()[0]
        renewed_profile = dataclasses.replace(self.profile, qualification_digest="sha256:" + "f" * 64)
        with mock.patch.object(native, "load_profile", return_value=renewed_profile):
            renewed = self.journal()
            record = renewed.records()[0]
            self.assertEqual(record, original)
            self.assertNotEqual(record["profileDigest"], renewed_profile.digest)
            state = json.loads((self.path / native.STATE_FILE).read_bytes())
            self.assertEqual(state["schemaVersion"], 2)
            self.assertEqual(state["profileBasisDigest"], native.profile_basis_digest(renewed_profile))

    def test_v1_migration_requires_exact_old_profile_and_never_discards_records(self):
        journal = self.journal()
        client = journal.prepare(self.intent(), self.argv())
        client.abort_unreleased()
        legacy = json.loads((self.path / native.STATE_FILE).read_bytes())
        legacy.pop("profileBasisDigest")
        legacy.update(schemaVersion=1, profileDigest=self.profile.digest)
        (self.path / native.STATE_FILE).write_text(json.dumps(legacy))
        migrated = self.journal()
        self.assertEqual(migrated.records()[0]["clientId"], client.client_id)
        self.assertEqual(json.loads((self.path / native.STATE_FILE).read_bytes())["schemaVersion"], 2)
        (self.path / native.STATE_FILE).write_text(json.dumps(legacy))
        renewed_profile = dataclasses.replace(self.profile, qualification_digest="sha256:" + "f" * 64)
        with mock.patch.object(native, "load_profile", return_value=renewed_profile), self.assertRaises(native.NativeClientError):
            self.journal()

    def test_policy_basis_change_cannot_reinterpret_existing_native_history(self):
        self.journal()
        changed = dataclasses.replace(self.profile, policy_digest="sha256:" + "e" * 64)
        with mock.patch.object(native, "load_profile", return_value=changed), self.assertRaises(native.NativeClientError):
            self.journal()

    def test_strict_decoder_supports_full_quota_and_rejects_malformed_json(self):
        value = {"records": {"native-" + f"{index:032x}": {"strings": ["x"] * 40} for index in range(native.MAX_RECORDS)}}
        self.assertEqual(native._decode(json.dumps(value).encode()), value)
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'{"x":' + b'[' * 13 + b'0' + b']' * 13 + b'}', b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw[:40]), self.assertRaises(native.NativeClientError):
                native._decode(raw)

    def test_loaded_history_rejects_impossible_ack_or_namespace(self):
        journal = self.journal()
        client = journal.prepare(self.intent(), self.argv())
        client.abort_unreleased()
        state = json.loads((self.path / native.STATE_FILE).read_bytes())
        for key, value in (("state", "completed-acknowledged"), ("responseDigest", DIGEST)):
            malformed = copy.deepcopy(state)
            malformed["records"][client.client_id][key] = value
            (self.path / native.STATE_FILE).write_text(json.dumps(malformed))
            with self.assertRaises(native.NativeClientError):
                journal.records()
        (self.path / native.STATE_FILE).write_text(json.dumps(state))

    def test_controller_crash_before_and_after_release_stays_blocked(self):
        for phase in ("before", "after"):
            with self.subTest(phase=phase):
                path = self.scratch / ("crash-" + phase)
                path.mkdir(mode=0o700)
                if self.execution_marker.exists():
                    self.execution_marker.unlink()
                result = subprocess.run(
                    [sys.executable, "-I", "-B", "-c", CRASH_CONTROLLER, str(ROOT / "src"),
                     str(path), str(self.profile_path), json.dumps(self.tools.as_dict()), phase],
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False,
                    cwd=self.scratch, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                )
                self.assertEqual(result.returncode, 0, result.stderr[:2048])
                identity = json.loads(result.stdout)
                reopened = native.NativeClientJournal(path, self.profile_path, self.tools)
                self.journals.append(reopened)
                record = self.state(reopened, identity["clientId"])
                self.assertEqual(record["state"], "gated" if phase == "before" else "exec-channel-open")
                self.assertEqual(record["native"]["pid"], identity["pid"])
                with mock.patch.object(native.os, "killpg") as kill, mock.patch.object(reopened._identity, "safe_signal_group") as old_signal:
                    report = reopened.recover()
                    # A fast guest PID-1 reaper can already have removed the
                    # orphan leader. killpg(PGID, 0) is then only an existence
                    # query; no nonzero cross-restart signal is authorized.
                    for call in kill.call_args_list:
                        self.assertEqual(call.args, (identity["pid"], 0))
                        self.assertEqual(call.kwargs, {})
                    old_signal.assert_not_called()
                self.assertTrue(report["poolBlocked"])
                self.assertEqual(self.state(reopened, identity["clientId"])["state"], "delivery-uncertain")
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and not self.execution_marker.exists():
                    time.sleep(.01)
                self.assertEqual(self.execution_marker.exists(), phase == "after")


if __name__ == "__main__":
    unittest.main()
