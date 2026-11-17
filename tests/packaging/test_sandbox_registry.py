"""Registry state tests; execute only in the assigned isolated test runner.

Set SF_REGISTRY_TEST_ROOT to a writable directory with protected ancestors,
such as /scratch. Production validation deliberately rejects shared /tmp.
No test calls Docker or executes target-controlled repository code.
"""

from __future__ import annotations

import copy
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import sandbox_registry as registry  # noqa: E402


NAMESPACE = "sf-qualification"
CREATED = "2026-11-17T00:15:00Z"
SCOPE = {
    "projectId": "sha256:" + "1" * 64, "team": "fixture-team", "featureId": "feature-1",
    "role": "backend-engineer", "taskId": "task-1", "attempt": 1,
}
CHILD_SCRIPT = """import json,os,sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
from startup_factory_cli.sandbox_registry import SandboxRegistry,RegistryBusy
r=SandboxRegistry(Path(sys.argv[2]),'sf-qualification')
try:
    with r.locked() as tx:
        if sys.argv[3]=='reserve-and-crash':
            epoch=tx.takeover()
            record=tx.reserve(json.loads(sys.argv[4]),epoch=epoch)
            print(json.dumps(record),flush=True)
            os._exit(0)
        print('acquired',flush=True)
except RegistryBusy:
    print('busy',flush=True)
    sys.exit(3)
finally:
    r.close()
"""


class SandboxRegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        base = Path(os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd()))
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-registry-test-", dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name)
        self.path = self.scratch / "registry"
        self.path.mkdir(mode=0o700)

    def open_registry(self, **kwargs) -> registry.SandboxRegistry:
        result = registry.SandboxRegistry(self.path, NAMESPACE, **kwargs)
        self.addCleanup(result.close)
        return result

    def allocate(self, tx, epoch):
        record = tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
        return tx.bind(
            record["name"], record["generation"], epoch,
            sandbox_id=str(uuid.uuid4()), created_at=CREATED,
        )

    @staticmethod
    def observation(record, state):
        return {"sandboxId": record["sandboxId"], "createdAt": record["createdAt"], "state": state}

    def remove(self, tx, record, epoch):
        arguments = (record["name"], record["generation"], epoch)
        tx.fence(*arguments)
        tx.transition(*arguments, state="stopping")
        tx.transition(
            *arguments, state="stopped",
            observation=self.observation(record, "stopped" if record["sandboxId"] else "absent"),
        )
        tx.transition(*arguments, state="removing")
        return tx.transition(*arguments, state="removed", observation=self.observation(record, "absent"))

    def child(self, mode):
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c", CHILD_SCRIPT, str(ROOT / "src"), str(self.path), mode, json.dumps(SCOPE)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False,
            cwd=self.scratch,
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.scratch), "TMPDIR": str(self.scratch), "LC_ALL": "C"},
        )

    def state(self):
        return json.loads((self.path / registry.STATE_FILE).read_bytes())

    def change_state(self, mutate):
        state = self.state()
        mutate(state)
        (self.path / registry.STATE_FILE).write_text(json.dumps(state))

    def test_reservation_is_durable_before_binding_and_returns_copies(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            self.assertRegex(record["name"], r"^sf-[0-9a-f]{32}$")
            self.assertRegex(record["generation"], r"^gen-[0-9a-f]{32}$")
            self.assertEqual(self.state()["records"][record["name"]], record)
            record["scope"]["role"] = "fake-role"
            self.assertEqual(tx.records()[0]["scope"]["role"], "backend-engineer")
            self.assertIsNone(tx.records()[0]["sandboxId"])
        with self.assertRaises(registry.RegistryError):
            tx.records()
        self.assertEqual((self.path / registry.STATE_FILE).stat().st_mode & 0o777, 0o600)

    def test_new_controller_must_take_over_and_fences_prior_generations(self):
        first = self.open_registry()
        with first.locked() as tx:
            epoch1 = tx.takeover()
            record = self.allocate(tx, epoch1)
            tx.transition(record["name"], record["generation"], epoch1, state="ready")
        second = self.open_registry()
        with second.locked() as tx:
            with self.assertRaises(registry.RegistryError):
                tx.authorize(record["name"], record["generation"], epoch1, allowed_states={"ready"})
            epoch2 = tx.takeover()
            self.assertGreater(epoch2, epoch1)
            fenced = tx.records()[0]
            self.assertEqual(fenced["state"], "fenced")
            self.assertEqual(fenced["epoch"], epoch2)
            for field in ("name", "generation", "scope", "sandboxId", "createdAt"):
                self.assertEqual(fenced[field], record[field])
            with self.assertRaises(registry.RegistryError):
                tx.authorize(record["name"], record["generation"], epoch2, allowed_states={"running"})
        with first.locked() as tx:
            with self.assertRaises(registry.RegistryError):
                tx.reserve(copy.deepcopy(SCOPE), epoch=epoch1)

    def test_epoch_and_generation_mismatch_cannot_authorize_or_mutate(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = self.allocate(tx, epoch)
            for generation, supplied_epoch in (("gen-" + "0" * 32, epoch), (record["generation"], epoch + 1), (record["generation"], True)):
                with self.subTest(generation=generation, epoch=supplied_epoch):
                    with self.assertRaises(registry.RegistryError):
                        tx.authorize(record["name"], generation, supplied_epoch, allowed_states={"allocated"})
                    with self.assertRaises(registry.RegistryError):
                        tx.fence(record["name"], generation, supplied_epoch)

    def test_binding_is_exact_idempotent_and_cannot_adopt_a_replacement(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = self.allocate(tx, epoch)
            arguments = (record["name"], record["generation"], epoch)
            self.assertEqual(tx.bind(*arguments, sandbox_id=record["sandboxId"], created_at=CREATED), record)
            for identifier, created in ((str(uuid.uuid4()), CREATED), (record["sandboxId"], "2026-11-17T00:16:00Z")):
                with self.assertRaises(registry.RegistryError):
                    tx.bind(*arguments, sandbox_id=identifier, created_at=created)
            another = tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            with self.assertRaises(registry.RegistryError):
                tx.bind(another["name"], another["generation"], epoch, sandbox_id=record["sandboxId"], created_at=CREATED)

    def test_binding_preserves_execution_contract_nanosecond_timestamp(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            precise = "2026-11-17T00:15:00.123456789Z"
            bound = tx.bind(
                record["name"], record["generation"], epoch,
                sandbox_id=str(uuid.uuid4()), created_at=precise,
            )
            self.assertEqual(bound["createdAt"], precise)
            self.assertEqual(self.state()["records"][record["name"]]["createdAt"], precise)

    def test_controlled_lifecycle_never_revives_fenced_or_removed_records(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = self.allocate(tx, epoch)
            arguments = (record["name"], record["generation"], epoch)
            for state in ("ready", "running", "collecting", "work-complete"):
                tx.transition(*arguments, state=state)
                self.assertEqual(tx.authorize(*arguments, allowed_states={state})["state"], state)
            tx.fence(*arguments)
            for state in ("ready", "running", "collecting", "work-complete"):
                with self.assertRaises(registry.RegistryError):
                    tx.transition(*arguments, state=state)
                with self.assertRaises(registry.RegistryError):
                    tx.authorize(*arguments, allowed_states={state})
            removed = self.remove(tx, record, epoch)
            self.assertEqual(removed["state"], "removed")
            with self.assertRaises(registry.RegistryError):
                tx.fence(*arguments)
            with self.assertRaises(registry.RegistryError):
                tx.transition(*arguments, state="ready")

    def test_stop_and_removal_require_matching_adapter_observations(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = self.allocate(tx, epoch)
            arguments = (record["name"], record["generation"], epoch)
            tx.fence(*arguments)
            with self.assertRaises(registry.RegistryError):
                tx.transition(*arguments, state="removed", observation=self.observation(record, "absent"))
            tx.transition(*arguments, state="stopping")
            for observation in (None, {**self.observation(record, "stopped"), "sandboxId": str(uuid.uuid4())}, {**self.observation(record, "stopped"), "extra": True}):
                with self.assertRaises(registry.RegistryError):
                    tx.transition(*arguments, state="stopped", observation=observation)
            tx.transition(*arguments, state="stopped", observation=self.observation(record, "stopped"))
            with self.assertRaises(registry.RegistryError):
                tx.transition(*arguments, state="removed", observation=self.observation(record, "stopped"))
            self.assertEqual(tx.transition(*arguments, state="removed", observation=self.observation(record, "absent"))["state"], "removed")

    def test_unbound_failed_create_is_retained_and_can_only_confirm_absence(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            with self.assertRaises(registry.RegistryError):
                tx.authorize(record["name"], record["generation"], epoch, allowed_states={"allocated"})
            removed = self.remove(tx, record, epoch)
            self.assertEqual(removed["state"], "removed")
            self.assertEqual(len(tx.records()), 1)
            fresh = tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            self.assertNotEqual(fresh["name"], record["name"])

    def test_uncertain_cleanup_never_frees_permanent_name_quota(self):
        owner = self.open_registry(max_names=1)
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = self.allocate(tx, epoch)
            arguments = (record["name"], record["generation"], epoch)
            for state in ("cleanup-pending", "lost", "fenced"):
                tx.transition(*arguments, state=state)
                with self.assertRaises(registry.RegistryQuotaExceeded):
                    tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            self.remove(tx, record, epoch)
            with self.assertRaises(registry.RegistryQuotaExceeded):
                tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)

    def test_removed_names_cannot_be_reused_even_if_randomness_repeats(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = self.allocate(tx, epoch)
            self.remove(tx, record, epoch)
            with mock.patch.object(registry.secrets, "token_hex", return_value=record["name"][3:]):
                with self.assertRaises(registry.RegistryError):
                    tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            self.assertEqual(len(tx.records()), 1)

    def test_byte_quota_refuses_mutation_without_forgetting_history(self):
        owner = self.open_registry(max_state_bytes=512)
        with owner.locked() as tx:
            epoch = tx.takeover()
            before = (self.path / registry.STATE_FILE).read_bytes()
            with self.assertRaises(registry.RegistryQuotaExceeded):
                tx.reserve({**SCOPE, "featureId": "f" * 1024}, epoch=epoch)
            self.assertEqual((self.path / registry.STATE_FILE).read_bytes(), before)
            self.assertEqual(tx.records(), ())

    def test_real_second_process_cannot_enter_the_locked_namespace(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            tx.takeover()
            result = self.child("lock")
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertEqual(result.stdout, b"busy\n")
        result = self.child("lock")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"acquired\n")

    def test_losing_thread_cannot_clear_the_winning_transaction(self):
        owner = self.open_registry()
        before_lock = threading.Event()
        attempt_lock = threading.Event()
        errors = []
        original_flock = registry.fcntl.flock

        def delayed_flock(descriptor, operation):
            if (
                threading.current_thread().name == "registry-contender"
                and operation == (registry.fcntl.LOCK_EX | registry.fcntl.LOCK_NB)
            ):
                before_lock.set()
                if not attempt_lock.wait(timeout=2):
                    raise AssertionError("fixture did not release the contender")
            return original_flock(descriptor, operation)

        def contend():
            try:
                with owner.locked():
                    errors.append(AssertionError("contender unexpectedly acquired the lock"))
            except Exception as exc:
                errors.append(exc)

        with mock.patch.object(registry.fcntl, "flock", side_effect=delayed_flock):
            thread = threading.Thread(target=contend, name="registry-contender")
            thread.start()
            try:
                self.assertTrue(before_lock.wait(timeout=2))
                with owner.locked() as tx:
                    epoch = tx.takeover()
                    attempt_lock.set()
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(len(errors), 1)
                    self.assertIsInstance(errors[0], registry.RegistryBusy)
                    self.assertEqual(tx.epoch, epoch)
                    tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            finally:
                attempt_lock.set()
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())

    def test_a_transaction_cannot_be_used_from_another_thread(self):
        owner = self.open_registry()
        errors = []
        with owner.locked() as tx:
            epoch = tx.takeover()

            def mutate():
                try:
                    tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
                except Exception as exc:
                    errors.append(exc)

            thread = threading.Thread(target=mutate)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], registry.RegistryError)
            self.assertEqual(tx.records(), ())

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX descriptor-inheritance fixture")
    def test_inherited_context_cannot_authorize_or_unlock_its_parent(self):
        owner = self.open_registry()
        context = owner.locked()
        tx = context.__enter__()
        try:
            epoch = tx.takeover()
            child = os.fork()
            if child == 0:
                status = 1
                try:
                    try:
                        tx.records()
                    except registry.RegistryError:
                        status = 0
                    context.__exit__(None, None, None)
                    owner.close()
                except BaseException:
                    status = 2
                os._exit(status)
            deadline = time.monotonic() + 2
            while True:
                waited, status = os.waitpid(child, os.WNOHANG)
                if waited == child:
                    break
                if time.monotonic() >= deadline:
                    # The unreaped fixture child still reserves this PID.
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
                    self.fail("inherited registry fixture exceeded its deadline")
                time.sleep(0.01)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
            contender = self.child("lock")
            self.assertEqual(contender.returncode, 3, contender.stderr)
            self.assertEqual(tx.epoch, epoch)
        finally:
            context.__exit__(None, None, None)

    def test_crashed_controller_reservation_survives_and_is_fenced_on_takeover(self):
        result = self.child("reserve-and-crash")
        self.assertEqual(result.returncode, 0, result.stderr)
        reserved = json.loads(result.stdout)
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = tx.records()[0]
            self.assertEqual(record["name"], reserved["name"])
            self.assertEqual(record["generation"], reserved["generation"])
            self.assertEqual(record["state"], "fenced")
            self.assertGreater(epoch, reserved["epoch"])
            fresh = tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            self.assertNotEqual(fresh["name"], reserved["name"])

    def test_symlink_and_writable_ancestor_or_nonprivate_root_are_rejected(self):
        alias = self.scratch / "alias"
        alias.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(registry.RegistryError):
            registry.SandboxRegistry(alias, NAMESPACE)
        self.path.chmod(0o755)
        with self.assertRaises(registry.RegistryError):
            self.open_registry()
        self.path.chmod(0o700)
        self.scratch.chmod(0o777)
        try:
            with self.assertRaises(registry.RegistryError):
                self.open_registry()
        finally:
            self.scratch.chmod(0o700)
        with self.assertRaises(registry.RegistryError):
            registry.SandboxRegistry(Path("relative/registry"), NAMESPACE)

    def test_symlink_hardlink_and_writable_state_files_are_rejected(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            tx.takeover()
        target = self.path / registry.STATE_FILE
        original = target.read_bytes()
        outside = self.scratch / "outside.json"
        outside.write_bytes(original)
        outside.chmod(0o600)
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaises(registry.RegistryError):
            with self.open_registry().locked():
                self.fail("symlink state accepted")
        target.unlink()
        os.link(outside, target)
        with self.assertRaises(registry.RegistryError):
            with self.open_registry().locked():
                self.fail("hardlink state accepted")
        target.unlink()
        target.write_bytes(original)
        target.chmod(0o644)
        with self.assertRaises(registry.RegistryError):
            with self.open_registry().locked():
                self.fail("writable state accepted")

    def test_lock_and_marker_hardlinks_are_not_authority(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            tx.takeover()
        for name in (registry.LOCK_FILE, registry.MARKER_FILE):
            with self.subTest(name=name):
                duplicate = self.scratch / (name + ".link")
                os.link(self.path / name, duplicate)
                try:
                    with self.assertRaises(registry.RegistryError):
                        with self.open_registry().locked():
                            self.fail("linked authority file accepted")
                finally:
                    duplicate.unlink()

    def test_missing_state_or_marker_cannot_reset_existing_history(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
        target = self.path / registry.STATE_FILE
        original = target.read_bytes()
        target.unlink()
        with self.assertRaises(registry.RegistryError):
            with self.open_registry().locked():
                self.fail("missing history was reset")
        target.write_bytes(original)
        target.chmod(0o600)
        (self.path / registry.MARKER_FILE).unlink()
        with self.assertRaises(registry.RegistryError):
            with self.open_registry().locked():
                self.fail("missing identity was reset")

    def test_closed_schema_and_corrupted_state_fail_before_authorization(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            record = self.allocate(tx, epoch)
        target = self.path / registry.STATE_FILE
        original = target.read_bytes()
        mutations = (
            lambda state: state.update(qualified=True),
            lambda state: state.update(schemaVersion=True),
            lambda state: state.update(schemaVersion=2),
            lambda state: state.update(namespace="another-factory"),
            lambda state: state.update(epoch=0),
            lambda state: state["records"][record["name"]]["scope"].update(attempt=True),
            lambda state: state["records"][record["name"]].update(state="future-state"),
            lambda state: state["records"][record["name"]].update(unexpected="authority"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                target.write_bytes(original)
                self.change_state(mutate)
                with self.assertRaises(registry.RegistryError):
                    with self.open_registry().locked():
                        self.fail("corrupted state accepted")
        for raw in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"epoch":NaN}', b"[" * 20 + b"0" + b"]" * 20, b"\xff"):
            with self.subTest(raw=raw):
                target.write_bytes(raw)
                with self.assertRaises(registry.RegistryError):
                    with self.open_registry().locked():
                        self.fail("invalid JSON accepted")

    def test_changes_during_transaction_and_root_replacement_are_rejected(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            self.change_state(lambda state: state.update(revision=state["revision"] + 1))
            with self.assertRaises(registry.RegistryError):
                tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
        with self.open_registry().locked() as tx:
            tx.takeover()
            self.path.rename(self.scratch / "old-registry")
            self.path.mkdir(mode=0o700)
            with self.assertRaises(registry.RegistryError):
                tx.records()

    def test_uncertain_directory_fsync_poisoning_survives_as_fenced_history(self):
        owner = self.open_registry()
        original_fsync = os.fsync
        with owner.locked() as tx:
            epoch = tx.takeover()

            def fail_directory(descriptor):
                if descriptor == owner._root_fd:
                    raise OSError(errno.EIO, "fixture directory sync failure")
                return original_fsync(descriptor)

            with mock.patch.object(registry.os, "fsync", side_effect=fail_directory):
                with self.assertRaises(registry.RegistryUncertainWrite):
                    tx.reserve(copy.deepcopy(SCOPE), epoch=epoch)
            with self.assertRaises(registry.RegistryError):
                tx.records()
        with self.assertRaises(registry.RegistryError):
            with owner.locked():
                self.fail("uncertain controller resumed")
        replacement = self.open_registry()
        with replacement.locked() as tx:
            tx.takeover()
            records = tx.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["state"], "fenced")

    def test_invalid_scope_and_authorization_state_sets_do_not_mutate(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            for scope in (
                {**SCOPE, "hostPath": "/private"}, {**SCOPE, "attempt": 0}, {**SCOPE, "taskId": ""},
                {**SCOPE, "projectId": "unbound-project"}, {**SCOPE, "attempt": 2**31},
                {**SCOPE, "role": "-bad-role"}, {**SCOPE, "featureId": "f" * 1023 + "\u00e9"},
            ):
                with self.assertRaises(registry.RegistryError):
                    tx.reserve(scope, epoch=epoch)
            record = self.allocate(tx, epoch)
            for states in (set(), {"fenced"}, {"removed"}, ["allocated"]):
                with self.assertRaises(registry.RegistryError):
                    tx.authorize(record["name"], record["generation"], epoch, allowed_states=states)

    def test_gate_scope_accepts_only_the_exact_dash_zero_pair(self):
        owner = self.open_registry()
        with owner.locked() as tx:
            epoch = tx.takeover()
            gate = {**SCOPE, "taskId": "-", "attempt": 0}
            record = tx.reserve(gate, epoch=epoch)
            self.assertEqual(record["scope"], gate)
            for scope in (
                {**gate, "attempt": 1}, {**gate, "attempt": False},
                {**SCOPE, "attempt": 0}, {**SCOPE, "attempt": True},
                {**gate, "attempt": -1},
            ):
                with self.subTest(scope=scope), self.assertRaises(registry.RegistryError):
                    tx.reserve(scope, epoch=epoch)


if __name__ == "__main__":
    unittest.main()
