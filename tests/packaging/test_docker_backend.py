from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import signal
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import docker_backend as adapter  # noqa: E402
from startup_factory_cli.execution_backend import (  # noqa: E402
    ArtifactReference, BackendIdentity, DockerProfile, GuestCommand, LaunchScope, LaunchSpec,
)
from startup_factory_cli.sandbox_network_policy import ModelNetworkPolicy
from startup_factory_cli.sandbox_exec_probe import CommandResult  # noqa: E402


NAME = "sf-" + "1" * 32
OTHER_NAME = "sf-" + "2" * 32
UUID = "d9f44bce-019d-43c3-b8c2-dcf7ac05258b"
CREATED = "2026-11-17T01:01:11+01:00"
DIGEST = "sha256:" + "a" * 64


def profile() -> DockerProfile:
    return DockerProfile.from_dict({
        "schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
        "controllerUid": 501, "sbxPath": "/opt/factory/sbx", "sbxSha256": "1" * 64,
        "namespace": "sf-unit", "image": "docker.io/sbx/shell@sha256:" + "2" * 64,
        "guestWorkdir": "/workspace/project", "policyDigest": DIGEST,
        "qualificationDigest": "sha256:" + "b" * 64,
        "limits": {"cpus": 1, "memoryMiB": 512, "rootDiskMiB": 2048,
                   "dockerDiskMiB": 512, "wallSeconds": 30, "maxOutputBytes": 65536},
    })


class FakeSBX:
    """Data-only runtime model; never starts Docker or a guest executable."""
    def __init__(self, selected: DockerProfile, events: list[str]) -> None:
        self.profile = selected
        self.events = events
        self.calls = []
        self.objects = {}
        self.inspect_transform = lambda value: value
        self.list_transform = lambda value: value
        self.fail = None
        self.stop_remains_running = False
        self.removal_retains_object = False

    def add(self, name: str = NAME) -> BackendIdentity:
        self.objects[name] = {"name": name, "id": UUID, "created_at": CREATED,
                              "state": "stopped"}
        return BackendIdentity(name, UUID, CREATED)

    def metadata(self, name: str) -> dict:
        return {
            **self.objects[name], "created_version": "v0.54.0", "daemon_version": "v0.54.0",
            "cpus": self.profile.limits.cpus, "memory": f"{self.profile.limits.memory_mib}m",
            "image": "sandbox-kit-assembled:fixture", "image_digest": self.profile.image.split("@")[1],
            "kits": [self.profile.image], "host_mounts": [], "runtime_mounts": [],
            "working_dir": "", "effective_working_dir": "/home/agent/workspace",
            "mcp_mode": "static", "mcp_servers": [], "mcp_gateway": True,
            "network": name, "network_policy": {"scope": "sandbox"}, "uptime": "1s",
        }

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        operation = argv[4]
        self.events.append(operation)
        if operation == self.fail:
            return CommandResult(1, b"", b"fixture failure")
        if operation == "ls":
            rows = [{"name": row["name"], "id": row["id"], "created_at": "2026-11-17T00:01:11Z",
                     "status": row["state"], "agent": "shell", "cpus": 1,
                     "memory": "512m", "memory_mib": 512, "last_used_at": "2026-11-17T00:01:13.013655Z"}
                    for row in self.objects.values()]
            output = self.list_transform(json.dumps(rows).encode())
            return CommandResult(0, output)
        if operation == "create":
            self.add(argv[argv.index("--name") + 1])
            return CommandResult(0, b"created\n")
        if operation == "inspect":
            if argv[5] not in self.objects:
                return CommandResult(1, b"", b"sandbox not found")
            return CommandResult(0, self.inspect_transform(json.dumps(self.metadata(argv[5])).encode()))
        if operation == "stop":
            if not self.stop_remains_running:
                self.objects[argv[5]]["state"] = "stopped"
            return CommandResult(0)
        if operation == "rm":
            if argv[5] != "--force":
                raise AssertionError("removal must not prompt")
            if not self.removal_retains_object:
                del self.objects[argv[6]]
            return CommandResult(0)
        raise AssertionError("unexpected runtime operation")


class FakeNative:
    """Real private pipes and fake process custody; tests never signal a PID."""
    def __init__(self, events: list[str]) -> None:
        input_read, input_write = os.pipe()
        output_read, output_write = os.pipe()
        error_read, error_write = os.pipe()
        self.stdin = os.fdopen(input_write, "wb", buffering=0)
        self.stdout = os.fdopen(output_read, "rb", buffering=0)
        self.stderr = os.fdopen(error_read, "rb", buffering=0)
        self.peers = [input_read, output_write, error_write]
        self.pid = 999999
        self.returncode = None
        self.events = events
        self.fail_reap = False

    def _reap_owned(self, *, timeout):
        self.events.append("reap")
        if self.fail_reap:
            raise adapter.subprocess.TimeoutExpired("fixture", timeout)
        self.returncode = -signal.SIGKILL
        return self.returncode

    def cleanup(self):
        for stream in (self.stdin, self.stdout, self.stderr):
            stream.close()
        for fd in self.peers:
            try:
                os.close(fd)
            except OSError:
                pass


class DockerBackendTest(unittest.TestCase):
    def setUp(self):
        self.selected = profile()
        self.events = []
        self.runner = FakeSBX(self.selected, self.events)
        self.requests = []
        self.reserved_name = NAME
        self.denied = set()
        self.permit_transform = lambda value: value
        self.native = []
        self.spawn_calls = []
        self.loader = self.patch("load_profile", return_value=self.selected)
        self.patch("os.geteuid", return_value=501)
        self.patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir="/fixture/controller-home", pw_name="factory"))
        self.patch("os.killpg", side_effect=lambda pid, _signal: self.events.append(f"signal:{pid}"))
        self.backend = adapter.DockerBackend(Path("/protected/profile.json"), permit=self.permits,
                                             runner=self.runner, popen_factory=self.spawn)
        self.command = GuestCommand(("/usr/bin/python3", "-I", "-B", "/opt/factory/bridge.py"))
        self.scope = LaunchScope(DIGEST, "team", "F-1", "backend", "T-1", 1)
        self.spec = LaunchSpec(self.scope, self.selected.digest, self.command)

    def patch(self, name, **kwargs):
        target = adapter
        components = name.split(".")
        for component in components[:-1]:
            target = getattr(target, component)
        patcher = mock.patch.object(target, components[-1], **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    @contextlib.contextmanager
    def permits(self, selected, request):
        self.requests.append(request)
        if request.operation in self.denied:
            raise adapter.DockerBackendError("external authority denied fixture operation")
        name = (self.reserved_name if request.operation == "create" else
                (None if request.identity is None else request.identity.name))
        issued = adapter.OperationPermit(request.digest, name, "gen-" + "a" * 32, 1, DIGEST)
        self.events.append("lease-enter:" + request.operation)
        try:
            yield self.permit_transform(issued)
        finally:
            self.events.append("lease-exit:" + request.operation)

    def spawn(self, argv, **kwargs):
        self.spawn_calls.append((list(argv), kwargs))
        child = FakeNative(self.events)
        self.native.append(child)
        self.addCleanup(child.cleanup)
        self.events.append("spawn")
        return child

    def policy_runtime(self, *, fail_remove=False, extra_rule=False):
        policy = ModelNetworkPolicy.from_dict({"schemaVersion": 1, "namespace": "sf-unit", "preset": "deny-all",
            "provider": "openai", "rules": [{"host": "api.openai.com:443", "method": "POST", "path": "/v1/responses"}]})
        self.selected = dataclasses.replace(self.selected, policy_digest=policy.digest)
        self.loader.return_value = self.selected
        self.runner.profile = self.selected
        identity = self.runner.add()
        fixture_root = ROOT / "tests/fixtures/sandbox"
        def rows(stage):
            value = json.loads((fixture_root / ("sbx-v0.54.0-policy-" + stage + ".json")).read_bytes())
            return json.loads(json.dumps(value).replace("sfq-policy-20261117-27f520c1", NAME))
        state = rows("locked")
        original = self.runner
        def runtime(argv, **kwargs):
            if argv[4] != "policy":return original(argv, **kwargs)
            original.calls.append((list(argv), kwargs));self.events.append("policy:" + argv[5])
            if argv[5:] == ["ls", NAME, "--json"]:
                output = json.loads(json.dumps(state))
                if extra_rule:output["rules"].append(output["rules"][0])
                return CommandResult(0, json.dumps(output).encode())
            if argv[5:] == ["allow", "network", "--sandbox", NAME, "api.openai.com:443", "--method", "POST", "--path", "/v1/responses"]:
                state.clear();state.update(rows("staged"));return CommandResult(0)
            lock = next(row["id"] for row in state["rules"] if row.get("editable") is True and row["decision"] == "deny")
            if argv[5:] == ["rm", "network", "--sandbox", NAME, "--id", lock, "--force"]:
                if fail_remove:return CommandResult(1, b"", b"fixture remove refused")
                state.clear();state.update(rows("active"));return CommandResult(0)
            raise AssertionError("unexpected policy command")
        self.backend._runner = runtime
        return identity, policy

    def test_policy_activation_verifies_lock_then_staged_then_exact_active_rules(self):
        identity, policy = self.policy_runtime()
        receipt = self.backend.configure_network(identity, policy)
        data = json.loads(self.backend.read_receipt(receipt))
        self.assertEqual(data["identity"], identity.as_dict())
        self.assertEqual(data["policyDigest"], policy.digest)
        self.assertEqual(self.requests[-1].operation, "policy-activate")
        self.assertEqual([event for event in self.events if event.startswith("policy:")],
                         ["policy:ls", "policy:allow", "policy:ls", "policy:rm", "policy:ls"])
        # Every native policy operation has an immediately preceding exact-ID inspection.
        calls = [argv for argv, _kwargs in self.runner.calls]
        for index, argv in enumerate(calls):
            if argv[4] == "policy":self.assertEqual(calls[index - 1][4:6], ["inspect", NAME])
        self.assertFalse(self.backend._uncertain)

    def test_policy_activation_denied_drift_or_extra_rules_never_removes_lock(self):
        for mode in ("permit", "digest", "extra"):
            with self.subTest(mode=mode):
                identity, policy = self.policy_runtime(extra_rule=mode == "extra")
                if mode == "permit":self.denied.add("policy-activate")
                if mode == "digest":policy = ModelNetworkPolicy.from_dict({**policy.as_dict(), "rules": [{"host": "api.openai.com:443", "method": "GET", "path": "/v1/models"}]})
                before = len(self.runner.calls)
                with self.assertRaises(ValueError if mode == "extra" else adapter.DockerBackendError):
                    self.backend.configure_network(identity, policy)
                self.assertFalse(any(argv[4:6] == ["policy", "rm"] for argv, _ in self.runner.calls[before:]))
                self.denied.clear();self.backend._uncertain = False

    def test_partial_policy_activation_failure_blocks_workload_dispatch(self):
        identity, policy = self.policy_runtime(fail_remove=True)
        with self.assertRaises(adapter.DockerBackendError):self.backend.configure_network(identity, policy)
        self.assertTrue(self.backend._uncertain)
        with self.assertRaises(adapter.DockerBackendError):self.backend.open_session(identity, self.command)
        self.assertEqual(self.spawn_calls, [])

    def test_default_provider_denies_even_probe_before_runtime_or_profile_access(self):
        inert = adapter.DockerBackend(Path("/untrusted/profile.json"), runner=self.runner)
        with self.assertRaisesRegex(adapter.DockerBackendError, "no external"):
            inert.probe(self.selected)
        self.loader.assert_not_called()
        self.assertEqual(self.runner.calls, [])

    def test_probe_reports_observations_without_qualification_or_daemon_commands(self):
        result = self.backend.probe(self.selected)
        self.assertFalse(hasattr(result, "ready"))
        self.assertFalse(hasattr(result, "qualified"))
        self.assertEqual(self.runner.calls, [])
        self.assertIn("external", " ".join(result.observations))

    def test_provision_and_collect_phases_bind_permit_workdir_and_separate_limits(self):
        identity = self.runner.add()
        for phase in ("provision", "collect"):
            with self.subTest(phase=phase):
                session = self.backend.open_session(identity, self.command, operation=phase)
                self.assertEqual(self.requests[-1].operation, phase)
                argv = self.spawn_calls[-1][0]
                self.assertEqual(argv[argv.index("--workdir") + 1], "/" if phase == "provision" else self.selected.guest_workdir)
                self.assertEqual(session._input_limit, adapter.MAX_TRANSFER_BYTES if phase == "provision" else self.selected.limits.max_output_bytes)
                self.assertEqual(session._limit, adapter.MAX_TRANSFER_BYTES if phase == "collect" else self.selected.limits.max_output_bytes)
                session.close()

    def test_guest_transfer_budgets_cannot_escape_permitted_phase(self):
        identity = self.runner.add()
        for kwargs in ({"max_input_bytes": adapter.MAX_TRANSFER_BYTES},
                       {"max_output_bytes": adapter.MAX_TRANSFER_BYTES},
                       {"operation": "provision", "max_input_bytes": adapter.MAX_TRANSFER_BYTES + 1},
                       {"operation": "collect", "max_output_bytes": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(adapter.DockerBackendError):
                self.backend.open_session(identity, self.command, **kwargs)
        self.assertEqual(self.spawn_calls, [])

    def test_permit_binds_operation_profile_identity_epoch_and_reconciliation(self):
        identity = self.runner.add()
        for change in (
            {"request_digest": "sha256:" + "0" * 64}, {"epoch": True}, {"epoch": 0},
            {"generation": "guest-claim"}, {"reconciliation_digest": "unproven"},
            {"reserved_name": OTHER_NAME},
        ):
            with self.subTest(change=change):
                self.permit_transform = lambda issued: dataclasses.replace(issued, **change)
                with self.assertRaises(adapter.DockerBackendError):
                    self.backend.inspect(identity)
        self.assertEqual(self.runner.calls, [])

    def test_actual_controller_uid_is_checked_before_each_permit_and_command(self):
        identity = self.runner.add()
        self.backend.inspect(identity)
        count = len(self.requests)
        with mock.patch.object(adapter.os, "geteuid", return_value=502):
            with self.assertRaisesRegex(adapter.DockerBackendError, "UID"):
                self.backend.inspect(identity)
        self.assertEqual(len(self.requests), count)

    def test_controller_lease_cannot_be_inherited_by_another_process(self):
        with mock.patch.object(adapter.os, "getpid", return_value=os.getpid() + 1):
            with self.assertRaisesRegex(adapter.DockerBackendError, "fork"):
                self.backend.probe(self.selected)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.runner.calls, [])

    def test_profile_drift_requires_a_new_controller_and_no_command_runs(self):
        self.backend.probe(self.selected)
        changed = dataclasses.replace(self.selected, namespace="sf-changed")
        self.loader.return_value = changed
        with self.assertRaisesRegex(adapter.DockerBackendError, "profile changed"):
            self.backend.create(self.spec)
        self.assertEqual(self.runner.calls, [])

    def test_create_uses_exact_mountless_pinned_flags_and_minimal_environment(self):
        with mock.patch.dict(os.environ, {"HOME": "/wrong", "GH_TOKEN": "dummy", "DOCKER_HOST": "wrong"}):
            identity = self.backend.create(self.spec)
        self.assertEqual(identity.name, NAME)
        self.assertEqual([args[4] for args, _ in self.runner.calls], ["ls", "create", "inspect"])
        args, options = self.runner.calls[1]
        self.assertEqual(args, [
            "/opt/factory/sbx", "--app-name", "sf-unit", "--no-input", "create", "--name", NAME,
            "--cpus", "1", "--memory", "512m", "--skills", "off", "--static-mcp", "none",
            "--deny-network", "**", "--pull", "missing", self.selected.image,
        ])
        environment = options["env"]
        self.assertEqual(environment["HOME"], "/fixture/controller-home")
        self.assertEqual(environment["DOCKER_SANDBOXES_ROOT_SIZE"], "2048m")
        self.assertEqual(environment["DOCKER_SANDBOXES_DOCKER_SIZE"], "512m")
        self.assertEqual(set(environment), {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "NO_COLOR",
                                            "DOCKER_SANDBOXES_ROOT_SIZE", "DOCKER_SANDBOXES_DOCKER_SIZE"})
        self.assertLessEqual(options["timeout_seconds"], 30)
        self.assertLessEqual(options["max_stdout_bytes"], 65536)

    def test_create_does_not_reuse_reserved_names_or_launch_without_bound_profile(self):
        self.backend.create(self.spec)
        before = len(self.runner.calls)
        with self.assertRaisesRegex(adapter.DockerBackendError, "already reserved"):
            self.backend.create(self.spec)
        self.assertEqual(len(self.runner.calls), before)
        with self.assertRaises(adapter.DockerBackendError):
            self.backend.create(dataclasses.replace(self.spec, profile_digest=DIGEST))

    def test_failed_or_uncertain_create_requires_external_reconciliation_not_blind_cleanup(self):
        self.runner.fail = "create"
        with self.assertRaises(adapter.DockerBackendError):
            self.backend.create(self.spec)
        self.assertNotIn("rm", self.events)
        self.assertNotIn("stop", self.events)
        self.reserved_name = OTHER_NAME
        with self.assertRaisesRegex(adapter.DockerBackendError, "uncertainty"):
            self.backend.create(self.spec)

    def test_inspect_matches_both_identity_fields_and_rejects_unknown_or_unsafe_metadata(self):
        for change in (
            {"id": "11111111-1111-4111-8111-111111111111"}, {"created_at": "2026-11-17T00:01:11Z"},
            {"host_mounts": ["/home"]}, {"runtime_mounts": ["/root"]}, {"mcp_servers": ["host"]},
            {"mcp_mode": "dynamic"}, {"working_dir": "/host/project"}, {"cpus": True},
            {"memory": 512}, {"memory": "1g"}, {"image_digest": DIGEST}, {"kits": []},
            {"network_policy": {"scope": "global"}}, {"network_policy": {"scope": "sandbox", "allowed": True}},
            {"daemon_version": "v0.55.0"}, {"future": True},
        ):
            with self.subTest(change=change):
                instance = adapter.DockerBackend(Path("/protected/profile.json"), permit=self.permits, runner=self.runner, popen_factory=self.spawn)
                identity = self.runner.add()
                self.runner.inspect_transform = lambda raw: json.dumps({**json.loads(raw), **change}).encode()
                with self.assertRaises(adapter.DockerBackendError):
                    instance.inspect(identity)

    def test_inspect_accepts_observed_running_uptime_without_using_it_as_identity(self):
        identity = self.runner.add()
        self.runner.objects[NAME]["state"] = "running"
        self.assertEqual(self.backend.inspect(identity).state, "running")

    def test_actual_v054_inspect_and_list_fixture_replays_preserve_timestamp_distinction(self):
        fixture_root = ROOT / "tests/fixtures/sandbox"
        inspect_raw = (fixture_root / "sbx-v0.54.0-inspect-stopped.json").read_bytes()
        list_raw = (fixture_root / "sbx-v0.54.0-ls-stopped.json").read_bytes()
        observed = json.loads(inspect_raw)
        selected = dataclasses.replace(self.selected, image=observed["kits"][0])
        self.loader.return_value = selected
        self.runner.add(observed["name"])
        self.runner.inspect_transform = lambda _raw: inspect_raw
        self.runner.list_transform = lambda _raw: list_raw
        instance = adapter.DockerBackend(Path("/protected/profile.json"), permit=self.permits, runner=self.runner, popen_factory=self.spawn)
        identity = BackendIdentity(observed["name"], observed["id"], observed["created_at"])
        self.assertEqual(instance.inspect(identity).identity, identity)
        # The list API normalizes timezones. It validates rows but proves
        # absence only by name/UUID; it must not replace the pinned creation text.
        rows = instance._rows(selected)
        self.assertEqual(rows[0]["id"], identity.sandbox_id)
        self.assertNotEqual(rows[0]["created_at"], identity.created_at)

    def test_duplicate_nonfinite_oversized_and_failed_native_results_fail_closed(self):
        identity = self.runner.add()
        for raw in (b'{"id":"a","id":"b"}', b'{"cpus":NaN}', b"[{}]", b"x" * 65537):
            with self.subTest(raw=raw[:30]):
                self.runner.inspect_transform = lambda _original: raw
                with self.assertRaises(adapter.DockerBackendError):
                    self.backend.inspect(identity)
        self.runner.fail = "inspect"
        with self.assertRaisesRegex(adapter.DockerBackendError, "absence is not established"):
            self.backend.inspect(identity)

    def test_live_session_has_exact_guest_argv_bound_permit_and_retained_lease(self):
        identity = self.runner.add()
        session = self.backend.open_session(identity, self.command)
        self.addCleanup(session.close)
        self.assertNotIn("lease-exit:open-session", self.events)
        self.assertEqual(self.requests[-1].guest_command, self.command)
        args, options = self.spawn_calls[0]
        self.assertEqual(args[4:], ["exec", "-i", "--user", "root", "--workdir", "/workspace/project",
                                    "--", NAME, *self.command.argv])
        self.assertEqual(options["env"]["HOME"], "/fixture/controller-home")
        self.assertIs(session.process, self.native[-1])
        session.stdin.write(b"ping")
        self.assertEqual(os.read(self.native[-1].peers[0], 4), b"ping")
        os.write(self.native[-1].peers[1], b"pong")
        self.assertEqual(session.stdout.read(4), b"pong")
        session.cancel()
        self.assertIn("lease-exit:open-session", self.events)
        self.assertIsNotNone(self.native[-1].returncode)
        self.assertTrue(all(stream.closed for stream in (session.stdin, session.stdout, session.stderr)))
        self.assertNotIn("stop", self.events)
        self.assertNotIn("rm", self.events)

    def test_stop_and_destroy_denial_do_not_cancel_owned_session(self):
        identity = self.runner.add()
        session = self.backend.open_session(identity, self.command)
        self.addCleanup(session.close)
        self.denied.update({"stop", "destroy"})
        for operation in (self.backend.stop, self.backend.destroy):
            with self.assertRaises(adapter.DockerBackendError):
                operation(identity)
        self.assertIsNone(session.process.returncode)
        self.assertNotIn("reap", self.events)

    def test_stop_reaps_owned_client_before_daemon_command_and_confirms_stopped_identity(self):
        identity = self.runner.add()
        session = self.backend.open_session(identity, self.command)
        self.runner.objects[NAME]["state"] = "running"
        observed = self.backend.stop(identity)
        self.assertEqual(observed.state, "stopped")
        self.assertLess(self.events.index("lease-enter:stop"), self.events.index("reap"))
        self.assertLess(self.events.index("reap"), self.events.index("stop"))
        self.assertTrue(session.stdin.closed)

    def test_unreaped_client_blocks_destructive_commands(self):
        identity = self.runner.add()
        self.backend.open_session(identity, self.command)
        self.native[-1].fail_reap = True
        with self.assertRaisesRegex(adapter.DockerBackendError, "uncertain"):
            self.backend.stop(identity)
        self.assertNotIn("stop", self.events)
        with self.assertRaises(adapter.DockerBackendError):
            self.backend.destroy(identity)
        self.assertNotIn("rm", self.events)

    def test_stop_does_not_treat_successful_command_as_stopped_observation(self):
        identity = self.runner.add()
        self.runner.objects[NAME]["state"] = "running"
        self.runner.stop_remains_running = True
        with self.assertRaisesRegex(adapter.DockerBackendError, "not confirmed stopped"):
            self.backend.stop(identity)

    def test_destroy_requires_stopped_then_forced_remove_and_positive_structured_absence(self):
        identity = self.runner.add()
        reference = self.backend.destroy(identity)
        self.assertEqual([args[4] for args, _ in self.runner.calls], ["inspect", "rm", "ls"])
        self.assertEqual(self.runner.calls[1][0][4:], ["rm", "--force", NAME])
        receipt = json.loads(self.backend.read_receipt(reference))
        self.assertTrue(receipt["nameAndIdAbsent"])
        self.assertFalse(receipt["qualified"])
        self.assertFalse(receipt["storageCleanupVerified"])
        self.assertEqual(receipt["identity"], identity.as_dict())
        self.assertEqual(receipt["epoch"], 1)

    def test_destroy_will_not_remove_running_or_mismatched_objects(self):
        identity = self.runner.add()
        self.runner.objects[NAME]["state"] = "running"
        with self.assertRaises(adapter.DockerBackendError):
            self.backend.destroy(identity)
        self.assertNotIn("rm", self.events)
        self.runner.objects[NAME]["state"] = "stopped"
        self.runner.objects[NAME]["id"] = "11111111-1111-4111-8111-111111111111"
        with self.assertRaises(adapter.DockerBackendError):
            self.backend.destroy(identity)
        self.assertNotIn("rm", self.events)

    def test_removal_presence_same_name_or_same_uuid_cannot_become_absence_receipt(self):
        for same_name in (True, False):
            with self.subTest(same_name=same_name):
                self.runner = FakeSBX(self.selected, self.events)
                identity = self.runner.add()
                self.runner.removal_retains_object = True
                if not same_name:
                    self.runner.list_transform = lambda raw: json.dumps([
                        {**json.loads(raw)[0], "name": OTHER_NAME}
                    ]).encode()
                instance = adapter.DockerBackend(Path("/protected/profile.json"), permit=self.permits, runner=self.runner, popen_factory=self.spawn)
                with self.assertRaisesRegex(adapter.DockerBackendError, "remains present"):
                    instance.destroy(identity)

    def test_listing_failure_or_unknown_shape_never_establishes_absence(self):
        for raw in (b"{}", b'[{"name":"unknown"}]', b"[NaN]", b"not JSON"):
            self.runner = FakeSBX(self.selected, self.events)
            identity = self.runner.add()
            self.runner.list_transform = lambda _raw: raw
            instance = adapter.DockerBackend(Path("/protected/profile.json"), permit=self.permits, runner=self.runner, popen_factory=self.spawn)
            with self.subTest(raw=raw), self.assertRaises(adapter.DockerBackendError):
                instance.destroy(identity)

    def test_blob_transfers_are_explicitly_unsupported_without_copying_paths(self):
        identity = self.runner.add()
        for operation in (self.backend.stage_input, self.backend.collect_output):
            with self.assertRaises(adapter.DockerBackendUnsupported):
                operation(identity, ArtifactReference(DIGEST))
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.spawn_calls, [])


@unittest.skipUnless(os.name == "posix", "requires isolated POSIX subprocess fixtures")
class NativeSessionTest(unittest.TestCase):
    def make_session(self, script, *, timeout=0.2, maximum=1024):
        child = adapter._spawn([sys.executable, "-I", "-c", script],
                               env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        session = adapter.NativeSession(child, timeout=timeout, output_limit=maximum,
                                        lease=contextlib.ExitStack())
        self.addCleanup(session.close)
        return session

    def test_public_process_cannot_reap_pid_reservation_and_cancel_closes_live_pipes(self):
        session = self.make_session("import time;time.sleep(2)")
        with self.assertRaises(adapter.DockerBackendError):
            session.process.poll()
        with self.assertRaises(adapter.DockerBackendError):
            session.process.wait(timeout=0)
        session.cancel()
        self.assertIsNotNone(session.process.returncode)
        self.assertTrue(all(stream.closed for stream in (session.stdin, session.stdout, session.stderr)))

    def test_output_overrun_kills_owned_native_client_and_is_bounded(self):
        session = self.make_session("import os,time;os.write(1,b'x'*4096);time.sleep(2)", maximum=32)
        with self.assertRaisesRegex(adapter.DockerBackendError, "output byte limit"):
            session.stdout.read(4096)
        session.close()
        self.assertIsNotNone(session.process.returncode)

    def test_native_deadline_terminates_client_without_claiming_guest_cleanup(self):
        session = self.make_session("import time;time.sleep(2)")
        with self.assertRaisesRegex(adapter.DockerBackendError, "deadline"):
            session.stdout.read(1)
        session.close()
        self.assertIsNotNone(session.process.returncode)

    def test_concurrent_blocked_reader_is_released_by_cancel(self):
        session = self.make_session("import time;time.sleep(3)", timeout=2)
        failures = []
        entered = threading.Event()

        def read():
            entered.set()
            try:
                session.stdout.read(1)
            except (adapter.DockerBackendError, OSError, ValueError) as exc:
                failures.append(exc)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        self.assertTrue(entered.wait(0.5))
        session.cancel()
        reader.join(timeout=0.5)
        self.assertFalse(reader.is_alive(), "cancel left a native reader blocked")
        self.assertIsNotNone(session.process.returncode)

    def test_control_runner_captures_separate_output_and_reaps_its_owned_child(self):
        original_spawn = adapter._spawn
        children = []

        def observed_spawn(argv, *, env):
            child = original_spawn(argv, env=env)
            children.append(child)
            return child

        with mock.patch.object(adapter, "_spawn", side_effect=observed_spawn):
            result = adapter._run_control(
                [sys.executable, "-I", "-c", "import os,sys;os.write(1,b'out');os.write(2,b'err');sys.exit(7)"],
                env={"PATH": "/usr/bin:/bin"}, timeout_seconds=0.2,
                max_stdout_bytes=1024, max_stderr_bytes=1024,
            )
        self.assertEqual((result.returncode, result.stdout, result.stderr), (7, b"out", b"err"))
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].returncode, 7)
        self.assertTrue(all(stream.closed for stream in (children[0].stdin, children[0].stdout, children[0].stderr)))

    def test_control_runner_output_cap_cancels_and_reaps_before_returning_failure(self):
        original_spawn = adapter._spawn
        children = []

        def observed_spawn(argv, *, env):
            child = original_spawn(argv, env=env)
            children.append(child)
            return child

        with mock.patch.object(adapter, "_spawn", side_effect=observed_spawn):
            with self.assertRaisesRegex(adapter.DockerBackendError, "output byte limit"):
                adapter._run_control(
                    [sys.executable, "-I", "-c", "import os,time;os.write(1,b'x'*4096);time.sleep(2)"],
                    env={"PATH": "/usr/bin:/bin"}, timeout_seconds=0.2,
                    max_stdout_bytes=32, max_stderr_bytes=32,
                )
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(all(stream.closed for stream in (children[0].stdin, children[0].stdout, children[0].stderr)))


if __name__ == "__main__":
    unittest.main()
