#!/usr/bin/env python3
"""Real supervisor → native relay → durable outbox, in the isolated runner."""
from __future__ import annotations

import json
import dataclasses
import os
from pathlib import Path
import runpy
import threading
import time
import struct
import subprocess
import sys
import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "bin")]
from startup_factory_cli.sandbox_registry import SandboxRegistry  # noqa: E402
from sandbox_ingest import BoundContext  # noqa: E402
from sandbox_transport import RelayContext, RelayLimits, project_id_for_repository  # noqa: E402
from outbox_capability import verify_entry  # noqa: E402
from outbox_capability import active_record  # noqa: E402
from startup_factory_cli.execution_backend import DockerProfile, GuestCommand  # noqa: E402
from startup_factory_cli.sandbox_deployment import canonical_bytes  # noqa: E402
import sandbox_client as client  # noqa: E402
import sandbox_service as service  # noqa: E402

FIXTURE = runpy.run_path(str(ROOT / "tests/publication-supervisor-test.py"), run_name="relay_fixture")
BIN = ROOT / "bin"


class SandboxNativeRelayTest(unittest.TestCase):
    # Reuse only the lifecycle/peer-auth fixture, not its full inherited suite.
    for _method in ("setUp", "mint_gate", "start", "wait_for", "stop_process", "finish"):
        locals()[_method] = FIXTURE["PublicationSupervisorTest"].__dict__[_method]

    def context(self):
        registry_path = self.lifecycle / "sandbox-registry"
        registry_path.mkdir(mode=0o700)
        registry = SandboxRegistry(registry_path, "sf-native-test")
        self.addCleanup(registry.close)
        scope = {"projectId": project_id_for_repository(self.repository), "team": FIXTURE["TEAM"],
                 "featureId": FIXTURE["FEATURE"], "role": FIXTURE["ROLE"], "taskId": self.entry["taskId"], "attempt": 1}
        with registry.locked() as transaction:
            epoch = transaction.takeover()
            record = transaction.reserve(scope, epoch=epoch)
            record = transaction.bind(record["name"], record["generation"], epoch,
                sandbox_id=str(uuid.uuid4()), created_at="2026-11-17T01:01:11+01:00")
            transaction.transition(record["name"], record["generation"], epoch, state="ready")
            record = transaction.transition(record["name"], record["generation"], epoch, state="running")
            registry_id = transaction.registry_id
        bound = BoundContext(repository=self.repository, workspace=self.workspace, team=FIXTURE["TEAM"],
            feature=FIXTURE["FEATURE"], role=FIXTURE["ROLE"], task=self.entry["taskId"], attempt=1,
            generation=record["generation"], transport=self.locator)
        context = RelayContext.from_dict({"schemaVersion": 1, "registryRoot": str(registry_path),
            "registryId": registry_id, "namespace": registry.namespace, "name": record["name"],
            "generation": record["generation"], "epoch": epoch, "sandboxId": record["sandboxId"],
            "createdAt": record["createdAt"], "scope": scope, "boundContext": bound.as_dict(),
            "allowedArtifacts": {"architecture-approval": [None]},
            "watchdog": {"deploymentPath": "/fixture/deployment.json", "leaseId": "1" * 32, "deadline": 2524608000},
            "limits": RelayLimits(wall_seconds=5).as_dict()})
        path = registry_path / "relay-context.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(context.as_dict(), stream)
        return registry, epoch, record, path

    def request(self, identifier="a" * 32):
        return {"schemaVersion": 1, "id": identifier, "operation": "artifact.submit",
                "marker": "architecture-approval", "bodyHex": FIXTURE["BODY"].hex(), "targetStatus": None}

    @staticmethod
    def framed(request):
        raw = json.dumps(request, separators=(",", ":")).encode()
        return struct.pack("!I", len(raw)) + raw

    def decode(self, raw):
        self.assertGreaterEqual(len(raw), 4, raw)
        size = struct.unpack("!I", raw[:4])[0]
        self.assertEqual(len(raw), size + 4)
        return json.loads(raw[4:])

    def test_sandbox_native_descendant_admits_and_exact_retry_survives_fence(self):
        registry, epoch, record, context_path = self.context()
        shim = self.root / "relay-shim.py"
        shim.write_text("""import json,os,pathlib,struct,subprocess,sys
request={'schemaVersion':1,'id':'a'*32,'operation':'artifact.submit','marker':'architecture-approval','bodyHex':pathlib.Path(sys.argv[3]).read_bytes().hex(),'targetStatus':None}
raw=json.dumps(request,separators=(',',':')).encode()
bootstrap="import sys,runpy;sys.path.insert(0,sys.argv[1]);import sandbox_transport as t;t.verify_watchdog_lease=lambda *a,**k:True;sys.argv=[sys.argv[1]+'/sandbox-relay.py','--context',sys.argv[2]];runpy.run_path(sys.argv[0],run_name='__main__')"
result=subprocess.run([sys.executable,'-I','-B','-c',bootstrap,sys.argv[1],os.environ['TEST_RELAY_CONTEXT']],input=struct.pack('!I',len(raw))+raw,capture_output=True,timeout=7)
if result.returncode:sys.stderr.buffer.write(result.stderr);raise SystemExit(result.returncode)
pathlib.Path(sys.argv[4]).write_bytes(result.stdout)
""")
        output = self.root / "relay-result"
        process = self.start(shim, output, self.root / "unused-go", "relay", extra_environment={"TEST_RELAY_CONTEXT": str(context_path)})
        self.finish(process)
        receipt = self.decode(output.read_bytes())
        self.assertEqual(receipt["status"], "admitted")
        self.assertNotIn(str(self.repository), json.dumps(receipt))
        pending = list((self.workspace / "outbox/pending").glob("*.json"))
        self.assertEqual(len(pending), 1)
        entry = json.loads(pending[0].read_text())
        verified = verify_entry(str(self.repository), str(self.workspace), entry, FIXTURE["BODY_DIGEST"])
        self.assertEqual(verified["role"], FIXTURE["ROLE"])
        with registry.locked() as transaction:
            transaction.fence(record["name"], record["generation"], epoch)
        # This process is deliberately not a supervisor descendant. It can
        # recover this exact prior admission, but cannot mint another one.
        replay = subprocess.run([sys.executable, "-I", "-B", str(BIN / "sandbox-relay.py"), "--context", str(context_path)],
            input=self.framed(self.request()), capture_output=True, timeout=7)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(self.decode(replay.stdout), receipt)
        fresh = subprocess.run([sys.executable, "-I", "-B", str(BIN / "sandbox-relay.py"), "--context", str(context_path)],
            input=self.framed(self.request("b" * 32)), capture_output=True, timeout=7)
        self.assertNotEqual(fresh.returncode, 0)
        self.assertEqual(len(list((self.workspace / "outbox/pending").glob("*.json"))), 1)

    def test_sandbox_protected_context_alone_cannot_replace_native_peer_authentication(self):
        _registry, _epoch, _record, context_path = self.context()
        result = subprocess.run([sys.executable, "-I", "-B", str(BIN / "sandbox-relay.py"), "--context", str(context_path)],
            input=self.framed(self.request()), capture_output=True, timeout=7)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(str(self.repository).encode(), result.stdout + result.stderr)
        self.assertEqual(list((self.workspace / "outbox/pending").glob("*.json")), [])

    def test_real_job_socket_native_client_and_relay_require_supervisor_descendance(self):
        _registry, _epoch, _record, context_path = self.context()
        context = RelayContext.from_file(context_path)
        data = json.loads((ROOT / "config/sandbox.config.example.json").read_bytes())
        data.update(controllerUid=os.geteuid(), namespace=context.namespace)
        profile = DockerProfile.from_dict(data)
        job_root = self.lifecycle / "jobs"
        job_root.mkdir(mode=0o700)
        bundle = self.root / "fixture-bundle"
        (bundle / "bin").mkdir(parents=True, mode=0o700)
        # Only the test watchdog authority is substituted. The actual shipped
        # native relay, ingest, supervisor socket and kernel ancestry checks run.
        (bundle / "bin/sandbox-relay.py").write_text(
            "import sys,runpy\n"
            f"sys.path.insert(0,{str(BIN)!r})\n"
            "import sandbox_transport as t\n"
            "t.verify_watchdog_lease=lambda *a,**k:True\n"
            f"runpy.run_path({str(BIN / 'sandbox-relay.py')!r},run_name='__main__')\n")
        deployment = SimpleNamespace(controller_uid=os.geteuid(), controller_gid=os.getegid(),
            registry_root=str(context.registry_root), job_root=str(job_root),
            socket_path=str(self.lifecycle / "j.sock"), profile_path="/fixture/profile.json",
            source_path=Path("/fixture/deployment.json"), max_active_jobs=1, max_queued_jobs=4,
            job_request_max_bytes=256 * 1024, digest="sha256:" + "d" * 64,
            account_home=str(self.lifecycle), lifecycle_root=str(self.lifecycle), bundle_root=str(bundle),
            programs={"python": {"path": sys.executable}},
            projects=({"projectId": context.scope.project_id, "repository": str(self.repository),
                       "workspaceRoot": str(self.workspace.parent)},))
        binding = {"schemaVersion": 1, "backend": profile.backend, "namespace": context.namespace,
            "name": context.name, "sandboxId": context.sandbox_id, "createdAt": context.created_at,
            "generation": context.generation, "epoch": context.epoch, "profileDigest": profile.digest,
            "policyDigest": profile.policy_digest, "image": profile.image, "inputDigest": "sha256:" + "e" * 64,
            "baseCommit": "1" * 40, "state": "ready", "acceptedCommit": None,
            "acceptedTree": None, "acceptedExportDigest": None}
        with _registry.locked() as transaction:
            second = transaction.reserve(context.scope.as_dict(), epoch=_epoch)
            second = transaction.bind(second["name"], second["generation"], _epoch,
                sandbox_id=str(uuid.uuid4()), created_at=context.created_at)
            transaction.transition(second["name"], second["generation"], _epoch, state="ready")
            transaction.transition(second["name"], second["generation"], _epoch, state="running")
        outside_context = dataclasses.replace(context, name=second["name"], generation=second["generation"],
            sandbox_id=second["sandboxId"], bound=dataclasses.replace(context.bound, generation=second["generation"]))
        outside_binding = {**binding, "name": second["name"], "generation": second["generation"], "sandboxId": second["sandboxId"]}
        fixture = self
        class Executor:
            def __init__(inner):
                inner.profile = profile
            def run(inner, request, channel, cancel):
                selected, selected_binding = (context, binding) if request.id.endswith("a" * 32) else (outside_context, outside_binding)
                response = channel.request("bound", binding=selected_binding, relayContext=selected.as_dict())
                if response["raw"] != b"ack":
                    raise AssertionError("native client did not bind")
                raw = canonical_bytes(fixture.request(request.id[4:]))
                response = channel.request("publish", requestHex=raw.hex())
                return {"schemaVersion": 1, "jobId": request.id, "exitCode": 0,
                    "status": "fixture-admitted", "receipt": json.loads(response["raw"])}
            def close(inner):
                pass
        server = service.JobServer(deployment, Executor())
        thread = threading.Thread(target=server.serve, daemon=True)
        thread.start()
        def stop_server():
            server.stop(); thread.join(timeout=2); server.close()
        self.addCleanup(stop_server)
        self.wait_for(Path(deployment.socket_path))
        def write_request(identifier):
            value = {"schemaVersion": 1, "id": "job-" + identifier,
                "deploymentDigest": deployment.digest, "profileDigest": profile.digest,
                "kind": "review", "repository": str(self.repository), "workspace": str(self.workspace),
                "scope": context.scope.as_dict(), "baseCommit": binding["baseCommit"],
                "targetRef": "refs/heads/agent-task/fixture/review", "guestCommand": GuestCommand(("/usr/bin/true",)).as_dict(),
                "promptHex": "", "capabilityId": self.capability["id"], "transport": self.locator,
                "executionSha256": None}
            path = job_root / (value["id"] + ".request.json")
            path.write_bytes(canonical_bytes(value)); path.chmod(0o600)
            return path
        approved = write_request("a" * 32)
        outside = write_request("b" * 32)
        config = self.root / "rpc-client-fixture.json"
        config.write_text(json.dumps({"deployment": {**deployment.__dict__, "source_path": str(deployment.source_path)},
            "profile": profile.as_dict(), "request": str(approved)}))
        shim = self.root / "rpc-native-client.py"
        shim.write_text("""import json,os,pathlib,sys,time
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,str(pathlib.Path(sys.argv[1]).parent/'src'))
from startup_factory_cli.execution_backend import DockerProfile
import sandbox_client as c
value=json.loads(pathlib.Path(os.environ['TEST_RPC_CONFIG']).read_text())
deployment=SimpleNamespace(**value['deployment']);deployment.source_path=pathlib.Path(deployment.source_path)
profile=DockerProfile.from_dict(value['profile'])
c.load_profile=lambda _path:profile;c.verify_deployment=lambda *_args,**_kwargs:None
result=c.run_client(deployment,pathlib.Path(value['request']))
output=pathlib.Path(sys.argv[4]);pending=output.with_name(output.name+'.pending')
pending.write_text(json.dumps(result));os.replace(pending,output)
deadline=time.monotonic()+8
while not pathlib.Path(sys.argv[5]).exists():
 if time.monotonic()>deadline:raise SystemExit(81)
 time.sleep(.01)
""")
        output, release = self.root / "rpc-result.json", self.root / "rpc-release"
        process = self.start(shim, output, release, "rpc", extra_environment={"TEST_RPC_CONFIG": str(config)})
        try:
            self.wait_for(output)
            result = json.loads(output.read_bytes())
            self.assertEqual(result["receipt"]["status"], "admitted")
            # The original capability is still active. Therefore the following
            # denial establishes missing OS ancestry, not expiry/revocation.
            active_record(str(self.repository), str(self.workspace), self.capability["id"])
            with mock.patch.object(client, "load_profile", return_value=profile), mock.patch.object(client, "verify_deployment"):
                with self.assertRaises(service.ServiceError):
                    client.run_client(deployment, outside)
            pending = list((self.workspace / "outbox/pending").glob("*.json"))
            self.assertEqual(len(pending), 1)
            package = json.loads(pending[0].read_bytes())
            self.assertEqual(verify_entry(str(self.repository), str(self.workspace), package, FIXTURE["BODY_DIGEST"])["role"], FIXTURE["ROLE"])
        finally:
            release.touch()
            self.finish(process)


if __name__ == "__main__":
    unittest.main()
