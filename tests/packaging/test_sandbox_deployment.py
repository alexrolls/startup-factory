"""Deployment/qualification fixtures; run only in the bounded offline runner."""
from __future__ import annotations

import copy
from contextlib import contextmanager
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import tarfile
import plistlib
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli import sandbox_deployment as deployment  # noqa: E402
from startup_factory_cli import sandbox_qualification_evidence as evidence  # noqa: E402
from startup_factory_cli import sandbox_qualification_observer as observer  # noqa: E402
from startup_factory_cli import sandbox_deployment_installer as deployment_installer  # noqa: E402
from startup_factory_cli.installer import PRESERVED_CONFIG_FILES, EXTENSION_ROOTS  # noqa: E402
from startup_factory_cli.execution_backend import DockerProfile  # noqa: E402
from startup_factory_cli.sandbox_enrollment import profile_basis_digest  # noqa: E402
from startup_factory_cli.sandbox_registry import SandboxRegistry  # noqa: E402


NOW = 1_800_000_000
DIGEST = "sha256:" + "8" * 64


def profile_data(uid=1000):
    return {"schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1, "controllerUid": uid,
        "sbxPath": "/Library/StartupFactory/runtime/Sbx.app/Contents/MacOS/sbx", "sbxSha256": "2" * 64,
        "namespace": "sf-managed", "image": "registry.example.com/factory/agent@sha256:" + "3" * 64,
        "guestWorkdir": "/workspace/project", "limits": {"cpus": 1, "memoryMiB": 512, "rootDiskMiB": 2048,
        "dockerDiskMiB": 512, "wallSeconds": 30, "maxOutputBytes": 65536}, "policyDigest": DIGEST,
        "qualificationDigest": "sha256:" + "0" * 64}


def deployment_data(profile, root="/Library/StartupFactory"):
    home = root + "/state/home"
    bundle = root + "/bundle"
    return {"schemaVersion": 1, "backend": "docker-sandboxes", "namespace": profile.namespace,
        "profilePath": root + "/config/profile.json", "profileBasisDigest": profile_basis_digest(profile),
        "receiptPath": root + "/config/enrollment.json", "registryRoot": home + "/registry",
        "nativeJournalRoot": home + "/native", "socketPath": home + "/control.sock", "jobRoot": home + "/jobs",
        "watchdogSocketPath": home + "/watchdog.sock", "watchdogRoot": home + "/watchdog",
        "evidenceRoot": root + "/evidence", "controllerUid": profile.controller_uid, "controllerGid": profile.controller_uid,
        "accountName": "_sf_factory", "accountHome": home, "bundleRoot": bundle, "bundleDigest": DIGEST,
        "runtimeRoot": str(Path(profile.sbx_path).parents[2]), "runtimeDigest": DIGEST,
        "modelCredentials": {"providers": {}, "roles": {}},
        "credentialRoot": home + "/credentials",
        "lifecycleRoot": home + "/lifecycle",
        "networkPolicyPath": root + "/config/network-policy.json",
        "programs": {name: {"path": path, "sha256": "4" * 64} for name, path in {
            "python": "/usr/bin/python3", "gate": bundle + "/bin/sandbox-native-gate.py",
            "lifecycleHelper": bundle + "/bin/process-lifecycle.py", "runner": bundle + "/bin/sandbox-custody.py",
            "watchdog": bundle + "/bin/sandbox-watchdog.py"}.items()},
        "projects": [{"projectId": DIGEST, "repository": home + "/projects/fixture", "workspaceRoot": home + "/projects/fixture/.teamwork"}],
        "maxActiveJobs": 1, "maxQueuedJobs": 4, "jobRequestMaxBytes": 65536,
        "storage": {"mountPoint": root + "/state", "volumeUuid": "11111111-2222-3333-4444-555555555555",
            "quotaBytes": 8 * 1024**3, "minimumFreeBytes": 4 * 1024**3}}


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        self.profile = DockerProfile.from_dict(profile_data())
        self.data = deployment_data(self.profile)

    def parse(self, value=None):
        return deployment.Deployment(Path("/Library/StartupFactory/deployment.json"), deployment.canonical_bytes(self.data if value is None else value))

    def test_closed_manifest_raw_digest_and_returned_values_are_snapshots(self):
        selected = self.parse()
        self.assertEqual(selected.controller_uid, 1000)
        self.assertEqual(selected.native_journal_root, self.data["nativeJournalRoot"])
        selected.programs["python"]["sha256"] = "0" * 64
        selected.projects[0]["repository"] = "/unapproved"
        self.assertEqual(selected.as_dict(), self.data)
        padded = deployment.Deployment(selected.source_path, selected.raw + b" ")
        self.assertNotEqual(selected.digest, padded.digest)
        self.assertEqual(selected.as_dict(), padded.as_dict())

    def test_unsafe_authority_identity_paths_and_unbounded_fields_are_denied(self):
        changes = [
            lambda value: value.update(enabled=True), lambda value: value.update(controllerUid=True),
            lambda value: value.update(namespace="sf-qualification"), lambda value: value.update(accountName="aischenko"),
            lambda value: value.update(nativeJournalRoot=value["registryRoot"]),
            lambda value: value.update(receiptPath=value["accountHome"] + "/receipt.json"),
            lambda value: value.update(maxActiveJobs=0), lambda value: value.update(jobRequestMaxBytes=True),
            lambda value: value["projects"].append(copy.deepcopy(value["projects"][0])),
            lambda value: value["programs"]["runner"].update(path=value["bundleRoot"] + "/bin/untrusted.py"),
            lambda value: value["storage"].update(quotaBytes=0),
        ]
        for change in changes:
            value = copy.deepcopy(self.data); change(value)
            with self.subTest(value=str(value)[:100]), self.assertRaises(deployment.DeploymentError):
                self.parse(value)

    def test_strict_json_rejects_duplicate_depth_float_and_surrogate(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.1}', b'{"x":"\\ud800"}', b'{"x":' + b'[' * 20 + b'0' + b']' * 20 + b'}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(deployment.DeploymentError):
                deployment.decode_object(raw)

    def test_preparation_has_concrete_fixed_arguments_and_never_enables_a_service(self):
        plan = deployment.preparation_plan(self.parse())
        self.assertFalse(plan["qualified"])
        self.assertFalse(plan["serviceStartAllowed"])
        self.assertEqual(plan["programArguments"][-3:], ["serve", "--deployment", "/Library/StartupFactory/deployment.json"])
        self.assertTrue(all(command[0] == "/usr/bin/dscl" for command in plan["accountCommands"]))
        self.assertFalse(any("-passwd" in command for command in plan["accountCommands"]))

    def test_private_directory_rejects_symlinks_writable_components_and_wrong_owner(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd())) as temporary:
            root = Path(temporary); root.chmod(0o700)
            private = root / "private"; private.mkdir(mode=0o700)
            self.assertEqual(deployment.private_directory(private, os.geteuid()), (private.stat().st_dev, private.stat().st_ino))
            alias = root / "alias"; alias.symlink_to(private)
            with self.assertRaises((deployment.DeploymentError, OSError)):
                deployment.private_directory(alias, os.geteuid())
            root.chmod(0o777)
            with self.assertRaises(deployment.DeploymentError):
                deployment.private_directory(private, os.geteuid())
            root.chmod(0o700)
            with self.assertRaises(deployment.DeploymentError):
                deployment.private_directory(private, os.geteuid() + 1)

    def test_nonroot_cannot_issue_or_write_enrollment(self):
        self.assertNotEqual(os.geteuid(), 0, "use the assigned nonroot isolated runner")
        with self.assertRaisesRegex(evidence.QualificationEvidenceError, "root"):
            evidence.issue_enrollment(self.parse())

    def test_unloaded_launchd_arguments_use_exact_pins_and_private_environment(self):
        candidates = deployment_installer.launchd_candidates(self.parse())
        self.assertEqual(len(candidates), 2)
        for raw in candidates.values():
            value = plistlib.loads(raw)
            self.assertFalse(value["RunAtLoad"])
            self.assertFalse(value["KeepAlive"])
            self.assertEqual(value["UserName"], "_sf_factory")
            self.assertEqual(value["Umask"], 0o077)
            self.assertEqual(value["ProgramArguments"][-3:], ["serve", "--deployment", "/Library/StartupFactory/deployment.json"])
            self.assertEqual(set(value["EnvironmentVariables"]), {"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "SBX_NO_TELEMETRY", "STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"})

    def test_installer_snapshot_rejects_links_fifo_oversize_and_hash_drift(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd())) as temporary:
            root = Path(temporary)
            regular = root / "regular"; regular.write_bytes(b"data")
            self.assertEqual(deployment_installer._bounded_input(regular, 4), b"data")
            with self.assertRaises(deployment.DeploymentError):
                deployment_installer._bounded_input(regular, 3)
            linked = root / "linked"; linked.symlink_to(regular)
            with self.assertRaises(OSError):
                deployment_installer._bounded_input(linked, 4)
            linked.unlink(); os.link(regular, linked)
            with self.assertRaises(deployment.DeploymentError):
                deployment_installer._bounded_input(regular, 4)
            fifo = root / "fifo"; os.mkfifo(fifo)
            with self.assertRaises(deployment.DeploymentError):
                deployment_installer._bounded_input(fifo, 4)

    def test_release_preparation_computes_all_source_pins_without_installing(self):
        payload = {"SKILL.md": b"---\nname: startup-factory\n---\n", **{path: b"{}\n" for path in PRESERVED_CONFIG_FILES}}
        payload["config/team.config.md"] = ("AGENT_EXECUTION_BACKEND=docker-sandboxes\nAGENT_SANDBOX_ENFORCED=true\n"
            f"AGENT_SANDBOX_DEPLOYMENT={self.parse().source_path}\nBROKER_LIFECYCLE_ROOT={self.parse().lifecycle_root}\n"
            "SANDBOX_DEFAULT_CMD=codex exec --model qualification-model < {prompt_file}\n").encode()
        payload.update({"bin/" + name: b"# fixed reviewed fixture\n" for name in ("sandbox-native-gate.py", "process-lifecycle.py", "sandbox-custody.py", "sandbox-watchdog.py")})
        records = [{"path": path, "size": len(raw), "mode": "0755" if path.startswith("bin/") else "0644", "sha256": hashlib.sha256(raw).hexdigest()} for path, raw in sorted(payload.items())]
        manifest = {"schemaVersion": 1, "name": "startup-factory", "version": "1.0.0", "sourceRepository": "https://example.invalid/fixture",
            "sourceCommit": "1" * 40, "preservationPolicy": {"version": 1, "preservedConfigFiles": list(PRESERVED_CONFIG_FILES), "extensionRoots": list(EXTENSION_ROOTS)},
            "requiredPaths": ["SKILL.md", "bin/"], "files": records}
        payload[".startup-factory-bundle.json"] = deployment.canonical_bytes(manifest)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for path, raw in payload.items():
                info = tarfile.TarInfo("startup-factory/" + path); info.size = len(raw)
                info.mode = 0o755 if path.startswith("bin/") else 0o644
                archive.addfile(info, io.BytesIO(raw))
        with tempfile.TemporaryDirectory(dir=os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd())) as temporary:
            archive = Path(temporary) / "reviewed.tar.gz"; archive.write_bytes(stream.getvalue())
            with self.assertRaises(deployment.DeploymentError):
                deployment_installer.prepare_bundle_pins(self.parse(), self.profile, archive, archive_sha256="0" * 64)
            result = deployment_installer.prepare_bundle_pins(self.parse(), self.profile, archive, archive_sha256=hashlib.sha256(stream.getvalue()).hexdigest())
        self.assertFalse(result["qualified"])
        self.assertEqual(result["files"], len(payload))
        self.assertEqual(result["preparedDeployment"]["programs"]["runner"]["sha256"], hashlib.sha256(payload["bin/sandbox-custody.py"]).hexdigest())
        self.assertNotEqual(result["preparedDeployment"]["bundleDigest"], self.data["bundleDigest"])

    def test_release_default_native_config_cannot_be_pinned_as_docker_deployment(self):
        with self.assertRaisesRegex(deployment.DeploymentError, "deployment-specific"):
            deployment_installer.validate_release_configuration({"config/team.config.md": (ROOT / "config/team.config.md").read_bytes()}, self.parse())
        valid = ("AGENT_EXECUTION_BACKEND=docker-sandboxes\nAGENT_SANDBOX_ENFORCED=true\n"
            f"AGENT_SANDBOX_DEPLOYMENT={self.parse().source_path}\nBROKER_LIFECYCLE_ROOT={self.parse().lifecycle_root}\n"
            "SANDBOX_DEFAULT_CMD=codex exec < {prompt_file}\n").encode()
        deployment_installer.validate_release_configuration({"config/team.config.md": valid}, self.parse())
        with self.assertRaises(deployment.DeploymentError):
            deployment_installer.validate_release_configuration({"config/team.config.md": valid.replace(self.parse().lifecycle_root.encode(), b"/wrong/lifecycle")}, self.parse())


class StorageAndHistoryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("SF_REGISTRY_TEST_ROOT"))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.root.chmod(0o700)
        self.profile = DockerProfile.from_dict(profile_data(os.geteuid()))
        self.selected = deployment.Deployment(self.root / "deployment.json", deployment.canonical_bytes(deployment_data(self.profile, str(self.root))))
        data = self.selected.as_dict()
        paths = [data["accountHome"], *(data[key] for key in deployment._PRIVATE_ROOTS),
            *(project[key] for project in data["projects"] for key in ("repository", "workspaceRoot"))]
        for path in paths:
            Path(path).mkdir(mode=0o700, parents=True, exist_ok=True)
        self.handles = []
        self.native = None
        for path, filename, kind in ((self.selected.native_journal_root, "native-clients.json", "native"),
                (self.selected.credential_root, "model-credentials.json", "credentials")):
            registry = SandboxRegistry(Path(path), self.selected.namespace); self.handles.append(registry)
            self.addCleanup(registry.close)
            with registry.locked() as tx:
                tx.takeover()
                if kind == "native":
                    from startup_factory_cli.execution_backend import canonical_digest
                    state = {"schemaVersion": 2, "journalId": tx.registry_id,
                        "profileBasisDigest": self.selected.profile_basis_digest,
                        "toolsDigest": canonical_digest({key: self.selected.programs[key] for key in ("python", "gate", "lifecycleHelper")}),
                        "revision": 0, "records": {}}
                    self.native, self.native_state = registry, state
                else:
                    state = {"schemaVersion": 1, "deploymentDigest": self.selected.digest, "revision": 0, "leases": {}}
                target = Path(path) / filename; target.write_bytes(deployment.canonical_bytes(state)); target.chmod(0o600)

    def test_all_project_and_private_paths_share_enrolled_device(self):
        deployment.verify_storage_paths(self.selected)
        repository = Path(self.selected.projects[0]["repository"])
        inode = repository.stat().st_ino
        original = os.fstat
        def changed_device(fd):
            info = original(fd)
            if info.st_ino == inode:
                return SimpleNamespace(st_uid=info.st_uid, st_mode=info.st_mode, st_dev=info.st_dev + 1)
            return info
        with mock.patch.object(deployment.os, "fstat", side_effect=changed_device), self.assertRaises(deployment.DeploymentError):
            deployment.verify_storage_paths(self.selected)

    def test_quiescent_main_and_model_histories_pass_but_unlocked_unknown_or_pending_fail(self):
        evidence.verify_quiescent_histories(self.selected)
        with self.native.locked(), self.assertRaises(BlockingIOError):
            evidence.verify_quiescent_histories(self.selected)
        root = Path(self.selected.native_journal_root)
        pending = root / ".native-clients.pending"; pending.write_bytes(b"uncertain"); pending.chmod(0o600)
        with self.assertRaises(evidence.QualificationEvidenceError):
            evidence.verify_quiescent_histories(self.selected)
        pending.unlink()
        bad = dict(self.native_state, schemaVersion=1)
        (root / "native-clients.json").write_bytes(deployment.canonical_bytes(bad))
        with self.assertRaises(RuntimeError):
            evidence.verify_quiescent_histories(self.selected)
        bad = dict(self.native_state, records={"native-" + "a" * 32: {"state": "completed-acknowledged"}})
        (root / "native-clients.json").write_bytes(deployment.canonical_bytes(bad))
        with self.assertRaises(RuntimeError):
            evidence.verify_quiescent_histories(self.selected)

    def test_derived_watchdog_native_history_is_checked_when_present(self):
        root = Path(self.selected.watchdog_root) / "native-clients"; root.mkdir(mode=0o700)
        registry = SandboxRegistry(root, self.selected.namespace); self.addCleanup(registry.close)
        with registry.locked() as tx:
            state = dict(self.native_state, journalId=tx.registry_id)
            tx.takeover()
        target = root / "native-clients.json"; target.write_bytes(deployment.canonical_bytes(state)); target.chmod(0o600)
        evidence.verify_quiescent_histories(self.selected)
        pending = root / ".native-clients.pending"; pending.write_bytes(b"uncertain"); pending.chmod(0o600)
        with self.assertRaises(evidence.QualificationEvidenceError):
            evidence.verify_quiescent_histories(self.selected)


class LiveEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-live-evidence-", dir=os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd()))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.root.chmod(0o700)
        self.profile = DockerProfile.from_dict(profile_data(os.geteuid()))
        self.data = deployment_data(self.profile, str(self.root))
        self.selected = deployment.Deployment(self.root / "deployment.json", deployment.canonical_bytes(self.data))
        self.binding = {"root": self.selected.registry_root, "device": 1, "inode": 2, "registryId": "reg-" + "9" * 32}
        self.artifact = b"fixed redacted dummy probe results\n"
        patch = mock.patch.object(evidence, "read_root_protected", return_value=(self.artifact, hashlib.sha256(self.artifact).hexdigest()))
        patch.start(); self.addCleanup(patch.stop)
        self.artifact_reader = patch

    def document(self, gate, observations):
        return {"schemaVersion": 1, "kind": "root-reviewed-live-qualification", "gateId": gate, "method": evidence.METHODS[gate],
            "deploymentDigest": self.selected.digest, "profileBasisDigest": self.selected.profile_basis_digest,
            "controllerUid": self.selected.controller_uid, "namespace": self.selected.namespace, "registry": self.binding,
            "observedAt": NOW - 10, "validUntil": NOW + 100, "review": {"reviewerUid": 0, "scope": "actual-dedicated-macos-host"},
            "artifacts": [{"path": self.selected.evidence_root + "/probe.log", "sha256": deployment.digest_bytes(self.artifact)}], "observations": observations}

    def verify(self, value, **kwargs):
        return evidence.verify_live_evidence(deployment.canonical_bytes(value), value["gateId"], self.selected, self.profile, self.binding, now=NOW, **kwargs)

    def test_generic_pass_or_vm_smoke_cannot_become_qualification(self):
        for value in ({"passed": True}, {"schemaVersion": 1, "reportKind": "manual-startup-factory-docker-sandboxes-smoke", "passed": True}):
            with self.assertRaises(evidence.QualificationEvidenceError):
                evidence.verify_live_evidence(deployment.canonical_bytes(value), "exec-protocol", self.selected, self.profile, self.binding, now=NOW)

    def test_network_probes_need_complete_cases_positive_controls_and_expected_outcomes(self):
        observations = {"policyDigest": self.profile.policy_digest, "policyInstalledSequence": 1, "firstGuestSequence": 2,
            "probes": [{"case": key, "positiveControlReached": True, "guestReached": key == "approved-dummy-model", "policyDecision": "allow" if key == "approved-dummy-model" else "deny"} for key in sorted(evidence.POLICY_CASES)]}
        value = self.document("policy-before-execution", observations)
        self.verify(value)
        for mutate in (lambda data: data["observations"]["probes"].pop(),
                       lambda data: data["observations"].update(firstGuestSequence=1),
                       lambda data: data["observations"]["probes"][0].update(positiveControlReached=False),
                       lambda data: next(case for case in data["observations"]["probes"] if case["case"] == "public-ipv4").update(guestReached=True)):
            changed = copy.deepcopy(value); mutate(changed)
            with self.assertRaises(evidence.QualificationEvidenceError):
                self.verify(changed)

    def test_changed_raw_evidence_digest_expiry_binding_and_scope_are_denied(self):
        observations = {"image": self.profile.image, "hostMounts": [], "runtimeMounts": [], "mcpServers": [],
            "skillsEnabled": False, "settings": {key: False for key in ("ssh.agentForwardingEnabled", "browser.enabled", "clipboard.imagePaste", "sandbox.fuse", "model.server.enabled")}, "guestRootCanaryHostReads": []}
        value = self.document("mountless-startup", observations)
        self.verify(value)
        for mutate in (lambda data: data.update(validUntil=NOW), lambda data: data.update(deploymentDigest=DIGEST),
                       lambda data: data["review"].update(scope="inside-test-vm"),
                       lambda data: data["artifacts"][0].update(sha256=DIGEST),
                       lambda data: data["observations"]["settings"].update({"model.server.enabled": True})):
            changed = copy.deepcopy(value); mutate(changed)
            with self.assertRaises(evidence.QualificationEvidenceError):
                self.verify(changed)

    def test_endpoint_evidence_rechecks_real_socket_inode_and_private_parent(self):
        home = Path(self.selected.account_home); home.mkdir(parents=True, mode=0o700)
        # Intermediate fixture state root belongs to this worker and is protected.
        home.parent.chmod(0o700); home.chmod(0o700)
        selected = home / "daemon.sock"
        server = socket.socket(socket.AF_UNIX)
        self.addCleanup(server.close)
        server.bind(str(selected)); selected.chmod(0o600)
        info = selected.stat()
        observations = {"strategy": "dedicated-account-exclusive-controller", "endpoints": [{"path": str(selected), "device": info.st_dev, "inode": info.st_ino, "uid": os.geteuid(), "mode": 0o600}],
            "ordinaryUidProbes": [{"uid": os.geteuid() + 1, "path": str(selected), "connectErrno": errno.EACCES}], "guestControlAccess": False,
            "faultCases": [{"case": key, "unexpectedNativeDispatches": 0} for key in sorted(evidence.IDENTITY_CASES)]}
        value = self.document("object-identity", observations)
        self.verify(value)
        changed = copy.deepcopy(value); changed["observations"]["endpoints"][0]["inode"] += 1
        with self.assertRaises(evidence.QualificationEvidenceError):
            self.verify(changed)
        changed = copy.deepcopy(value); changed["observations"]["ordinaryUidProbes"][0]["connectErrno"] = errno.ENOENT
        with self.assertRaises(evidence.QualificationEvidenceError):
            self.verify(changed)
        selected.chmod(0o666)
        with self.assertRaises(evidence.QualificationEvidenceError):
            self.verify(value)

    def test_credentials_need_dummy_scoped_access_and_no_global_fallback(self):
        observations = {"principalKind": "dummy-only", "globalProviderSecrets": [], "guestPlaintextCredentialReads": [],
            "privilegedServiceAccess": [], "scopedDummyRequestReceived": True, "afterScopedRemovalStatus": 401,
            "agentUid": 2000, "modelCliSha256": "a" * 64, "modelCliRequestSucceeded": True,
            "tlsProxySentinelObserved": True, "caTrusted": True, "dummyModelResponseDigest": DIGEST,
            "quotaDeniedAt": 3, "quotaLimit": 3, "externalMacBrokerFixture": "authenticated-native-peer-only"}
        value = self.document("credentials", observations); self.verify(value)
        for mutate in (lambda data: data["observations"].update(globalProviderSecrets=["openai"]),
                       lambda data: data["observations"].update(afterScopedRemovalStatus=200),
                       lambda data: data["observations"].update(agentUid=1000),
                       lambda data: data["observations"].update(caTrusted=False),
                       lambda data: data["observations"].update(modelCliRequestSucceeded=False),
                       lambda data: data["observations"].update(externalMacBrokerFixture="inside-vm-only")):
            changed = copy.deepcopy(value); mutate(changed)
            with self.assertRaises(evidence.QualificationEvidenceError):
                self.verify(changed)

    def test_transport_cleanup_and_hard_storage_semantics_are_not_generic_pass_flags(self):
        values = {
            "exec-protocol": {"nonTty": True, "maxFrameBytes": 65536, "cases": [{"case": key, "expectedDigest": DIGEST, "observedDigest": DIGEST, "elapsedMillis": 100, "nativeChildrenRemaining": 0} for key in sorted(evidence.TRANSPORT_CASES)]},
            "cancellation-cleanup": {"independentWatchdog": "external-process", "serverReconciliation": "daemon-barrier-and-positive-empty-inventory", "cases": [{"case": key, "publicationFencedBeforeStop": True, "queuedCommandsAfterBarrier": 0, "remainingOwnedSandboxes": [], "remainingOwnedPorts": [], "storageReconciled": True} for key in sorted(evidence.LIFECYCLE_CASES)]},
            "resource-limits": {"cpus": 1, "memoryMiB": 512, "rootDiskMiB": 2048, "dockerDiskMiB": 512, "outputBytes": 1024,
                "volumeUuid": self.selected.storage["volumeUuid"], "quotaBytes": self.selected.storage["quotaBytes"], "coveredWritableRoots": [self.selected.account_home],
                "guestRootPressureErrno": errno.ENOSPC, "hostPressureBytes": 2 * 1024**3, "hostMinimumFreeBytes": 5 * 1024**3, "retainedBytesAfterCleanup": 1024,
                "maxConcurrentJobs": 1, "hostPhysicalMemoryMiB": 8192, "hostReservedMemoryMiB": 2048, "hostLogicalCpus": 8},
        }
        for gate, observations in values.items():
            value = self.document(gate, observations); self.verify(value)
            with self.assertRaises(evidence.QualificationEvidenceError):
                self.verify({**value, "observations": {"passed": True}})
        changed = self.document("resource-limits", {**values["resource-limits"], "cpus": True})
        with self.assertRaises(evidence.QualificationEvidenceError):
            self.verify(changed)

    def test_platform_proof_is_exact_current_supported_mac_os_not_vm_linux(self):
        observed = {"system": "Darwin", "architecture": "arm64", "osVersion": "15.7.1", "kernelRelease": "24.6.0", "pythonVersion": "3.12.0", "cliVersion": "v0.54.0",
            "daemonVersion": "v0.54.0", "runtimeSha256": self.profile.sbx_sha256, "signatureTeamId": "9BNSXJN65R", "notarized": True}
        value = self.document("version-platform", observed)
        with mock.patch.object(evidence, "platform", SimpleNamespace(system=lambda: "Darwin", machine=lambda: "arm64", mac_ver=lambda: ("15.7.1", (), ""), release=lambda: "24.6.0")):
            self.verify(value)
            changed = copy.deepcopy(value); changed["observations"]["architecture"] = "x86_64"
            with self.assertRaises(evidence.QualificationEvidenceError):
                self.verify(changed)
        with self.assertRaises(evidence.QualificationEvidenceError):
            self.verify(value)

    def test_native_metadata_parser_needs_actual_false_values_and_exact_policy_pin(self):
        settings = [{"key": key, "type": "bool", "value": False} for key in sorted(observer.REQUIRED_DISABLED_SETTINGS)]
        self.assertEqual(set(observer.parse_settings(json.dumps(settings).encode())), observer.REQUIRED_DISABLED_SETTINGS)
        for records in (settings + [settings[0]], settings[:-1], [{**record, "value": 0} for record in settings]):
            with self.assertRaises(deployment.DeploymentError):
                observer.parse_settings(json.dumps(records).encode())
        from startup_factory_cli import sandbox_network_policy as network
        descriptor = network.parse_network_policy(deployment.canonical_bytes({"schemaVersion": 1, "namespace": self.profile.namespace,
            "preset": "deny-all", "provider": "openai", "rules": [{"host": "api.openai.com:443", "method": "POST", "path": "/v1/responses"}]}))
        policy = {"rules": [*network._filesystem_rows(), network._fallback()]}
        self.assertEqual(observer.parse_policy(json.dumps(policy).encode(), descriptor)["stage"], "global")
        with self.assertRaises(deployment.DeploymentError):
            observer.parse_policy(json.dumps({"rules": []}).encode(), descriptor)

    def test_apfs_metadata_requires_exact_mounted_volume_and_finite_quota(self):
        storage = self.selected.storage
        info = {"FilesystemType": "apfs", "MountPoint": storage["mountPoint"], "VolumeUUID": storage["volumeUuid"]}
        volumes = {"Containers": [{"Volumes": [{"APFSVolumeUUID": storage["volumeUuid"], "CapacityQuota": storage["quotaBytes"]}]}]}
        self.assertEqual(observer.parse_storage(plistlib.dumps(info), plistlib.dumps(volumes), self.selected)["quotaBytes"], storage["quotaBytes"])
        for quota in (0, True, storage["quotaBytes"] + 1):
            volumes["Containers"][0]["Volumes"][0]["CapacityQuota"] = quota
            with self.assertRaises(deployment.DeploymentError):
                observer.parse_storage(plistlib.dumps(info), plistlib.dumps(volumes), self.selected)

    def test_root_endpoint_probe_uses_real_supplementary_groups_and_rejects_connect_or_absence(self):
        endpoint = {"path": self.selected.account_home + "/daemon.sock"}
        account = SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="ordinary")
        identity = SimpleNamespace(geteuid=lambda: 0, getgrouplist=lambda _name, _gid: [20, 80])
        with mock.patch.object(observer, "os", identity), mock.patch.object(observer.pwd, "getpwall", return_value=[account]), \
                mock.patch.object(observer, "read_root_protected", return_value=(None, "4" * 64)), \
                mock.patch.object(observer, "_bounded", return_value=str(errno.EACCES).encode()) as query:
            observer.current_endpoint_denials(self.selected, [endpoint])
            self.assertEqual(query.call_args.args[2], {"user": 501, "group": 20, "extra_groups": [20, 80]})
            for response in (b"0", str(errno.ENOENT).encode(), b"-1"):
                query.return_value = response
                with self.assertRaises(deployment.DeploymentError):
                    observer.current_endpoint_denials(self.selected, [endpoint])

    def test_root_account_status_accepts_only_disabled_marker_without_other_providers(self):
        with mock.patch.object(observer, "read_root_protected"), mock.patch.object(observer, "_bounded", return_value=b"AuthenticationAuthority: ;DisabledUser;\n") as query:
            observer.current_account_status(self.selected)
            self.assertEqual(query.call_args.args[0][-1], "AuthenticationAuthority")
            for raw in (b"AuthenticationAuthority: ;ShadowHash;\n", b"AuthenticationAuthority: ;DisabledUser; ;ShadowHash;\n", b"Password: *\n"):
                query.return_value = raw
                with self.assertRaises(deployment.DeploymentError):
                    observer.current_account_status(self.selected)

    def test_existing_registry_lock_and_live_reservations_block_root_observation(self):
        root = Path(self.selected.registry_root); root.mkdir(parents=True, mode=0o700)
        root.parent.chmod(0o700); root.parent.parent.chmod(0o700)
        registry = SandboxRegistry(root, self.selected.namespace)
        self.addCleanup(registry.close)
        with registry.locked() as transaction:
            expected_id = transaction.registry_id
            with self.assertRaises(BlockingIOError):
                with evidence._quiescent_registry(self.selected):
                    self.fail("second observer obtained an already held lock")
        with evidence._quiescent_registry(self.selected) as binding:
            self.assertEqual(binding["registryId"], expected_id)
            self.assertEqual(binding["inode"], root.stat().st_ino)
        with registry.locked() as transaction:
            transaction.takeover()
            transaction.reserve({"projectId": DIGEST, "team": "fixture", "featureId": "feature", "role": "developer", "taskId": "task", "attempt": 1}, epoch=transaction.epoch)
        with self.assertRaises(evidence.QualificationEvidenceError):
            with evidence._quiescent_registry(self.selected):
                self.fail("allocated reservation was silently enrolled")


class IssuerOrderingTest(unittest.TestCase):
    """Mock only privileged installation/observer seams; no root file is issued."""
    setUp = LiveEvidenceTest.setUp
    def issuer(self, *, install, observer_error=False, write_error=None):
        raw_profile = deployment.canonical_bytes(self.profile.as_dict())
        settings = {key: False for key in observer.REQUIRED_DISABLED_SETTINGS}
        @contextmanager
        def quiescent(_deployment):
            yield self.binding
        def read(path, **_kwargs):
            if str(path) == self.selected.receipt_path:
                raise FileNotFoundError
            raw = raw_profile if str(path) == self.selected.profile_path else deployment.canonical_bytes({"gate": Path(path).stem})
            return raw, hashlib.sha256(raw).hexdigest()
        def reviewed(raw, gate, *_args, **_kwargs):
            return {"validUntil": NOW + 100, "observations": {
                "mountless-startup": {"settings": settings}, "version-platform": {"pythonVersion": "3.12.0"},
                "resource-limits": {"hostPhysicalMemoryMiB": 8192, "hostLogicalCpus": 8},
                "object-identity": {"endpoints": [{"path": "fixed-fixture"}]},
            }.get(gate, {})}
        with mock.patch.object(evidence, "os", SimpleNamespace(geteuid=lambda: 0)), \
                mock.patch.object(evidence, "verify_deployment"), mock.patch.object(evidence, "verify_quiescent_histories"), mock.patch.object(evidence, "_quiescent_registry", side_effect=quiescent), \
                mock.patch.object(evidence, "read_root_protected", side_effect=read), mock.patch.object(evidence, "verify_live_evidence", side_effect=reviewed), \
                mock.patch.object(observer, "current_account_status"), mock.patch.object(observer, "current_interpreter", return_value="3.12.0"), \
                mock.patch.object(observer, "current_settings_policy", side_effect=deployment.DeploymentError("live settings changed") if observer_error else None, return_value={"settings": settings}), \
                mock.patch.object(observer, "current_storage"), mock.patch.object(observer, "current_endpoint_denials"), \
                mock.patch.object(observer, "current_protected_denials"), mock.patch.object(observer, "current_host_resources", return_value={"physicalMemoryMiB": 8192, "logicalCpus": 8}), \
                mock.patch.object(evidence, "_root_write", side_effect=write_error) as writes:
            try:
                result = evidence.issue_enrollment(self.selected, now=NOW, install=install)
            except Exception:
                self.writes = writes.call_args_list
                raise
            self.writes = writes.call_args_list
            return result

    def test_root_verification_without_install_has_no_authority_writes(self):
        result = self.issuer(install=False)
        self.assertFalse(result["installed"])
        self.assertEqual(self.writes, [])

    def test_root_install_commits_all_proof_then_receipt_then_profile_pointer(self):
        result = self.issuer(install=True)
        self.assertTrue(result["installed"])
        self.assertEqual(len(self.writes), len(evidence.REQUIRED_CHECK_IDS) + 2)
        self.assertEqual(str(self.writes[-2].args[0]), self.selected.receipt_path)
        self.assertEqual(str(self.writes[-1].args[0]), self.selected.profile_path)
        profile = DockerProfile.from_dict(json.loads(self.writes[-1].args[1]))
        self.assertEqual(profile.qualification_digest, deployment.digest_bytes(self.writes[-2].args[1]))
        self.assertEqual(profile_basis_digest(profile), self.selected.profile_basis_digest)
        self.assertEqual(result["expiresAt"], NOW + 100)

    def test_changed_current_settings_or_failed_receipt_write_never_updates_profile(self):
        with self.assertRaises(deployment.DeploymentError):
            self.issuer(install=True, observer_error=True)
        self.assertEqual(self.writes, [])
        def crash(path, _raw, **_kwargs):
            if str(path) == self.selected.receipt_path:
                raise OSError("fixture interruption before profile authority pointer")
        with self.assertRaises(OSError):
            self.issuer(install=True, write_error=crash)
        self.assertFalse(any(str(call.args[0]) == self.selected.profile_path for call in self.writes))


if __name__ == "__main__":
    unittest.main()
