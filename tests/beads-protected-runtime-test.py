#!/usr/bin/env python3
"""Offline conformance tests for the task-#3 protected Beads protocol."""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

runtime = importlib.import_module("startup_factory_cli.beads_protected_runtime")
from support.beads_protected_runtime_harness import logic_harness


def digest(label: str) -> str:
    return runtime.sha256(label.encode("utf-8"))


class ProtectedRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "protected"
        self.root.mkdir(mode=0o700)
        self.key = self.root / "beads-runtime.hmac"
        self.key.write_bytes(b"offline-fixture-key-material-32b")
        self.key.chmod(0o600)
        self.repository = digest("repository")
        self.expires = int(time.time()) + 3600
        self.logic_harness = logic_harness(
            runtime, self.root, self.key, self.repository
        )
        self.logic_harness.__enter__()

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            self.logic_harness.__exit__(None, None, None)

    def request(self, name: str, **values):
        payload = {
            "protectedRoot": str(self.root),
            "hmacKeyPath": str(self.key),
            "repositoryLocatorSha256": self.repository,
            **values,
        }
        schema = runtime._TYPE_SCHEMAS[name]
        for field in schema["nullable"]:
            payload.setdefault(field, None)
        return getattr(runtime, name)(payload=payload)

    def sequence(self, mode: str = "create") -> dict:
        create = mode == "create"
        return {
            "bootstrapChangeKind": "create" if create else "reattest",
            "preparationMode": mode,
            "preparationSequenceKind": mode,
            "preparationSequenceSha256": digest(f"sequence:{mode}"),
            "remediationEvidenceSha256": None,
            "databasePathKind": "stage" if create else "installed-selector",
            "createStageDatabasePathLocatorSha256": digest("stage") if create else None,
            "installedDatabaseSelectorBindingSha256": None if create else digest("selector-binding"),
            "selectorObservationASha256": None if create else digest("selector-a"),
            "selectedStoreObservationASha256": None if create else digest("store-a"),
        }

    def closed_payload(self, name: str, **values):
        schema = runtime._TYPE_SCHEMAS[name]
        payload = {
            field: (None if field in schema["nullable"] else f"fixture:{field}")
            for field in schema["fields"]
        }
        payload.update(values)
        return payload

    def store(self):
        self.logic_harness.bind_repository(self.repository)
        return runtime._Store(
            {
                "protectedRoot": str(self.root),
                "hmacKeyPath": str(self.key),
                "repositoryLocatorSha256": self.repository,
            }
        )

    def authorize_transition(self, command: str, expected: str | None, candidate=None, mode="create"):
        return runtime.authorize_beads_authority_transition_v1(
            self.request(
                "AuthorizeBeadsAuthorityTransitionRequestV1",
                command=command,
                authorizationNonce=f"{command}-nonce",
                expiresAtUnix=self.expires,
                expectedCurrentFullBytesSha256=expected,
                candidate=candidate,
                **self.sequence(mode),
            )
        )

    def bootstrap_revoked(self):
        authorization = self.authorize_transition("revoke", None)
        return runtime.revoke_beads_authority_epoch_v1(
            self.request(
                "RevokeBeadsAuthorityEpochRequestV1",
                authorizationRecordSha256=authorization.record_sha256,
            )
        )

    def create_runtime_and_release_manifests(self):
        core_payload = {
            "bootstrapChangeKind": "create",
            "adapterChangeKind": "create",
            "remediationEvidenceSha256": None,
            "baselineCommit": runtime.BEADS_BASELINE_COMMIT,
        }
        bootstrap_core = runtime.build_beads_bootstrap_runtime_core_v1(
            runtime.BeadsBootstrapRuntimeCoreInputsV1(payload=core_payload)
        )
        adapter_core = runtime.build_beads_adapter_release_core_v1(
            runtime.BeadsAdapterReleaseCoreInputsV1(payload=core_payload)
        )
        core = runtime.record_beads_change_plan_core_v1(
            self.request(
                "RecordBeadsChangePlanCoreRequestV1",
                bootstrapRuntimeCoreCanonicalJson=bootstrap_core.decode(),
                adapterReleaseCoreCanonicalJson=adapter_core.decode(),
            )
        )
        runtime_capability = runtime.authorize_beads_runtime_api_manifest_record_v1(
            self.request(
                "AuthorizeBeadsRuntimeApiManifestRecordRequestV1",
                mode="revoked-bootstrap",
                capabilityNonce="runtime-manifest-capability",
                expiresAtUnix=self.expires,
                expectedCurrentFullBytesSha256=None,
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                runtimeTransactionAuthorityBinding={"kind": "task-3-attempt", "identitySha256": digest("task-3")},
            )
        )
        runtime_manifest = runtime.record_beads_protected_runtime_api_manifest_v1(
            self.request(
                "RecordBeadsProtectedRuntimeApiManifestRequestV1",
                moduleSha256=digest("module"),
                schemaFixtureSha256=runtime.sha256(runtime.beads_protected_runtime_schema_v1()),
                exports=sorted((*runtime._TYPE_NAMES, *runtime._FUNCTION_EXPORTS)),
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
            ),
            runtime_capability,
        )
        release_capability = runtime.authorize_beads_adapter_release_manifest_record_v1(
            self.request(
                "AuthorizeBeadsAdapterReleaseManifestRecordRequestV1",
                capabilityNonce="release-manifest-capability",
                expiresAtUnix=self.expires,
                expectedCurrentFullBytesSha256=None,
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                adapterReleaseCoreSha256=core.payload["adapterReleaseCoreSha256"],
                runtimeApiManifestRecordSha256=runtime_manifest.record_sha256,
            )
        )
        observation = {
            "bootstrapRuntimeCoreSha256": core.payload["bootstrapRuntimeCoreSha256"],
            "adapterReleaseCoreSha256": core.payload["adapterReleaseCoreSha256"],
            "runtimeApiManifestRecordSha256": runtime_manifest.record_sha256,
            "adapterPayloadSha256": digest("adapter-payload"),
            "remediationEvidenceSha256": None,
        }
        release_manifest = runtime.record_beads_adapter_release_manifest_v1(
            self.request(
                "RecordBeadsAdapterReleaseManifestRequestV1",
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                adapterReleaseCoreSha256=core.payload["adapterReleaseCoreSha256"],
                runtimeApiManifestRecordSha256=runtime_manifest.record_sha256,
                runtimeManifestObservations=[{**observation, "phase": phase} for phase in ("A", "B", "C")],
                adapterPayloadSha256=digest("adapter-payload"),
                releaseIdentitySha256=digest("release"),
                remediationEvidenceSha256=None,
            ),
            release_capability,
        )
        return core, runtime_manifest, release_manifest

    def test_schema_fixture_and_registered_surface_are_exact(self) -> None:
        fixture_path = ROOT / "tests" / "fixtures" / "beads-protected-runtime-v1.json"
        fixture_bytes = fixture_path.read_bytes()
        fixture = json.loads(fixture_bytes)
        self.assertEqual(runtime.canonical_bytes(fixture) + b"\n", fixture_bytes)
        self.assertEqual(fixture["baselineCommit"], runtime.BEADS_BASELINE_COMMIT)
        self.assertEqual(fixture["schemaFixtureSha256"], runtime.sha256(runtime.beads_protected_runtime_schema_v1()))
        for name in (*runtime._TYPE_NAMES, *runtime._FUNCTION_EXPORTS):
            self.assertTrue(hasattr(runtime, name), name)

    def test_mode_and_symlinked_protected_state_fail_closed(self) -> None:
        self.root.chmod(0o777)
        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "mode 0700"):
            runtime.prepare_atomic_claim_v1(
                self.request(
                    "PrepareAtomicClaimRequestV1",
                    taskId="task-1",
                    expectedRevision="1",
                    claimNonce="nonce-1",
                    expiresAtUnix=self.expires,
                )
            )
        self.root.chmod(0o700)
        self.key.unlink()
        outside = Path(self.temporary.name) / "outside-key"
        outside.write_bytes(b"x" * 32)
        outside.chmod(0o600)
        self.key.symlink_to(outside)
        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "non-symlink"):
            runtime.prepare_atomic_claim_v1(
                self.request(
                    "PrepareAtomicClaimRequestV1",
                    taskId="task-1",
                    expectedRevision="1",
                    claimNonce="nonce-1",
                    expiresAtUnix=self.expires,
                )
            )

    def test_capability_is_one_use_and_crash_resume_is_exact(self) -> None:
        self.bootstrap_revoked()
        core, _, _ = self.create_runtime_and_release_manifests()
        capability = runtime.authorize_beads_runtime_api_manifest_record_v1(
            self.request(
                "AuthorizeBeadsRuntimeApiManifestRecordRequestV1",
                mode="revoked-successor",
                capabilityNonce="runtime-successor",
                expiresAtUnix=self.expires,
                expectedCurrentFullBytesSha256=(
                    runtime._load_current(
                        self.store(),
                        "BeadsProtectedRuntimeApiManifestV1",
                        "beads-protected-runtime-api-manifest",
                        "runtime-api-manifests",
                    ).full_bytes_sha256
                ),
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                runtimeTransactionAuthorityBinding={"kind": "task-3-attempt", "identitySha256": digest("task-3-next")},
            )
        )
        request = self.request(
            "RecordBeadsProtectedRuntimeApiManifestRequestV1",
            moduleSha256=digest("module-next"),
            schemaFixtureSha256=runtime.sha256(runtime.beads_protected_runtime_schema_v1()),
            exports=sorted((*runtime._TYPE_NAMES, *runtime._FUNCTION_EXPORTS)),
            bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
        )
        with runtime._inject_fault("runtime-manifest-capability-consumed"), self.assertRaises(SystemExit):
            runtime.record_beads_protected_runtime_api_manifest_v1(request, capability)
        first = runtime.record_beads_protected_runtime_api_manifest_v1(request, capability)
        second = runtime.record_beads_protected_runtime_api_manifest_v1(request, capability)
        self.assertEqual(first.to_dict(), second.to_dict())
        altered = self.request(
            "RecordBeadsProtectedRuntimeApiManifestRequestV1",
            moduleSha256=digest("different"),
            schemaFixtureSha256=runtime.sha256(runtime.beads_protected_runtime_schema_v1()),
            exports=sorted((*runtime._TYPE_NAMES, *runtime._FUNCTION_EXPORTS)),
            bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
        )
        with self.assertRaises(runtime.BeadsCapabilityConsumedError):
            runtime.record_beads_protected_runtime_api_manifest_v1(altered, capability)

        successor_capability = runtime.authorize_beads_runtime_api_manifest_record_v1(
            self.request(
                "AuthorizeBeadsRuntimeApiManifestRecordRequestV1",
                mode="revoked-successor",
                capabilityNonce="runtime-current-crash",
                expiresAtUnix=self.expires,
                expectedCurrentFullBytesSha256=first.full_bytes_sha256,
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                runtimeTransactionAuthorityBinding={"kind": "task-3-attempt", "identitySha256": digest("task-3-final")},
            )
        )
        successor_request = self.request(
            "RecordBeadsProtectedRuntimeApiManifestRequestV1",
            moduleSha256=digest("module-final"),
            schemaFixtureSha256=runtime.sha256(runtime.beads_protected_runtime_schema_v1()),
            exports=sorted((*runtime._TYPE_NAMES, *runtime._FUNCTION_EXPORTS)),
            bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
        )
        with runtime._inject_fault("runtime-manifest-current-written"), self.assertRaises(SystemExit):
            runtime.record_beads_protected_runtime_api_manifest_v1(successor_request, successor_capability)
        recovered = runtime.record_beads_protected_runtime_api_manifest_v1(successor_request, successor_capability)
        self.assertEqual(digest("module-final"), recovered.payload["moduleSha256"])

    def test_hmac_tamper_is_never_repaired_or_accepted(self) -> None:
        self.bootstrap_revoked()
        store = self.store()
        current = store.directory("authority") / "current.json"
        envelope = json.loads(current.read_bytes())
        envelope["payload"]["authorityState"] = "active"
        current.write_bytes(runtime.canonical_bytes(envelope))
        current.chmod(0o600)
        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "authentication failed"):
            runtime._current_authority(store, require_active=True)
        self.assertEqual("active", json.loads(current.read_bytes())["payload"]["authorityState"])

    def test_full_preparation_authority_claim_and_mutation_chain(self) -> None:
        revoked = self.bootstrap_revoked()
        core, runtime_manifest, release_manifest = self.create_runtime_and_release_manifests()
        sequence = self.sequence("create")
        repository_path = Path(self.temporary.name).resolve() / "repository"
        repository_path.mkdir(mode=0o700)
        binary_directory = Path(self.temporary.name).resolve() / "bin"
        binary_directory.mkdir(mode=0o700)
        executable_path = binary_directory / "bd"
        executable_bytes = b"""#!/bin/sh
set -eu
if [ "${1-}" = version ]; then
    printf '{"commit":"20e493e569c922d1253bdeff068c5e56c94957fb","version":"1.1.2"}\\n'
    exit 0
fi
database=$2
if [ "${5-}" = init ]; then
    mkdir -p "$database/.dolt"
    chmod 700 "$database" "$database/.dolt"
    printf '{"initialized":true}\\n' >"$database/state.json"
    chmod 600 "$database/state.json"
    printf '{"initialized":true}\\n'
    exit 0
fi
if [ "${5-}:${6-}" = config:set ]; then
    printf '{"statuses":"%s"}\\n' "$8" >"$database/status.json"
    chmod 600 "$database/status.json"
    printf '{"updated":true}\\n'
    exit 0
fi
if [ "${5-}:${6-}" = config:list ]; then
    printf '{"statuses":["open","closed"]}\\n'
    exit 0
fi
exit 64
"""
        executable_path.write_bytes(executable_bytes)
        executable_path.chmod(0o700)
        install_path = repository_path / ".beads" / "embeddeddolt" / "sf"
        install_path.parent.mkdir(parents=True, mode=0o700)
        (repository_path / ".beads").chmod(0o700)
        install_path.parent.chmod(0o700)
        cleanup_parent = Path(self.temporary.name).resolve() / "cleanup-parent"
        cleanup_parent.mkdir(mode=0o700)
        cleanup_path = cleanup_parent / "stage-scaffold"
        cleanup_path.mkdir(mode=0o700)
        (cleanup_path / ".gitignore").write_bytes(b"*\n")
        (cleanup_path / ".gitignore").chmod(0o600)
        stage_path = cleanup_path / "sf"
        sequence["createStageDatabasePathLocatorSha256"] = runtime.sha256(
            runtime.canonical_bytes(runtime._observe_path_locator(stage_path, "test stage path"))
        )
        authorization = runtime.authorize_beads_preparation_v1(
            self.request(
                "AuthorizeBeadsPreparationRequestV1",
                planSha256=digest("plan"),
                executableSha256=runtime.sha256(executable_bytes),
                operatorIdentitySha256=digest("operator"),
                authorizationNonce="preparation-auth",
                expiresAtUnix=self.expires,
                runtimeApiManifestRecordSha256=runtime_manifest.record_sha256,
                adapterReleaseManifestRecordSha256=release_manifest.record_sha256,
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                adapterReleaseCoreSha256=core.payload["adapterReleaseCoreSha256"],
                createStageDatabasePath=str(stage_path),
                executablePath=str(executable_path),
                repositoryPath=str(repository_path),
                databaseName="sf",
                installPath=str(install_path),
                cleanupPath=str(cleanup_path),
                statusConfigValue="open,closed",
                **sequence,
            )
        )
        lease = runtime.begin_beads_preparation_v1(
            self.request(
                "BeginBeadsPreparationRequestV1",
                authorizationRecordSha256=authorization.record_sha256,
                leaseNonce="lease-1",
                expiresAtUnix=self.expires,
            )
        )
        commands = (
            ("binary-proof", [str(executable_path), "version", "--json"]),
            ("initialize", [str(executable_path), "--db", str(stage_path), "--json", "--sandbox", "init"]),
            (
                "status-config-write",
                [
                    str(executable_path), "--db", str(stage_path), "--json", "--sandbox",
                    "config", "set", "status.custom", "open,closed",
                ],
            ),
            (
                "status-config-readback",
                [str(executable_path), "--db", str(stage_path), "--json", "--sandbox", "config", "list"],
            ),
        )
        readback_step = None
        pre = None
        for ordinal, (command, argv) in enumerate(commands):
            if command == "status-config-readback":
                pre = runtime.observe_beads_store_v1(
                    self.request(
                        "ObserveBeadsStoreRequestV1",
                        leaseRecordSha256=lease.record_sha256,
                        observationPhase="pre",
                    )
                )
            step = runtime.advance_beads_preparation_v1(
                self.request(
                    "AdvanceBeadsPreparationRequestV1",
                    leaseRecordSha256=lease.record_sha256,
                    commandOrdinal=ordinal,
                    commandKind=command,
                    argv=argv,
                )
            )
            self.assertEqual("succeeded", step.payload["outcome"])
            if command == "status-config-readback":
                readback_step = step
            lease = runtime._load_record(
                self.store(),
                "BeadsPreparationLeaseV1",
                "beads-preparation-lease",
                "preparation-leases",
                step.payload["successorLeaseRecordSha256"],
            )
        assert pre is not None and readback_step is not None
        config_digest = readback_step.payload["stdoutSha256"]
        post = runtime.observe_beads_store_v1(
            self.request(
                "ObserveBeadsStoreRequestV1",
                leaseRecordSha256=lease.record_sha256,
                observationPhase="post",
                acceptedConfigEnvelopeSha256=config_digest,
                predecessorObservationRecordSha256=pre.record_sha256,
                configReadbackStepRecordSha256=readback_step.record_sha256,
            )
        )
        with runtime.use_beads_protected_runtime_v1(str(self.root), str(self.key)):
            dynamic = runtime.derive_beads_status_profile_dynamic_bindings_v1(lease, pre, post, config_digest)
        finish_request = self.request(
                "FinishBeadsPreparationRequestV1",
                leaseRecordSha256=lease.record_sha256,
                preObservationRecordSha256=pre.record_sha256,
                postObservationRecordSha256=post.record_sha256,
                dynamicBindingsCanonicalJson=runtime.canonical_bytes(dynamic.payload).decode(),
                statusProfilePayloadCanonicalJson='{"allowed":["open","closed"],"schemaVersion":1}',
                preparedStorePayloadCanonicalJson='{"database":"sf","schemaVersion":1}',
                expectedCurrentPointerFullBytesSha256=None,
        )
        with runtime._inject_fault("preparation-install-quarantined"), self.assertRaises(SystemExit):
            runtime.finish_beads_preparation_v1(finish_request)
        self.assertFalse(install_path.exists())
        with runtime._inject_fault("preparation-install-renamed"), self.assertRaises(SystemExit):
            runtime.finish_beads_preparation_v1(finish_request)
        with runtime._inject_fault("preparation-cleanup-retired"), self.assertRaises(SystemExit):
            runtime.finish_beads_preparation_v1(finish_request)
        self.assertFalse(cleanup_path.exists())
        retained = list(cleanup_path.parent.glob("startup-factory-retained-beads-*"))
        self.assertEqual(len(retained), 1)
        with runtime._inject_fault("preparation-cleanup-retirement-recorded"), self.assertRaises(SystemExit):
            runtime.finish_beads_preparation_v1(finish_request)
        finished = runtime.finish_beads_preparation_v1(finish_request)
        self.assertTrue((install_path / ".dolt").is_dir())
        self.assertFalse(stage_path.exists())
        self.assertFalse(cleanup_path.exists())
        self.assertTrue((retained[0] / ".gitignore").is_file())
        for field in (
            "installIntentRecordSha256", "installObservedRecordSha256",
            "cleanupIntentRecordSha256", "cleanupObservedRecordSha256",
        ):
            self.assertRegex(finished.payload[field], r"^sha256:[0-9a-f]{64}$")
        with runtime.use_beads_protected_runtime_v1(str(self.root), str(self.key)):
            finished_verification = runtime.verify_current_beads_preparation_v1(self.repository)
        candidate = {
            "preparationPointerRecordSha256": finished_verification.payload["pointerRecordSha256"],
            "preparationActivationReceiptRecordSha256": finished_verification.payload["activationReceiptRecordSha256"],
            "adapterReleaseManifestRecordSha256": release_manifest.record_sha256,
            "runtimeApiManifestRecordSha256": runtime_manifest.record_sha256,
            "repositoryPath": str(repository_path),
            "databaseName": "sf",
        }
        stage_auth = self.authorize_transition("stage", revoked.full_bytes_sha256, candidate)
        with runtime._inject_fault("stage-authority-current-written"), self.assertRaises(SystemExit):
            runtime.stage_beads_authority_epoch_v1(
                self.request("StageBeadsAuthorityEpochRequestV1", authorizationRecordSha256=stage_auth.record_sha256)
            )
        pending = runtime.stage_beads_authority_epoch_v1(
            self.request("StageBeadsAuthorityEpochRequestV1", authorizationRecordSha256=stage_auth.record_sha256)
        )
        activate_auth = self.authorize_transition("activate", pending.full_bytes_sha256, candidate)
        active = runtime.activate_beads_authority_epoch_v1(
            self.request("ActivateBeadsAuthorityEpochRequestV1", authorizationRecordSha256=activate_auth.record_sha256)
        )
        with runtime.use_beads_protected_runtime_v1(str(self.root), str(self.key)):
            verified = runtime.verify_active_beads_authority_v1(self.repository)
            self.assertEqual(active.record_sha256, verified.record_sha256)
            current_preparation = runtime.verify_current_beads_preparation_v1(self.repository)
            self.assertEqual(
                finished_verification.payload["pointerRecordSha256"],
                current_preparation.payload["pointerRecordSha256"],
            )
        claim = runtime.prepare_atomic_claim_v1(
            self.request(
                "PrepareAtomicClaimRequestV1",
                taskId="task-42",
                expectedRevision="r1",
                claimNonce="claim-42",
                expiresAtUnix=self.expires,
            )
        )
        claimed = runtime.advance_atomic_claim_v1(
            self.request(
                "AdvanceAtomicClaimRequestV1",
                leaseRecordSha256=claim.record_sha256,
                observedRevision="r2",
                observedStatus="active",
                claimSucceeded=True,
            )
        )
        receipt = runtime.record_atomic_claim_receipt_v1(
            self.request(
                "RecordAtomicClaimReceiptRequestV1",
                leaseRecordSha256=claimed.record_sha256,
                readBackRevision="r2",
                readBackStatus="active",
                claimIdentitySha256=digest("claim-identity"),
            )
        )
        launch = runtime.authorize_claim_launch_v1(
            self.request(
                "AuthorizeClaimLaunchRequestV1",
                claimReceiptRecordSha256=receipt.record_sha256,
                launchNonce="launch-42",
                expiresAtUnix=self.expires,
            )
        )
        self.assertEqual(receipt.record_sha256, launch.payload["claimReceiptRecordSha256"])
        mutation = runtime.begin_beads_mutation_v1(
            self.request(
                "BeginBeadsMutationRequestV1",
                mutationClass="ordinary",
                mutationNonce="mutation-1",
                commandArgv=["bd", "update", "task-42", "--json"],
                expiresAtUnix=self.expires,
                launchAuthorizationRecordSha256=launch.record_sha256,
            )
        )
        result = runtime.finish_beads_mutation_v1(
            self.request(
                "FinishBeadsMutationRequestV1",
                mutationClass="ordinary",
                mutationIntentRecordSha256=mutation.record_sha256,
                exitCode=0,
                stdoutSha256=digest("stdout"),
                stderrSha256=digest("empty"),
                readBackSha256=digest("read-back"),
            )
        )
        self.assertEqual("ordinary", result.payload["mutationClass"])
        self.assertNotEqual(digest("stdout"), result.payload["stdoutSha256"])
        self.assertNotEqual(digest("empty"), result.payload["stderrSha256"])
        self.assertNotEqual(digest("read-back"), result.payload["readBackSha256"])
        self.assertTrue(result.payload["observedByBroker"])
        executable_path.write_bytes(executable_bytes + b"# changed after activation\n")
        executable_path.chmod(0o700)
        with runtime.use_beads_protected_runtime_v1(str(self.root), str(self.key)):
            with self.assertRaises(runtime.BeadsProtectedRuntimeError):
                runtime.verify_active_beads_authority_v1(self.repository)

    def test_reattest_argv_gate_rejects_every_variant_before_recording(self) -> None:
        lease = runtime.BeadsPreparationLeaseV1(
            payload=self.closed_payload(
                "BeadsPreparationLeaseV1",
                preparationMode="reattest",
                installedSelectorPath="/repo/.beads/embeddeddolt",
                executablePath="/protected/bd",
                nextCommandOrdinal=0,
            ),
        )
        exact = ["/protected/bd", "--db", "/repo/.beads/embeddeddolt", "--json", "--sandbox", "config", "list"]
        runtime._expected_preparation_command(lease, "status-config-readback", exact)
        variants = (
            ["/protected/bd", "--db", "/repo/.beads/embeddeddolt/db", "--json", "--sandbox", "config", "list"],
            ["/protected/bd", "--json", "--db", "/repo/.beads/embeddeddolt", "--sandbox", "config", "list"],
            ["/protected/bd", "--db", "/repo/.beads/embeddeddolt", "--json", "config", "list"],
            exact + ["--readonly"],
            exact + ["--no-daemon"],
        )
        for argv in variants:
            with self.subTest(argv=argv), self.assertRaises(runtime.BeadsProtectedRuntimeError):
                runtime._expected_preparation_command(lease, "status-config-readback", argv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
