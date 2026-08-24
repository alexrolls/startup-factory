#!/usr/bin/env python3
"""Hostile regression controls for the protected Beads authority boundary."""

from __future__ import annotations

import importlib
import inspect
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

runtime = importlib.import_module("startup_factory_cli.beads_protected_runtime")
from support.beads_protected_runtime_harness import TEST_PROVENANCE, logic_harness


def digest(label: str) -> str:
    return runtime.sha256(label.encode("utf-8"))


class ProtectedRuntimeHostileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "protected"
        self.root.mkdir(mode=0o700)
        self.key = self.root / "beads-runtime.hmac"
        self.key.write_bytes(b"hostile-fixture-key-material-32bytes")
        self.key.chmod(0o600)
        self.repository = digest("hostile-repository")
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

    def sequence(self) -> dict[str, object]:
        return {
            "bootstrapChangeKind": "create",
            "preparationMode": "create",
            "preparationSequenceKind": "create",
            "preparationSequenceSha256": digest("hostile-sequence"),
            "remediationEvidenceSha256": None,
            "databasePathKind": "stage",
            "createStageDatabasePathLocatorSha256": digest("hostile-stage"),
            "installedDatabaseSelectorBindingSha256": None,
            "selectorObservationASha256": None,
            "selectedStoreObservationASha256": None,
        }

    def store(self) -> runtime._Store:
        self.logic_harness.bind_repository(self.repository)
        return runtime._Store(
            {
                "protectedRoot": str(self.root),
                "hmacKeyPath": str(self.key),
                "repositoryLocatorSha256": self.repository,
            }
        )

    def closed_payload(self, name: str, **values):
        schema = runtime._TYPE_SCHEMAS[name]
        payload = {
            field: (None if field in schema["nullable"] else f"fixture:{field}")
            for field in schema["fields"]
        }
        payload.update(values)
        return payload

    def test_all_protected_public_entries_refuse_without_live_external_session_before_effects(self) -> None:
        before_names = sorted(path.name for path in self.root.iterdir())
        before_key = self.key.read_bytes()
        before_mode = self.root.stat().st_mode
        self.logic_harness.__exit__(None, None, None)
        try:
            for name in runtime._FUNCTION_EXPORTS:
                if name in runtime._PURE_OFFLINE_FUNCTIONS:
                    continue
                function = getattr(runtime, name)
                signature = inspect.signature(function)
                arguments = [
                    None
                    for parameter in signature.parameters.values()
                    if parameter.default is inspect.Parameter.empty
                    and parameter.kind
                    in (
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                ]
                with self.subTest(function=name), self.assertRaisesRegex(
                    runtime.BeadsProtectedRuntimeError,
                    "fixed root-managed Linux Beads boundary controller required",
                ):
                    function(*arguments)
        finally:
            self.logic_harness = logic_harness(
                runtime, self.root, self.key, self.repository
            )
            self.logic_harness.__enter__()
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), before_names)
        self.assertEqual(self.key.read_bytes(), before_key)
        self.assertEqual(self.root.stat().st_mode, before_mode)
        self.assertFalse((self.root / runtime.REPOSITORY_NAMESPACE).exists())

    def test_darwin_missing_service_and_callback_bypass_are_deterministically_ineligible(self) -> None:
        self.assertFalse(hasattr(runtime, "_accept_verified_external_boundary_session_v1"))
        self.assertFalse(hasattr(runtime, "_offline_logic_only_v1"))
        self.logic_harness.__exit__(None, None, None)
        try:
            with mock.patch.object(runtime.sys, "platform", "darwin"):
                with self.assertRaisesRegex(
                    runtime.BeadsProtectedRuntimeError,
                    "host platform 'darwin' is not Linux",
                ):
                    runtime.prepare_atomic_claim_v1(
                        self.request(
                            "PrepareAtomicClaimRequestV1",
                            taskId="task-refused",
                            expectedRevision="1",
                            claimNonce="darwin-refusal",
                            expiresAtUnix=self.expires,
                        )
                    )
            with mock.patch.object(runtime.sys, "platform", "linux"), mock.patch.object(
                runtime._boundary_controller,
                "load_controller_config",
                side_effect=runtime._boundary_controller.ControllerProtocolError(
                    "fixed controller service is unavailable"
                ),
            ):
                with self.assertRaisesRegex(
                    runtime.BeadsProtectedRuntimeError,
                    "fixed controller service is unavailable",
                ):
                    runtime.prepare_atomic_claim_v1(
                        self.request(
                            "PrepareAtomicClaimRequestV1",
                            taskId="task-refused",
                            expectedRevision="1",
                            claimNonce="missing-service-refusal",
                            expiresAtUnix=self.expires,
                        )
                    )
        finally:
            self.logic_harness = logic_harness(
                runtime, self.root, self.key, self.repository
            )
            self.logic_harness.__enter__()
        self.assertFalse((self.root / runtime.REPOSITORY_NAMESPACE).exists())

    def test_native_mutation_refuses_without_session_before_hook_or_syscall(self) -> None:
        parent_path = self.base / "native-refusal"
        parent_path.mkdir(mode=0o700)
        source = parent_path / "source"
        target = parent_path / "target"
        source.mkdir(mode=0o700)
        parent, source_leaf = runtime._open_absolute_parent(
            source, "native refusal source"
        )
        hook_called = False

        def hook(*_args):
            nonlocal hook_called
            hook_called = True

        self.logic_harness.__exit__(None, None, None)
        try:
            with mock.patch.object(runtime, "_NATIVE_MUTATION_HOOK", hook):
                with self.assertRaisesRegex(
                    runtime.BeadsProtectedRuntimeError,
                    "fixed root-managed Linux Beads boundary controller required",
                ):
                    runtime._native_rename_noreplace(
                        parent,
                        source_leaf,
                        parent,
                        target.name,
                        phase="native-refusal-fixture",
                    )
        finally:
            os.close(parent)
            self.logic_harness = logic_harness(
                runtime, self.root, self.key, self.repository
            )
            self.logic_harness.__enter__()
        self.assertFalse(hook_called)
        self.assertTrue(source.is_dir())
        self.assertFalse(target.exists())

    def seed_current_manifests(self):
        core_payload = {
            "bootstrapChangeKind": "create",
            "adapterChangeKind": "create",
            "remediationEvidenceSha256": None,
            "baselineCommit": runtime.BEADS_BASELINE_COMMIT,
        }
        bootstrap = runtime.build_beads_bootstrap_runtime_core_v1(
            runtime.BeadsBootstrapRuntimeCoreInputsV1(payload=core_payload)
        )
        adapter = runtime.build_beads_adapter_release_core_v1(
            runtime.BeadsAdapterReleaseCoreInputsV1(payload=core_payload)
        )
        core = runtime.record_beads_change_plan_core_v1(
            self.request(
                "RecordBeadsChangePlanCoreRequestV1",
                bootstrapRuntimeCoreCanonicalJson=bootstrap.decode(),
                adapterReleaseCoreCanonicalJson=adapter.decode(),
            )
        )
        runtime_capability = runtime.authorize_beads_runtime_api_manifest_record_v1(
            self.request(
                "AuthorizeBeadsRuntimeApiManifestRecordRequestV1",
                mode="revoked-bootstrap",
                capabilityNonce="hostile-runtime-capability",
                expiresAtUnix=self.expires,
                expectedCurrentFullBytesSha256=None,
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                runtimeTransactionAuthorityBinding={
                    "kind": "task-3-attempt",
                    "identitySha256": digest("hostile-task-3"),
                },
            )
        )
        runtime_manifest = runtime.record_beads_protected_runtime_api_manifest_v1(
            self.request(
                "RecordBeadsProtectedRuntimeApiManifestRequestV1",
                moduleSha256=digest("hostile-module"),
                schemaFixtureSha256=runtime.sha256(runtime.beads_protected_runtime_schema_v1()),
                exports=sorted((*runtime._TYPE_NAMES, *runtime._FUNCTION_EXPORTS)),
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
            ),
            runtime_capability,
        )
        release_capability = runtime.authorize_beads_adapter_release_manifest_record_v1(
            self.request(
                "AuthorizeBeadsAdapterReleaseManifestRecordRequestV1",
                capabilityNonce="hostile-release-capability",
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
            "adapterPayloadSha256": digest("hostile-adapter-payload"),
            "remediationEvidenceSha256": None,
        }
        release_manifest = runtime.record_beads_adapter_release_manifest_v1(
            self.request(
                "RecordBeadsAdapterReleaseManifestRequestV1",
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                adapterReleaseCoreSha256=core.payload["adapterReleaseCoreSha256"],
                runtimeApiManifestRecordSha256=runtime_manifest.record_sha256,
                runtimeManifestObservations=[
                    {**observation, "phase": phase} for phase in ("A", "B", "C")
                ],
                adapterPayloadSha256=observation["adapterPayloadSha256"],
                releaseIdentitySha256=digest("hostile-release"),
                remediationEvidenceSha256=None,
            ),
            release_capability,
        )
        return core, runtime_manifest, release_manifest

    def seed_authority(self, state: str, generation: int = 1, predecessor: str | None = None):
        store = self.store()
        repository_path = self.base / f"authority-repository-{generation}"
        repository_path.mkdir(mode=0o700, exist_ok=True)
        return runtime._write_current(
            store,
            "BeadsAuthorityEpochStateV1",
            "beads-authority-epoch-state",
            "authority",
            {
                "repositoryLocatorSha256": self.repository,
                "generation": generation,
                "authorityState": state,
                "candidate": {
                    "preparationPointerRecordSha256": digest(f"pointer:{generation}"),
                    "preparationActivationReceiptRecordSha256": digest(
                        f"activation:{generation}"
                    ),
                    "adapterReleaseManifestRecordSha256": digest(
                        f"release:{generation}"
                    ),
                    "runtimeApiManifestRecordSha256": digest(
                        f"runtime:{generation}"
                    ),
                    "repositoryPath": str(repository_path),
                    "databaseName": "db",
                },
                "predecessorCurrentFullBytesSha256": predecessor,
                "preparationPointerRecordSha256": digest(f"pointer:{generation}"),
                "adapterReleaseManifestRecordSha256": digest(f"release:{generation}"),
                "runtimeApiManifestRecordSha256": digest(f"runtime:{generation}"),
                "transitionAuthorizationRecordSha256": digest(f"transition-auth:{generation}"),
                "transitionIntentSha256": digest(f"transition-intent:{generation}"),
                **self.sequence(),
            },
            predecessor,
        )

    def seed_preparation_pointer(self, suffix: str):
        store = self.store()
        sequence = self.sequence()
        result = runtime._signed_record(
            store,
            "FinishBeadsPreparationResultV1",
            "beads-preparation-result",
            {
                "repositoryLocatorSha256": self.repository,
                "leaseRecordSha256": digest(f"lease:{suffix}"),
                "preObservationRecordSha256": digest(f"pre:{suffix}"),
                "postObservationRecordSha256": digest(f"post:{suffix}"),
                "statusProfileRecordSha256": digest(f"status:{suffix}"),
                "preparedPayloadCanonicalSha256": digest(f"payload:{suffix}"),
                "preparedPayloadCanonicalJson": '{"schemaVersion":1}',
                "installIntentRecordSha256": None,
                "installObservedRecordSha256": None,
                "cleanupIntentRecordSha256": None,
                "cleanupObservedRecordSha256": None,
                "transactionIntentSha256": digest(f"finish-intent:{suffix}"),
                **sequence,
            },
            "preparation-results",
        )
        _, result_stored_head = runtime._journal_binding_for_record(
            store, result.record_sha256, result.full_bytes_sha256, require_current=True
        )
        pointer = runtime._write_current(
            store,
            "BeadsPreparationCurrentV1",
            "beads-preparation-current",
            "preparation-current",
            {
                "repositoryLocatorSha256": self.repository,
                "generation": 1,
                "predecessorCurrentFullBytesSha256": None,
                "resultRecordSha256": result.record_sha256,
                "resultStoredJournalHeadSha256": result_stored_head,
                "statusProfileRecordSha256": result.payload["statusProfileRecordSha256"],
                "leaseRecordSha256": result.payload["leaseRecordSha256"],
                "installIntentRecordSha256": None,
                "installObservedRecordSha256": None,
                "cleanupIntentRecordSha256": None,
                "cleanupObservedRecordSha256": None,
                "transactionIntentSha256": digest(f"pointer-intent:{suffix}"),
                **sequence,
            },
            None,
        )
        activation = runtime._signed_record(
            store,
            "BeadsPreparationActivationReceiptV1",
            "beads-preparation-activation-receipt",
            {
                "repositoryLocatorSha256": self.repository,
                "pointerRecordSha256": pointer.record_sha256,
                "pointerFullBytesSha256": pointer.full_bytes_sha256,
                "resultRecordSha256": result.record_sha256,
                "resultStoredJournalHeadSha256": result_stored_head,
                "statusProfileRecordSha256": result.payload["statusProfileRecordSha256"],
                "installIntentRecordSha256": None,
                "installObservedRecordSha256": None,
                "cleanupIntentRecordSha256": None,
                "cleanupObservedRecordSha256": None,
                **sequence,
            },
            "preparation-activation-receipts",
        )
        return store, pointer, activation

    def create_authorized_create_lease(self, suffix: str):
        revoked = self.seed_authority("revoked")
        core, runtime_manifest, release_manifest = self.seed_current_manifests()
        repository = self.base / f"repository-{suffix}"
        repository.mkdir(mode=0o700)
        install = repository / ".beads" / "embeddeddolt" / "db"
        install.parent.mkdir(parents=True, mode=0o700)
        (repository / ".beads").chmod(0o700)
        install.parent.chmod(0o700)
        cleanup = self.base / f"cleanup-{suffix}"
        cleanup.mkdir(mode=0o700)
        (cleanup / ".gitignore").write_bytes(b"*\n")
        (cleanup / ".gitignore").chmod(0o600)
        stage = cleanup / "db"
        executable = self.base / f"bd-{suffix}"
        executable_bytes = b"#!/bin/sh\nexit 0\n"
        executable.write_bytes(executable_bytes)
        executable.chmod(0o700)
        sequence = self.sequence()
        sequence["createStageDatabasePathLocatorSha256"] = runtime.sha256(
            runtime.canonical_bytes(
                runtime._observe_path_locator(stage, f"{suffix} stage")
            )
        )
        authorization = runtime.authorize_beads_preparation_v1(
            self.request(
                "AuthorizeBeadsPreparationRequestV1",
                planSha256=digest(f"plan:{suffix}"),
                executableSha256=runtime.sha256(executable_bytes),
                operatorIdentitySha256=digest(f"operator:{suffix}"),
                authorizationNonce=f"authorization-{suffix}",
                expiresAtUnix=self.expires,
                runtimeApiManifestRecordSha256=runtime_manifest.record_sha256,
                adapterReleaseManifestRecordSha256=release_manifest.record_sha256,
                bootstrapRuntimeCoreSha256=core.payload["bootstrapRuntimeCoreSha256"],
                adapterReleaseCoreSha256=core.payload["adapterReleaseCoreSha256"],
                createStageDatabasePath=str(stage),
                executablePath=str(executable),
                repositoryPath=str(repository),
                databaseName="db",
                installPath=str(install),
                cleanupPath=str(cleanup),
                statusConfigValue="open,closed",
                **sequence,
            )
        )
        lease = runtime.begin_beads_preparation_v1(
            self.request(
                "BeginBeadsPreparationRequestV1",
                authorizationRecordSha256=authorization.record_sha256,
                leaseNonce=f"lease-{suffix}",
                expiresAtUnix=self.expires,
            )
        )
        argv = [str(executable), "version", "--json"]
        self.assertEqual(revoked.record_sha256, lease.payload["revokedAuthorityRecordSha256"])
        return lease, argv

    def sign_preparation_command(self, lease, argv, suffix: str):
        transaction = digest(f"command-transaction:{suffix}")
        command = runtime._signed_record(
            self.store(),
            "BeadsPreparationCommandIntentV1",
            "beads-preparation-command-intent",
            {
                "repositoryLocatorSha256": self.repository,
                "leaseRecordSha256": lease.record_sha256,
                "commandOrdinal": lease.payload["nextCommandOrdinal"],
                "commandKind": "binary-proof",
                "argv": argv,
                "argvSha256": runtime.sha256(runtime.canonical_bytes(argv)),
                "transactionIntentSha256": transaction,
                **runtime._preparation_sequence_fields(lease.payload),
            },
            "preparation-commands",
        )
        return command, transaction

    def test_activation_receipt_requires_deterministic_filename_and_journal(self) -> None:
        store, pointer, activation = self.seed_preparation_pointer("rename")
        history = store.directory("preparation-activation-receipts", "history")
        source = history / f"{activation.record_sha256.removeprefix('sha256:')}.json"
        source.rename(history / f"{digest('renamed').removeprefix('sha256:')}.json")
        with self.assertRaises(runtime.BeadsProtectedRuntimeError):
            runtime._verify_preparation_pointer(store, pointer, historical=True)

        self.repository = digest("hostile-repository-journal")
        store, pointer, activation = self.seed_preparation_pointer("journal")
        journal_index = store.read_json(
            store.directory("journals", "by-record")
            / f"{activation.record_sha256.removeprefix('sha256:')}.json",
            "activation journal index",
        )
        _, _, journal_digest, _ = store.verify(journal_index, "beads-protected-journal-entry")
        (store.directory("journals", "history") / f"{journal_digest.removeprefix('sha256:')}.json").unlink()
        with self.assertRaises(runtime.BeadsProtectedRuntimeError):
            runtime._verify_preparation_pointer(store, pointer, historical=True)

    def test_unsigned_locator_and_symlinked_protected_ancestry_fail_closed(self) -> None:
        repository_path = self.base / "repository"
        selector = repository_path / ".beads" / "embeddeddolt"
        (selector / "db" / ".dolt").mkdir(parents=True, mode=0o700)
        unsigned = runtime.BeadsAuthorityLocatorV1(
            payload=self.closed_payload(
                "BeadsAuthorityLocatorV1",
                repositoryLocatorSha256=self.repository,
                repositoryPath=str(repository_path),
                databaseName="db",
                verifiedReceiptRecordSha256=digest("absent-receipt"),
                authorityStateRecordSha256=digest("absent-authority"),
                authorityStateFullBytesSha256=digest("absent-authority-full"),
                predecessorCurrentFullBytesSha256=None,
            )
        )
        with runtime.use_beads_protected_runtime_v1(str(self.root), str(self.key)):
            with self.assertRaises(runtime.BeadsProtectedRuntimeError):
                runtime.verify_beads_installed_database_selector_v1(
                    self.repository, unsigned, digest("pointer")
                )

        real_parent = self.base / "real-parent"
        real_parent.mkdir(mode=0o700)
        alias_parent = self.base / "alias-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        alias_root = alias_parent / "protected"
        alias_root.mkdir(mode=0o700)
        alias_key = alias_root / "beads-runtime.hmac"
        alias_key.write_bytes(b"hostile-fixture-key-material-32bytes")
        alias_key.chmod(0o600)
        with self.assertRaises(runtime.BeadsProtectedRuntimeError):
            runtime._Store(
                {
                    "protectedRoot": str(alias_root),
                    "hmacKeyPath": str(alias_key),
                    "repositoryLocatorSha256": digest("alias-repository"),
                }
            )

    def test_claim_launch_mutation_and_preparation_successors_are_one_use(self) -> None:
        store = self.store()
        active = runtime._write_current(
            store,
            "BeadsAuthorityEpochStateV1",
            "beads-authority-epoch-state",
            "authority",
            {
                "repositoryLocatorSha256": self.repository,
                "generation": 1,
                "authorityState": "active",
                "candidate": {
                    "preparationPointerRecordSha256": digest("pointer"),
                    "preparationActivationReceiptRecordSha256": digest(
                        "activation"
                    ),
                    "adapterReleaseManifestRecordSha256": digest("release"),
                    "runtimeApiManifestRecordSha256": digest("runtime"),
                    "repositoryPath": str(self.base),
                    "databaseName": "db",
                },
                "predecessorCurrentFullBytesSha256": None,
                "preparationPointerRecordSha256": digest("pointer"),
                "adapterReleaseManifestRecordSha256": digest("release"),
                "runtimeApiManifestRecordSha256": digest("runtime"),
                "transitionAuthorizationRecordSha256": digest("transition-auth"),
                "transitionIntentSha256": digest("transition-intent"),
                **self.sequence(),
            },
            None,
        )
        claim = runtime.prepare_atomic_claim_v1(
            self.request(
                "PrepareAtomicClaimRequestV1",
                taskId="task-hostile",
                expectedRevision="r1",
                claimNonce="claim-hostile",
                expiresAtUnix=self.expires,
            )
        )
        first = runtime.advance_atomic_claim_v1(
            self.request(
                "AdvanceAtomicClaimRequestV1",
                leaseRecordSha256=claim.record_sha256,
                observedRevision="r2",
                observedStatus="active",
                claimSucceeded=True,
            )
        )
        with self.assertRaises((runtime.BeadsCapabilityConsumedError, runtime.BeadsStaleAuthorityError)):
            runtime.advance_atomic_claim_v1(
                self.request(
                    "AdvanceAtomicClaimRequestV1",
                    leaseRecordSha256=claim.record_sha256,
                    observedRevision="r3",
                    observedStatus="active",
                    claimSucceeded=True,
                )
            )
        receipt = runtime.record_atomic_claim_receipt_v1(
            self.request(
                "RecordAtomicClaimReceiptRequestV1",
                leaseRecordSha256=first.record_sha256,
                readBackRevision="r2",
                readBackStatus="active",
                claimIdentitySha256=digest("claim-identity"),
            )
        )
        launch = runtime.authorize_claim_launch_v1(
            self.request(
                "AuthorizeClaimLaunchRequestV1",
                claimReceiptRecordSha256=receipt.record_sha256,
                launchNonce="launch-hostile",
                expiresAtUnix=self.expires,
            )
        )
        with self.assertRaises((runtime.BeadsCapabilityConsumedError, runtime.BeadsStaleAuthorityError)):
            runtime.authorize_claim_launch_v1(
                self.request(
                    "AuthorizeClaimLaunchRequestV1",
                    claimReceiptRecordSha256=receipt.record_sha256,
                    launchNonce="launch-fork",
                    expiresAtUnix=self.expires,
                )
            )
        mutation = runtime.begin_beads_mutation_v1(
            self.request(
                "BeginBeadsMutationRequestV1",
                mutationClass="ordinary",
                mutationNonce="mutation-hostile",
                commandArgv=["bd", "update", "task-hostile", "--json"],
                launchAuthorizationRecordSha256=launch.record_sha256,
                expiresAtUnix=self.expires,
            )
        )
        finish = dict(
            mutationClass="ordinary",
            mutationIntentRecordSha256=mutation.record_sha256,
            exitCode=0,
            stdoutSha256=digest("stdout"),
            stderrSha256=digest("stderr"),
            readBackSha256=digest("read-back"),
        )
        runtime.finish_beads_mutation_v1(self.request("FinishBeadsMutationRequestV1", **finish))
        finish["stdoutSha256"] = digest("forked-stdout")
        with self.assertRaises((runtime.BeadsCapabilityConsumedError, runtime.BeadsStaleAuthorityError)):
            runtime.finish_beads_mutation_v1(self.request("FinishBeadsMutationRequestV1", **finish))
        self.assertEqual("active", active.payload["authorityState"])

    def test_preparation_execution_and_public_mutation_share_one_consumption_path(self) -> None:
        lease, argv = self.create_authorized_create_lease("canonical-consumption")
        step = runtime.advance_beads_preparation_v1(
            self.request(
                "AdvanceBeadsPreparationRequestV1",
                leaseRecordSha256=lease.record_sha256,
                commandOrdinal=0,
                commandKind="binary-proof",
                argv=argv,
            )
        )
        command = runtime._load_record(
            self.store(),
            "BeadsPreparationCommandIntentV1",
            "beads-preparation-command-intent",
            "preparation-commands",
            step.payload["commandIntentRecordSha256"],
        )
        transaction = command.payload["transactionIntentSha256"]
        store = self.store()
        self.assertTrue(
            runtime._capability_consumed_by(
                store, "preparation-lease-successors", lease, transaction
            )
        )
        self.assertTrue(
            runtime._capability_consumed_by(
                store, "preparation-command-intents", command, transaction
            )
        )
        before = sorted(
            path.name for path in store.directory("mutation-intents", "history").iterdir()
        )
        replay = runtime.begin_beads_mutation_v1(
            self.request(
                "BeginBeadsMutationRequestV1",
                mutationClass="preparation",
                mutationNonce=transaction.removeprefix("sha256:"),
                commandArgv=argv,
                expiresAtUnix=lease.payload["expiresAtUnix"],
                preparationLeaseRecordSha256=lease.record_sha256,
                preparationCommandIntentRecordSha256=command.record_sha256,
            )
        )
        self.assertEqual(step.payload["mutationIntentRecordSha256"], replay.record_sha256)
        self.assertEqual(
            before,
            sorted(path.name for path in store.directory("mutation-intents", "history").iterdir()),
        )

        self.repository = digest("expired-preparation-command")
        expired_lease, expired_argv = self.create_authorized_create_lease("expired-command")
        expired_store = self.store()
        expired_payload = {
            key: value
            for key, value in expired_lease.payload.items()
            if key not in {"kind", "schemaVersion"}
        }
        expired_payload["expiresAtUnix"] = int(time.time()) - 1
        expired = runtime._signed_record(
            expired_store,
            "BeadsPreparationLeaseV1",
            "beads-preparation-lease",
            expired_payload,
            "preparation-leases",
        )
        expired_command, expired_transaction = self.sign_preparation_command(
            expired, expired_argv, "expired"
        )
        expired_transactions = expired_store.repository / "transactions"
        expired_before = sorted(
            str(path.relative_to(expired_transactions))
            for path in expired_transactions.rglob("intent.json")
        ) if expired_transactions.exists() else []
        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "expired|expiry"):
            runtime.begin_beads_mutation_v1(
                self.request(
                    "BeginBeadsMutationRequestV1",
                    mutationClass="preparation",
                    mutationNonce=expired_transaction.removeprefix("sha256:"),
                    commandArgv=expired_argv,
                    expiresAtUnix=expired.payload["expiresAtUnix"],
                    preparationLeaseRecordSha256=expired.record_sha256,
                    preparationCommandIntentRecordSha256=expired_command.record_sha256,
                )
            )
        expired_after = sorted(
            str(path.relative_to(expired_transactions))
            for path in expired_transactions.rglob("intent.json")
        ) if expired_transactions.exists() else []
        self.assertEqual(expired_before, expired_after)
        self.assertFalse(
            runtime._capability_consumed_by(
                expired_store,
                "preparation-command-intents",
                expired_command,
                expired_transaction,
            )
        )

    def test_joint_preparation_consumption_recovers_after_first_successor(self) -> None:
        lease, argv = self.create_authorized_create_lease("joint-consumption-crash")
        command, transaction = self.sign_preparation_command(
            lease, argv, "joint-consumption-crash"
        )
        store = self.store()
        with runtime._inject_fault("preparation-joint-lease-consumed"), self.assertRaises(
            SystemExit
        ):
            runtime._consume_preparation_command_v1(store, lease, command, argv)
        self.assertTrue(
            runtime._capability_consumed_by(
                store, "preparation-lease-successors", lease, transaction
            )
        )
        self.assertFalse(
            runtime._capability_consumed_by(
                store, "preparation-command-intents", command, transaction
            )
        )
        mutation = runtime._consume_preparation_command_v1(
            store, lease, command, argv
        )
        self.assertTrue(
            runtime._capability_consumed_by(
                store, "preparation-command-intents", command, transaction
            )
        )
        self.assertEqual(transaction, mutation.payload["transactionIntentSha256"])
        receipt = (
            store.directory(
                "preparation-joint-consumptions",
                transaction.removeprefix("sha256:"),
            )
            / "receipt.json"
        )
        body, _, _, _ = store.verify(
            store.read_json(receipt, "joint consumption receipt"),
            "beads-preparation-joint-consumption-receipt",
        )
        self.assertEqual(command.record_sha256, body["commandRecordSha256"])

    def test_authenticated_object_publication_recovers_every_write_ahead_boundary(self) -> None:
        phases = (
            "object-publication-intent-written",
            "object-publication-object-written",
            "object-publication-journal-written",
            "object-publication-provenance-written",
            "object-publication-receipt-written",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                store = self.store()
                kind = "beads-hostile-publication-fixture"
                envelope, _, record_digest, full_digest = store.sign(
                    kind,
                    {
                        "repositoryLocatorSha256": self.repository,
                        "phase": phase,
                    },
                )
                target = (
                    store.directory("hostile-publication-fixtures")
                    / f"{record_digest.removeprefix('sha256:')}.json"
                )
                with runtime._inject_fault(phase), self.assertRaises(SystemExit):
                    runtime._publish_authenticated_record(
                        store,
                        target,
                        envelope,
                        kind,
                        record_digest,
                        full_digest,
                    )
                runtime._publish_authenticated_record(
                    store,
                    target,
                    envelope,
                    kind,
                    record_digest,
                    full_digest,
                )
                self.assertEqual(
                    runtime.canonical_bytes(envelope),
                    runtime.canonical_bytes(
                        store.read_json(target, "recovered publication fixture")
                    ),
                )
                runtime._verify_journal(
                    store, kind, record_digest, full_digest
                )

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process death")
    def test_real_controller_process_death_repairs_only_publication_suffix(self) -> None:
        """An actual dead broker resumes through the production controller protocol.

        This deliberately does not use the logic harness: the public runtime,
        client response validation, and real durable controller state machine
        all execute.  Only the AF_UNIX transport is replaced with an in-process
        packet carrier so the offline suite does not claim a Linux service
        installation or peer-credential proof.
        """

        core_payload = {
            "bootstrapChangeKind": "create",
            "adapterChangeKind": "create",
            "remediationEvidenceSha256": None,
            "baselineCommit": runtime.BEADS_BASELINE_COMMIT,
        }
        bootstrap = runtime.build_beads_bootstrap_runtime_core_v1(
            runtime.BeadsBootstrapRuntimeCoreInputsV1(payload=core_payload)
        )
        adapter = runtime.build_beads_adapter_release_core_v1(
            runtime.BeadsAdapterReleaseCoreInputsV1(payload=core_payload)
        )
        requests = [
            (
                fault_phase,
                fault_occurrence,
                runtime.RecordBeadsChangePlanCoreRequestV1(
                    payload={
                        "protectedRoot": str(self.root),
                        "hmacKeyPath": str(self.key),
                        "repositoryLocatorSha256": digest(
                            f"integrated-recovery:{fault_phase}:{fault_occurrence}"
                        ),
                        "bootstrapRuntimeCoreCanonicalJson": bootstrap.decode(),
                        "adapterReleaseCoreCanonicalJson": adapter.decode(),
                    }
                ),
            )
            for fault_phase, fault_occurrence in (
                ("object-publication-object-written", 1),
                # The first publication is already terminal.  Recovery must
                # read-only verify and skip it, then authorize only this
                # second exact incomplete publication.
                ("object-publication-object-written", 2),
                ("journal-intent-written", 2),
                ("journal-history-written", 2),
                ("journal-index-written", 2),
                ("journal-current-written", 2),
            )
        ]
        controller = runtime._boundary_controller
        state_root = self.base / "real-controller-state"
        state_root.mkdir(mode=0o700)
        controller_key = b"integrated-controller-domain-key-32bytes"
        config = controller.ControllerConfig(
            beads_enabled=True,
            protected_root=self.root,
            record_hmac_key_path=self.key,
            controller_uid=91_001,
            broker_uid=91_002,
            worker_uid=91_003,
            transport_gid=91_004,
            runtime_manifest_path=Path("/usr/lib/startup-factory/runtime.json"),
            module_path=Path("/usr/lib/startup-factory/controller.py"),
            schema_path=Path("/usr/lib/startup-factory/schema.json"),
            runtime_manifest_sha256=digest("integrated-runtime"),
            module_sha256=digest("integrated-module"),
            schema_sha256=digest("integrated-schema"),
            config_epoch=11,
            key_epoch=13,
            native_boundary_manifest_path=Path(
                "/usr/lib/startup-factory/native-boundary-v27.json"
            ),
            native_boundary_manifest_sha256=digest("integrated-native-boundary-v27"),
            native_module_path=Path(controller.native_boundary_v27.__file__),
            native_module_sha256=digest("integrated-native-module-v27"),
        )

        class PacketCarrier:
            def __init__(self, *args, **kwargs):
                if args[:2] != (socket.AF_UNIX, socket.SOCK_SEQPACKET):
                    raise AssertionError("unexpected integrated transport family/type")
                self.response = b""
                self.received = False

            def settimeout(self, _seconds):
                return None

            def connect(self, _endpoint):
                return None

            def sendall(self, packet):
                self.response = controller._serve_packet(
                    packet, config.broker_uid, config, controller_key
                )

            def recv(self, _size):
                if self.received:
                    return b""
                self.received = True
                return self.response

            def close(self):
                return None

        self.logic_harness.__exit__(None, None, None)
        try:
            with mock.patch.object(runtime.sys, "platform", "linux"), mock.patch.object(
                controller, "STATE_ROOT", state_root
            ), mock.patch.object(
                controller, "load_controller_config", return_value=config
            ), mock.patch.object(
                controller.os, "geteuid", return_value=config.broker_uid
            ), mock.patch.object(
                controller, "_validate_transport_group"
            ), mock.patch.object(
                controller, "_validate_endpoint_parent"
            ), mock.patch.object(
                controller, "_endpoint_metadata"
            ), mock.patch.object(
                controller, "_peer_credentials", return_value=(123, config.controller_uid, config.transport_gid)
            ), mock.patch.object(
                controller.socket, "socket", PacketCarrier
            ), mock.patch.object(
                runtime,
                "_execute_supervised_beads_effect_v27",
                side_effect=AssertionError(
                    "publication recovery must never execute a Beads effect"
                ),
            ):
                for ordinal, (fault_phase, fault_occurrence, request) in enumerate(requests, 1):
                    with self.subTest(
                        fault_phase=fault_phase,
                        fault_occurrence=fault_occurrence,
                    ):
                        child = os.fork()
                        if child == 0:
                            try:
                                if fault_occurrence == 1:
                                    with runtime._inject_fault(fault_phase):
                                        runtime.record_beads_change_plan_core_v1(request)
                                else:
                                    original_fault = runtime._fault
                                    seen = 0

                                    def kill_at_later_publication(phase):
                                        nonlocal seen
                                        if phase == fault_phase:
                                            seen += 1
                                            if seen == fault_occurrence:
                                                raise SystemExit(137)
                                        original_fault(phase)

                                    runtime._fault = kill_at_later_publication
                                    runtime.record_beads_change_plan_core_v1(request)
                            except SystemExit:
                                os._exit(91)
                            except BaseException:
                                os._exit(93)
                            os._exit(92)
                        _, status = os.waitpid(child, 0)
                        self.assertTrue(os.WIFEXITED(status))
                        self.assertEqual(91, os.WEXITSTATUS(status))

                        publication_root = (
                            self.root
                            / runtime.REPOSITORY_NAMESPACE
                            / request.payload["repositoryLocatorSha256"].removeprefix("sha256:")
                            / "object-publications"
                        )
                        before_receipts = sorted(publication_root.glob("*/receipt.json"))
                        if fault_occurrence == 2:
                            self.assertEqual(1, len(before_receipts))

                        incomplete = [
                            path
                            for path in publication_root.iterdir()
                            if not (path / "receipt.json").exists()
                        ]
                        self.assertEqual(1, len(incomplete))
                        incomplete_intent = json.loads(
                            (incomplete[0] / "intent.json").read_bytes()
                        )
                        expected_incomplete_intent = runtime.sha256(
                            runtime.canonical_bytes(incomplete_intent["payload"])
                        )
                        protected_repository = publication_root.parent

                        def protected_snapshot():
                            return {
                                str(path.relative_to(protected_repository)): path.read_bytes()
                                for path in protected_repository.rglob("*")
                                if path.is_file()
                            }

                        before_inspection = protected_snapshot()
                        real_recover = controller.recover_publication_operation

                        def assert_read_only_before_recover(*args, **kwargs):
                            if kwargs.get("phase") == "authorize-publication":
                                self.assertEqual(before_inspection, protected_snapshot())
                            return real_recover(*args, **kwargs)

                        with mock.patch.object(
                            controller,
                            "recover_publication_operation",
                            side_effect=assert_read_only_before_recover,
                        ):
                            with self.assertRaisesRegex(
                                runtime.BeadsProtectedRuntimeError,
                                "exact publication suffix recovered; original operation outcome remains uncertain",
                            ):
                                runtime.record_beads_change_plan_core_v1(request)

                        if fault_occurrence == 2:
                            self.assertEqual(
                                2,
                                len(list(publication_root.glob("*/receipt.json"))),
                            )

                        state_files = sorted(state_root.glob("*.json"))
                        self.assertEqual(ordinal, len(state_files))
                        states = [
                            controller._load_state(path, controller_key)
                            for path in state_files
                        ]
                        self.assertTrue(all(state is not None for state in states))
                        matching_recovery = []
                        for state in states:
                            assert state is not None
                            self.assertEqual("publication-recovered", state[1]["state"])
                            self.assertIsNotNone(state[1]["response"]["resultSha256"])
                            if (
                                state[1]["recoveryPublicationIntentSha256"]
                                == expected_incomplete_intent
                            ):
                                matching_recovery.append(state)
                        self.assertEqual(1, len(matching_recovery))
                receipts = sorted(
                    (self.root / runtime.REPOSITORY_NAMESPACE).glob(
                        "*/object-publications/*/receipt.json"
                    )
                )
                # Every later-publication case has two durable publications;
                # the first-publication fixture has one.
                self.assertEqual(1 + (2 * (len(requests) - 1)), len(receipts))
        finally:
            self.logic_harness = logic_harness(
                runtime, self.root, self.key, self.repository
            )
            self.logic_harness.__enter__()

        self.repository = digest("stale-core-preparation-command")
        stale_lease, stale_argv = self.create_authorized_create_lease("stale-core-command")
        stale_store = self.store()
        stale_command, stale_transaction = self.sign_preparation_command(
            stale_lease, stale_argv, "stale-core"
        )
        current_runtime = stale_store.directory("runtime-api-manifests") / "current.json"
        current_runtime.rename(current_runtime.with_suffix(".saved"))
        stale_transactions = stale_store.repository / "transactions"
        stale_before = sorted(
            str(path.relative_to(stale_transactions))
            for path in stale_transactions.rglob("intent.json")
        ) if stale_transactions.exists() else []
        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "current|core"):
            runtime.begin_beads_mutation_v1(
                self.request(
                    "BeginBeadsMutationRequestV1",
                    mutationClass="preparation",
                    mutationNonce=stale_transaction.removeprefix("sha256:"),
                    commandArgv=stale_argv,
                    expiresAtUnix=stale_lease.payload["expiresAtUnix"],
                    preparationLeaseRecordSha256=stale_lease.record_sha256,
                    preparationCommandIntentRecordSha256=stale_command.record_sha256,
                )
            )
        stale_after = sorted(
            str(path.relative_to(stale_transactions))
            for path in stale_transactions.rglob("intent.json")
        ) if stale_transactions.exists() else []
        self.assertEqual(stale_before, stale_after)
        self.assertFalse(
            runtime._capability_consumed_by(
                stale_store,
                "preparation-command-intents",
                stale_command,
                stale_transaction,
            )
        )

    def test_create_argv_and_wire_shapes_are_closed_before_spawn(self) -> None:
        lease = runtime.BeadsPreparationLeaseV1(
            payload=self.closed_payload(
                "BeadsPreparationLeaseV1",
                preparationMode="create",
                createStageDatabasePath=str(self.base / "stage"),
                executablePath=str(self.base / "bd"),
                nextCommandOrdinal=0,
            )
        )
        with self.assertRaises(runtime.BeadsProtectedRuntimeError):
            runtime._expected_preparation_command(
                lease,
                "binary-proof",
                [str(self.base / "bd"), "attacker-command", str(self.base / "stage")],
            )

        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "unknown"):
            runtime.authorize_beads_authority_transition_v1(
                self.request(
                    "AuthorizeBeadsAuthorityTransitionRequestV1",
                    command="revoke",
                    authorizationNonce="unknown-field",
                    expiresAtUnix=self.expires,
                    expectedCurrentFullBytesSha256=None,
                    candidate=None,
                    unexpected="must-fail",
                    **self.sequence(),
                )
            )

    def test_release_observations_require_exact_unique_complete_a_b_c(self) -> None:
        observation = {
            "bootstrapRuntimeCoreSha256": digest("bootstrap"),
            "adapterReleaseCoreSha256": digest("adapter-core"),
            "runtimeApiManifestRecordSha256": digest("runtime-manifest"),
            "adapterPayloadSha256": digest("adapter-payload"),
            "remediationEvidenceSha256": None,
        }
        common = {
            "bootstrapRuntimeCoreSha256": observation["bootstrapRuntimeCoreSha256"],
            "adapterReleaseCoreSha256": observation["adapterReleaseCoreSha256"],
            "runtimeApiManifestRecordSha256": observation["runtimeApiManifestRecordSha256"],
            "adapterPayloadSha256": observation["adapterPayloadSha256"],
            "releaseIdentitySha256": digest("release"),
            "remediationEvidenceSha256": None,
        }
        duplicate = self.request(
            "RecordBeadsAdapterReleaseManifestRequestV1",
            runtimeManifestObservations=[
                {**observation, "phase": phase} for phase in ("A", "A", "C")
            ],
            **common,
        )
        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "unique ordered A/B/C"):
            runtime.record_beads_adapter_release_manifest_v1(
                duplicate,
                runtime.BeadsAdapterReleaseManifestRecordCapabilityV1(
                    payload=self.closed_payload("BeadsAdapterReleaseManifestRecordCapabilityV1")
                ),
            )
        malformed = self.request(
            "RecordBeadsAdapterReleaseManifestRequestV1",
            runtimeManifestObservations=[
                {**observation, "phase": phase, "unknown": "forbidden"}
                for phase in ("A", "B", "C")
            ],
            **common,
        )
        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "observation is malformed"):
            runtime.record_beads_adapter_release_manifest_v1(
                malformed,
                runtime.BeadsAdapterReleaseManifestRecordCapabilityV1(
                    payload=self.closed_payload("BeadsAdapterReleaseManifestRecordCapabilityV1")
                ),
            )

    def test_epoch_change_invalidates_claim_chain_before_successor_write(self) -> None:
        first_authority = self.seed_authority("active")
        claim = runtime.prepare_atomic_claim_v1(
            self.request(
                "PrepareAtomicClaimRequestV1",
                taskId="task-stale-epoch",
                expectedRevision="r1",
                claimNonce="claim-stale-epoch",
                expiresAtUnix=self.expires,
            )
        )
        self.seed_authority("active", 2, first_authority.full_bytes_sha256)
        with self.assertRaisesRegex(runtime.BeadsStaleAuthorityError, "current active authority"):
            runtime.advance_atomic_claim_v1(
                self.request(
                    "AdvanceAtomicClaimRequestV1",
                    leaseRecordSha256=claim.record_sha256,
                    observedRevision="r2",
                    observedStatus="active",
                    claimSucceeded=True,
                )
            )

    def test_executable_replacement_cannot_reintroduce_broker_spawn(self) -> None:
        large_binary = self.base / "large-approved-bd"
        large_bytes = b"#!/bin/sh\nexit 0\n#" + (b"x" * (runtime.MAX_CANONICAL_BYTES + 1)) + b"\n"
        large_binary.write_bytes(large_bytes)
        large_binary.chmod(0o700)
        large_observation = runtime._observe_executable(
            large_binary, runtime.sha256(large_bytes)
        )
        pinned, pinned_observation = runtime._install_pinned_executable(
            self.store(), large_binary, large_observation
        )
        self.assertEqual(runtime.sha256(large_bytes), pinned_observation["bytesSha256"])
        self.assertEqual(0o500, pinned.stat().st_mode & 0o777)
        retry_pinned, retry_observation = runtime._install_pinned_executable(
            self.store(), large_binary, large_observation
        )
        self.assertEqual(pinned, retry_pinned)
        self.assertEqual(pinned_observation, retry_observation)

        source = inspect.getsource(runtime)
        self.assertNotIn("def _spawn_verified_executable_v1", source)
        self.assertNotIn("subprocess.run(", source)

    def test_journal_old_head_and_deleted_terminal_evidence_are_not_recoverable(self) -> None:
        store = self.store()
        first = runtime._signed_record(
            store, "AtomicClaimReceiptV1", "atomic-claim-receipt",
            {
                "repositoryLocatorSha256": self.repository,
                "leaseRecordSha256": digest("lease-one"),
                "taskId": "task-one",
                "revision": "one",
                "status": "active",
                "claimIdentitySha256": digest("claim-one"),
                "activeAuthorityRecordSha256": digest("authority-one"),
            }, "claim-receipts",
        )
        second = runtime._signed_record(
            store, "AtomicClaimReceiptV1", "atomic-claim-receipt",
            {
                "repositoryLocatorSha256": self.repository,
                "leaseRecordSha256": digest("lease-two"),
                "taskId": "task-two",
                "revision": "two",
                "status": "active",
                "claimIdentitySha256": digest("claim-two"),
                "activeAuthorityRecordSha256": digest("authority-two"),
            }, "claim-receipts",
        )
        first_index = store.read_json(
            store.directory("journals", "by-record")
            / f"{first.record_sha256.removeprefix('sha256:')}.json",
            "first journal index",
        )
        (store.directory("journals") / "current.json").write_bytes(runtime.canonical_bytes(first_index))
        with self.assertRaises(runtime.BeadsProtectedRuntimeError):
            runtime._verify_journal(store, "atomic-claim-receipt", second.record_sha256, second.full_bytes_sha256)

        self.repository = digest("hostile-deleted-terminal")
        store, pointer, activation = self.seed_preparation_pointer("deleted-terminal")
        activation_path = store.directory("preparation-activation-receipts", "history") / (
            activation.record_sha256.removeprefix("sha256:") + ".json"
        )
        index_path = store.directory("journals", "by-record") / (
            activation.record_sha256.removeprefix("sha256:") + ".json"
        )
        index = store.read_json(index_path, "activation journal index")
        _, _, journal_record, _ = store.verify(index, "beads-protected-journal-entry")
        activation_path.unlink()
        index_path.unlink()
        (store.directory("journals", "history") / (journal_record.removeprefix("sha256:") + ".json")).unlink()
        with self.assertRaises(runtime.BeadsProtectedRuntimeError):
            runtime._finish_preparation_projection(store, pointer)
        self.assertFalse(activation_path.exists())

    def test_tree_identity_race_and_no_clobber_install_fail_closed(self) -> None:
        tree = self.base / "tree"
        child = tree / "child"
        replacement = self.base / "replacement-child"
        tree.mkdir(mode=0o700)
        child.mkdir(mode=0o700)
        replacement.mkdir(mode=0o700)
        (child / "original").write_bytes(b"original")
        (child / "original").chmod(0o600)
        (replacement / "replacement").write_bytes(b"replacement")
        (replacement / "replacement").chmod(0o600)
        saved = self.base / "saved-child"
        real_open = runtime.os.open
        switched = False

        def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal switched
            if path == "child" and dir_fd is not None and not switched:
                switched = True
                child.rename(saved)
                replacement.rename(child)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(runtime.os, "open", side_effect=swap_before_open):
            with self.assertRaises(runtime.BeadsProtectedRuntimeError):
                runtime._observe_directory_tree(tree, "raced tree")

        source_parent = self.base / "source-parent"
        target_parent = self.base / "target-parent"
        source_parent.mkdir(mode=0o700)
        target_parent.mkdir(mode=0o700)
        source = source_parent / "database"
        target = target_parent / "database"
        source.mkdir(mode=0o700)
        target.mkdir(mode=0o700)
        (source / "source-marker").write_bytes(b"source")
        (target / "target-marker").write_bytes(b"target")
        source_fd, source_leaf = runtime._open_absolute_parent(source, "source")
        target_fd, target_leaf = runtime._open_absolute_parent(target, "target")
        try:
            with self.assertRaises(runtime.BeadsProtectedRuntimeError):
                runtime._rename_directory_noreplace(source_fd, source_leaf, target_fd, target_leaf)
        finally:
            os.close(source_fd)
            os.close(target_fd)
        self.assertTrue((source / "source-marker").exists())
        self.assertTrue((target / "target-marker").exists())

    def test_wrong_preparation_core_has_zero_side_effects(self) -> None:
        self.seed_authority("revoked")
        core, runtime_manifest, release_manifest = self.seed_current_manifests()
        repository = self.base / "wrong-core-repository"
        install = repository / ".beads" / "embeddeddolt" / "db"
        install.parent.mkdir(parents=True, mode=0o700)
        repository.chmod(0o700)
        (repository / ".beads").chmod(0o700)
        install.parent.chmod(0o700)
        cleanup = self.base / "wrong-core-cleanup"
        cleanup.mkdir(mode=0o700)
        (cleanup / ".gitignore").write_bytes(b"*\n")
        (cleanup / ".gitignore").chmod(0o600)
        stage = cleanup / "db"
        executable = self.base / "wrong-core-bd"
        executable_bytes = b"#!/bin/sh\nexit 0\n"
        executable.write_bytes(executable_bytes)
        executable.chmod(0o700)
        sequence = self.sequence()
        sequence["createStageDatabasePathLocatorSha256"] = runtime.sha256(
            runtime.canonical_bytes(runtime._observe_path_locator(stage, "wrong-core stage"))
        )
        approved = self.store().directory("approved-executables")
        before = sorted(path.name for path in approved.iterdir())
        with mock.patch.object(
            runtime, "_execute_supervised_beads_effect_v27"
        ) as spawn:
            with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "core"):
                runtime.authorize_beads_preparation_v1(
                    self.request(
                        "AuthorizeBeadsPreparationRequestV1",
                        planSha256=digest("wrong-core-plan"),
                        executableSha256=runtime.sha256(executable_bytes),
                        operatorIdentitySha256=digest("wrong-core-operator"),
                        authorizationNonce="wrong-core-authorization",
                        expiresAtUnix=self.expires,
                        runtimeApiManifestRecordSha256=runtime_manifest.record_sha256,
                        adapterReleaseManifestRecordSha256=release_manifest.record_sha256,
                        bootstrapRuntimeCoreSha256=digest("wrong-bootstrap-core"),
                        adapterReleaseCoreSha256=core.payload["adapterReleaseCoreSha256"],
                        createStageDatabasePath=str(stage),
                        installedSelectorPath=None,
                        selectedStorePath=None,
                        doltRootPath=None,
                        executablePath=str(executable),
                        repositoryPath=str(repository),
                        databaseName="db",
                        installPath=str(install),
                        cleanupPath=str(cleanup),
                        statusConfigValue="open,closed",
                        sourceAuthorityTransitionReceiptRecordSha256=None,
                        sourcePreparationPointerRecordSha256=None,
                        **sequence,
                    )
                )
        self.assertEqual(before, sorted(path.name for path in approved.iterdir()))
        self.assertFalse(stage.exists())
        self.assertFalse(install.exists())
        spawn.assert_not_called()

    def test_regular_hash_binds_lstat_fd_and_final_name(self) -> None:
        parent_path = self.base / "hash-parent"
        parent_path.mkdir(mode=0o700)
        leaf = parent_path / "leaf"
        leaf.write_bytes(b"approved")
        leaf.chmod(0o600)
        replacement = parent_path / "replacement"
        replacement.write_bytes(b"replacement")
        replacement.chmod(0o600)
        metadata = leaf.lstat()
        parent = os.open(parent_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        real_fstat = runtime.os.fstat
        calls = 0

        def swap_after_hash(descriptor):
            nonlocal calls
            observed = real_fstat(descriptor)
            calls += 1
            if calls == 2:
                saved = parent_path / "saved"
                leaf.rename(saved)
                replacement.rename(leaf)
            return observed

        try:
            with mock.patch.object(runtime.os, "fstat", side_effect=swap_after_hash):
                with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "name|identity|changed"):
                    runtime._hash_regular_at(parent, "leaf", metadata, "swapped file")
        finally:
            os.close(parent)

    def test_install_revalidates_authorized_source_identity_inside_rename(self) -> None:
        source_parent = self.base / "bound-source-parent"
        target_parent = self.base / "bound-target-parent"
        source_parent.mkdir(mode=0o700)
        target_parent.mkdir(mode=0o700)
        source = source_parent / "database"
        replacement = source_parent / "replacement"
        target = target_parent / "database"
        source.mkdir(mode=0o700)
        replacement.mkdir(mode=0o700)
        expected = runtime._directory_identity(source.lstat())
        source_fd, source_leaf = runtime._open_absolute_parent(source, "source")
        target_fd, target_leaf = runtime._open_absolute_parent(target, "target")
        saved = source_parent / "saved"
        source.rename(saved)
        replacement.rename(source)
        try:
            with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "source.*identity"):
                runtime._rename_directory_noreplace(
                    source_fd,
                    source_leaf,
                    target_fd,
                    target_leaf,
                    expected_source_identity=expected,
                )
        finally:
            os.close(source_fd)
            os.close(target_fd)
        self.assertFalse(target.exists())
        self.assertTrue(source.exists())

        source.rename(replacement)
        saved.rename(source)
        raced_replacement = source_parent / "raced-replacement"
        raced_replacement.mkdir(mode=0o700)
        raced_saved = source_parent / "raced-saved"
        expected = runtime._directory_identity(source.lstat())
        source_fd, source_leaf = runtime._open_absolute_parent(source, "source")
        target_fd, target_leaf = runtime._open_absolute_parent(target, "target")
        real_cdll = runtime.ctypes.CDLL

        def swap_while_resolving_rename(*args, **kwargs):
            source.rename(raced_saved)
            raced_replacement.rename(source)
            return real_cdll(*args, **kwargs)

        try:
            with mock.patch.object(
                runtime.ctypes,
                "CDLL",
                side_effect=swap_while_resolving_rename,
            ):
                with self.assertRaisesRegex(
                    runtime.BeadsProtectedRuntimeError,
                    "quarantine|identity",
                ):
                    runtime._rename_directory_noreplace(
                        source_fd,
                        source_leaf,
                        target_fd,
                        target_leaf,
                        expected_source_identity=expected,
                    )
        finally:
            os.close(source_fd)
            os.close(target_fd)
        self.assertFalse(target.exists())
        self.assertTrue(raced_saved.exists())
        quarantine = target_parent / runtime._install_quarantine_leaf(
            target_leaf, expected
        )
        self.assertTrue(quarantine.exists())

    def test_native_rename_swap_never_exposes_replacement_at_authorized_target(self) -> None:
        source_parent = self.base / "native-source-parent"
        target_parent = self.base / "native-target-parent"
        source_parent.mkdir(mode=0o700)
        target_parent.mkdir(mode=0o700)
        source = source_parent / "database"
        replacement = source_parent / "replacement"
        target = target_parent / "database"
        source.mkdir(mode=0o700)
        replacement.mkdir(mode=0o700)
        (source / "approved").write_bytes(b"approved")
        (replacement / "unauthorized").write_bytes(b"unauthorized")
        expected = runtime._directory_identity(source.lstat())
        source_fd, source_leaf = runtime._open_absolute_parent(source, "native source")
        target_fd, target_leaf = runtime._open_absolute_parent(target, "native target")
        saved = source_parent / "saved-approved"
        invoked = False

        def swap_at_native_boundary(phase, _source_parent, source_name, _target_parent, _target_name):
            nonlocal invoked
            if phase == "install-source-to-quarantine" and not invoked:
                invoked = True
                source.rename(saved)
                replacement.rename(source)

        try:
            with mock.patch.object(runtime, "_NATIVE_MUTATION_HOOK", swap_at_native_boundary):
                with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "quarantine|identity"):
                    runtime._rename_directory_noreplace(
                        source_fd,
                        source_leaf,
                        target_fd,
                        target_leaf,
                        expected_source_identity=expected,
                    )
        finally:
            os.close(source_fd)
            os.close(target_fd)
        self.assertTrue(invoked)
        self.assertFalse(target.exists())
        self.assertFalse((target / "unauthorized").exists())

    def test_quarantined_install_tree_is_rechecked_at_native_publish_boundary(self) -> None:
        source_parent = self.base / "tree-source-parent"
        target_parent = self.base / "tree-target-parent"
        source_parent.mkdir(mode=0o700)
        target_parent.mkdir(mode=0o700)
        source = source_parent / "database"
        target = target_parent / "database"
        source.mkdir(mode=0o700)
        approved = source / "approved"
        approved.write_bytes(b"approved")
        approved.chmod(0o600)
        expected_tree = runtime._observe_directory_tree(
            source, "approved install tree"
        )
        expected_identity = expected_tree["rootIdentity"]
        source_fd, source_leaf = runtime._open_absolute_parent(
            source, "tree source"
        )
        target_fd, target_leaf = runtime._open_absolute_parent(
            target, "tree target"
        )
        hook_ran = False

        def mutate_quarantine_at_publish(
            phase, quarantine_parent, quarantine_name, _target_parent, _target_name
        ):
            nonlocal hook_ran
            if phase == "install-quarantine-to-target" and not hook_ran:
                hook_ran = True
                directory = os.open(
                    quarantine_name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=quarantine_parent,
                )
                try:
                    descriptor = os.open(
                        "approved", os.O_WRONLY | os.O_TRUNC, dir_fd=directory
                    )
                    try:
                        os.write(descriptor, b"changed!")
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(directory)

        try:
            with mock.patch.object(
                runtime, "_NATIVE_MUTATION_HOOK", mutate_quarantine_at_publish
            ):
                with self.assertRaisesRegex(
                    runtime.BeadsProtectedRuntimeError,
                    "source tree changed immediately before atomic rename",
                ):
                    runtime._rename_directory_noreplace(
                        source_fd,
                        source_leaf,
                        target_fd,
                        target_leaf,
                        expected_source_identity=expected_identity,
                        expected_source_tree=expected_tree,
                    )
        finally:
            os.close(source_fd)
            os.close(target_fd)
        self.assertTrue(hook_ran)
        self.assertFalse(target.exists())
        quarantine = target_parent / runtime._install_quarantine_leaf(
            target_leaf, expected_identity
        )
        self.assertTrue(quarantine.is_dir())

    def test_cleanup_retirement_swap_never_moves_replacement_or_deletes_evidence(self) -> None:
        parent_path = self.base / "cleanup-retirement-parent"
        parent_path.mkdir(mode=0o700)
        cleanup = parent_path / "cleanup"
        replacement = parent_path / "replacement"
        saved = parent_path / "saved-approved"
        retained = parent_path / ("startup-factory-retained-beads-" + "a" * 64)
        cleanup.mkdir(mode=0o700)
        replacement.mkdir(mode=0o700)
        (cleanup / ".gitignore").write_bytes(b"*\n")
        (replacement / "unauthorized").write_bytes(b"unauthorized")
        expected = runtime._directory_identity(cleanup.lstat())
        parent, cleanup_leaf = runtime._open_absolute_parent(
            cleanup, "cleanup retirement source"
        )
        hook_ran = False

        def swap_at_retirement_boundary(
            phase, parent_fd, source_name, _target_fd, _target_name
        ):
            nonlocal hook_ran
            if phase == "cleanup-active-to-retained" and not hook_ran:
                hook_ran = True
                os.rename(
                    source_name,
                    saved.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.rename(
                    replacement.name,
                    source_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )

        try:
            with mock.patch.object(runtime, "_NATIVE_MUTATION_HOOK", swap_at_retirement_boundary):
                with self.assertRaisesRegex(
                    runtime.BeadsProtectedRuntimeError,
                    "source identity changed immediately before atomic rename",
                ):
                    runtime._native_rename_noreplace(
                        parent,
                        cleanup_leaf,
                        parent,
                        retained.name,
                        phase="cleanup-active-to-retained",
                        expected_immediate_identity=expected,
                    )
        finally:
            os.close(parent)
        self.assertTrue(hook_ran)
        self.assertTrue(saved.is_dir())
        self.assertTrue((saved / ".gitignore").is_file())
        self.assertTrue((cleanup / "unauthorized").is_file())
        self.assertFalse(retained.exists())

    def test_open_directory_rebinds_every_final_name_after_traversal(self) -> None:
        parent = self.base / "traversal-parent"
        target = parent / "target"
        replacement = parent / "replacement"
        saved = parent / "saved-target"
        parent.mkdir(mode=0o700)
        target.mkdir(mode=0o700)
        replacement.mkdir(mode=0o700)
        real_validate = runtime._validate_directory_metadata
        switched = False

        def swap_after_open(metadata, label, *, private):
            nonlocal switched
            real_validate(metadata, label, private=private)
            if label == "bound traversal target" and not switched:
                switched = True
                target.rename(saved)
                replacement.rename(target)

        with mock.patch.object(
            runtime,
            "_validate_directory_metadata",
            side_effect=swap_after_open,
        ):
            with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "name|identity|changed"):
                descriptor, _ = runtime._open_absolute_directory(
                    target, "bound traversal target", private=True
                )
                os.close(descriptor)
        self.assertTrue(switched)

    def test_two_complete_tree_passes_detect_earlier_child_content_change(self) -> None:
        tree = self.base / "two-pass-tree"
        tree.mkdir(mode=0o700)
        child = tree / "first-child"
        child.write_bytes(b"first")
        child.chmod(0o600)
        hook_calls = 0

        def change_after_first_pass(phase, _descriptor, entries):
            nonlocal hook_calls
            self.assertEqual("between-complete-tree-passes", phase)
            self.assertEqual(1, len(entries))
            hook_calls += 1
            child.write_bytes(b"other")
            child.chmod(0o600)

        with mock.patch.object(runtime, "_TREE_PASS_HOOK", change_after_first_pass):
            with self.assertRaisesRegex(
                runtime.BeadsProtectedRuntimeError,
                "changed between the two complete physical tree passes",
            ):
                runtime._observe_directory_tree(tree, "two-pass hostile fixture")
        self.assertEqual(1, hook_calls)

    def test_production_reader_rejects_noninstalled_harness_provenance(self) -> None:
        store = self.store()
        envelope, _, record_sha256, full_sha256 = store.sign(
            "beads-test-harness-provenance-record",
            {
                "repositoryLocatorSha256": self.repository,
                "remediationEvidenceSha256": digest("test-provenance"),
            },
        )
        runtime._publish_authenticated_record(
            store,
            store.directory("test-harness-provenance-records", "history")
            / f"{record_sha256.removeprefix('sha256:')}.json",
            envelope,
            "beads-test-harness-provenance-record",
            record_sha256,
            full_sha256,
        )
        self.assertEqual(TEST_PROVENANCE, runtime._REQUIRED_PROVENANCE_DOMAIN)
        runtime._REQUIRED_PROVENANCE_DOMAIN = (
            runtime._boundary_controller.PRODUCTION_PROVENANCE
        )
        try:
            with self.assertRaisesRegex(
                runtime.BeadsProtectedRuntimeError,
                "live required controller provenance|live production provenance",
            ):
                runtime._load_record(
                    store,
                    "_WireRecord",
                    "beads-test-harness-provenance-record",
                    "test-harness-provenance-records",
                    record_sha256,
                )
        finally:
            runtime._REQUIRED_PROVENANCE_DOMAIN = TEST_PROVENANCE

    def test_finish_projection_is_the_unchanged_authenticated_result(self) -> None:
        store, pointer, _ = self.seed_preparation_pointer("authenticated-finish")
        returned = runtime._finish_preparation_projection(store, pointer)
        self.assertEqual(runtime._PREPARATION_TERMINAL, set(returned.payload))
        body, auth, record_sha, full_sha = store.verify(
            {"payload": returned.payload, "auth": returned.auth},
            "beads-preparation-result",
        )
        historical = runtime._load_record(
            store,
            "FinishBeadsPreparationResultV1",
            "beads-preparation-result",
            "preparation-results",
            returned.record_sha256,
        )
        self.assertEqual(historical.payload, body)
        self.assertEqual(historical.auth, auth)
        self.assertEqual(historical.record_sha256, record_sha)
        self.assertEqual(historical.full_bytes_sha256, full_sha)

    def test_journal_inspection_is_read_only_at_each_unique_crash_boundary(self) -> None:
        for phase in (
            "journal-intent-written",
            "journal-history-written",
            "journal-index-written",
            "journal-current-written",
        ):
            with self.subTest(phase=phase):
                self.repository = digest(f"journal-crash:{phase}")
                store = self.store()
                envelope, _, record_sha, full_sha = store.sign(
                    "hostile-journal-target",
                    {"repositoryLocatorSha256": self.repository, "phase": phase},
                )
                store.write_immutable(
                    store.directory("hostile-journal-targets", "history")
                    / f"{record_sha.removeprefix('sha256:')}.json",
                    envelope,
                )
                with runtime._inject_fault(phase), self.assertRaises(SystemExit):
                    runtime._journal_record(store, "hostile-journal-target", record_sha, full_sha)
                journal_root = store.directory("journals", create=False)
                before = {
                    str(path.relative_to(journal_root)): path.read_bytes()
                    for path in journal_root.rglob("*")
                    if path.is_file()
                }
                inspection = runtime._inspect_journal_chain(store)
                self.assertEqual(record_sha, inspection.pending_record_sha256)
                self.assertEqual(phase, inspection.incomplete_category)
                after = {
                    str(path.relative_to(journal_root)): path.read_bytes()
                    for path in journal_root.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(before, after)

    def test_every_registered_type_has_closed_schema_and_cores_roundtrip_exactly(self) -> None:
        schema = json.loads(runtime.beads_protected_runtime_schema_v1())
        self.assertEqual(set(runtime._TYPE_NAMES), set(schema["typeSchemas"]))
        for name in runtime._TYPE_NAMES:
            closure = schema["typeSchemas"][name]
            self.assertEqual({"fields", "nullable", "required"}, set(closure), name)
            self.assertEqual(set(closure["fields"]), set(closure["required"]), name)
            self.assertTrue(set(closure["nullable"]) <= set(closure["required"]), name)
            with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "unknown"):
                getattr(runtime, name)(payload={"unexpectedAuthority": "must-fail"})
            required = sorted(closure["required"])
            nullable = set(closure["nullable"])
            sample = {
                field: (None if field in nullable else f"fixture:{field}")
                for field in required
            }
            for field in required:
                missing = dict(sample)
                missing.pop(field)
                with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "missing"):
                    getattr(runtime, name)(payload=missing)
                if field not in nullable:
                    invalid_null = dict(sample)
                    invalid_null[field] = None
                    with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "non-nullable"):
                        getattr(runtime, name)(payload=invalid_null)

        with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "unknown"):
            runtime.build_beads_bootstrap_runtime_core_v1(
                runtime.BeadsBootstrapRuntimeCoreInputsV1(
                    payload={
                        "bootstrapChangeKind": "create",
                        "adapterChangeKind": "create",
                        "remediationEvidenceSha256": None,
                        "unexpectedAuthority": digest("must-fail"),
                    }
                )
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
