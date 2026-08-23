#!/usr/bin/env python3
"""Hostile regression controls for the protected Beads authority boundary."""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

runtime = importlib.import_module("startup_factory_cli.beads_protected_runtime")


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

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(self, name: str, **values):
        return getattr(runtime, name)(
            payload={
                "protectedRoot": str(self.root),
                "hmacKeyPath": str(self.key),
                "repositoryLocatorSha256": self.repository,
                **values,
            }
        )

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
        return runtime._Store(self.request("VerifyBeadsProtectedRuntimeApiManifestRequestV1").payload)

    def seed_authority(self, state: str, generation: int = 1, predecessor: str | None = None):
        store = self.store()
        return runtime._write_current(
            store,
            "BeadsAuthorityEpochStateV1",
            "beads-authority-epoch-state",
            "authority",
            {
                "repositoryLocatorSha256": self.repository,
                "generation": generation,
                "authorityState": state,
                "predecessorCurrentFullBytesSha256": predecessor,
                "preparationPointerRecordSha256": digest(f"pointer:{generation}"),
                "adapterReleaseManifestRecordSha256": digest(f"release:{generation}"),
                "runtimeApiManifestRecordSha256": digest(f"runtime:{generation}"),
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
            payload={
                "repositoryLocatorSha256": self.repository,
                "repositoryPath": str(repository_path),
                "databaseName": "db",
                "verifiedReceiptRecordSha256": digest("absent-receipt"),
            }
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
                "predecessorCurrentFullBytesSha256": None,
                "preparationPointerRecordSha256": digest("pointer"),
                "adapterReleaseManifestRecordSha256": digest("release"),
                "runtimeApiManifestRecordSha256": digest("runtime"),
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

    def test_create_argv_and_wire_shapes_are_closed_before_spawn(self) -> None:
        lease = runtime.BeadsPreparationLeaseV1(
            payload={
                "preparationMode": "create",
                "createStageDatabasePath": str(self.base / "stage"),
                "executablePath": str(self.base / "bd"),
                "nextCommandOrdinal": 0,
            }
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
                runtime.BeadsAdapterReleaseManifestRecordCapabilityV1(payload={}),
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
                runtime.BeadsAdapterReleaseManifestRecordCapabilityV1(payload={}),
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

    def test_executable_replacement_cannot_reach_spawn(self) -> None:
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

        binary = self.base / "approved-bd"
        approved_marker = self.base / "approved-ran"
        replacement_marker = self.base / "replacement-ran"
        approved = f"#!/bin/sh\nprintf approved >'{approved_marker}'\n".encode()
        replacement = f"#!/bin/sh\nprintf replacement >'{replacement_marker}'\n".encode()
        binary.write_bytes(approved)
        binary.chmod(0o700)
        expected = runtime._observe_executable(binary, runtime.sha256(approved))
        real_run = runtime.subprocess.run

        def replace_then_run(argv, **kwargs):
            replacement_path = self.base / "replacement-bd"
            replacement_path.write_bytes(replacement)
            replacement_path.chmod(0o700)
            os.replace(replacement_path, binary)
            return real_run(argv, **kwargs)

        with mock.patch.object(runtime.subprocess, "run", side_effect=replace_then_run):
            with self.assertRaises(runtime.BeadsProtectedRuntimeError):
                runtime._spawn_verified_executable_v1(
                    binary,
                    expected,
                    [str(binary)],
                    cwd=self.base,
                    env={"PATH": "/usr/bin:/bin"},
                )
        self.assertTrue(approved_marker.exists())
        self.assertFalse(replacement_marker.exists())

    def test_journal_old_head_and_deleted_terminal_evidence_are_not_recoverable(self) -> None:
        store = self.store()
        first = runtime._signed_record(
            store, "AtomicClaimReceiptV1", "atomic-claim-receipt",
            {"repositoryLocatorSha256": self.repository, "revision": "one"}, "claim-receipts",
        )
        second = runtime._signed_record(
            store, "AtomicClaimReceiptV1", "atomic-claim-receipt",
            {"repositoryLocatorSha256": self.repository, "revision": "two"}, "claim-receipts",
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

    def test_every_registered_type_has_closed_schema_and_cores_roundtrip_exactly(self) -> None:
        schema = json.loads(runtime.beads_protected_runtime_schema_v1())
        self.assertEqual(set(runtime._TYPE_NAMES), set(schema["typeSchemas"]))
        for name in runtime._TYPE_NAMES:
            closure = schema["typeSchemas"][name]
            self.assertEqual({"fields", "nullable", "required"}, set(closure), name)
            with self.assertRaisesRegex(runtime.BeadsProtectedRuntimeError, "unknown"):
                getattr(runtime, name)(payload={"unexpectedAuthority": "must-fail"})

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
