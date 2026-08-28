#!/usr/bin/env python3
"""Closed prepared-store payload and inert read-back-plan tests."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))
import bin.beads_contract as contract

PLAN_DOMAIN = b"startup-factory/beads-read-back-plan-candidate/v1\0"
PAYLOAD_DOMAIN = b"startup-factory/prepared-beads-store-payload/v1\0"
SOURCE_COMMIT = "20e493e569c922d1253bdeff068c5e56c94957fb"
EXPECTED_BODY = {
    "aggregateDeadlineSeconds": 120,
    "baselineVersion": "1.1.2",
    "envelope": {"noDuplicates": True, "noExtras": True, "noTrailingValue": True,
                 "outerKeys": ["data", "schema_version"], "schemaVersion": 1},
    "environmentProfile": "beads-protected-readback-env-v1",
    "kind": "beads-read-back-plan-candidate-v1",
    "maxArgvBytes": 65_536, "maxRecordBytes": 262_144, "maxSpawnCount": 4,
    "maxStringBytes": 65_536, "schemaVersion": 1, "sourceCommit": SOURCE_COMMIT,
    "stderrLimitBytesPerChild": 1_048_576, "stdoutLimitBytesPerChild": 1_048_576,
    "steps": [
        {"ordinal": 0, "requires": "terminal-mutation-process-group",
         "argvShape": ["$B", "--db", "$E", "--json", "--readonly", "--sandbox",
                       "list", "--id", "$ID", "--all", "--limit", "0"],
         "dataShape": "exact-one-issue-with-counts-v112"},
        {"ordinal": 1, "requires": "usable-ordinal-0-and-physical-equality",
         "argvShape": ["$B", "--db", "$E", "--json", "--readonly", "--sandbox",
                       "label", "list", "$ID"],
         "dataShape": "complete-label-string-array-v112"},
        {"ordinal": 2, "requires": "usable-ordinal-1-and-physical-equality",
         "argvShape": ["$B", "--db", "$E", "--json", "--readonly", "--sandbox",
                       "comments", "$ID"],
         "dataShape": "complete-comment-array-v112"},
        {"ordinal": 3, "requires": "usable-ordinal-2-and-physical-equality",
         "argvShape": ["$B", "--db", "$E", "--json", "--readonly", "--sandbox",
                       "dep", "list", "$ID", "--direction", "down"],
         "dataShape": "complete-one-id-dependency-projection-array-v112"},
    ],
}


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def expected_candidate() -> dict[str, object]:
    body = json.loads(json.dumps(EXPECTED_BODY))
    body["planSha256"] = "sha256:" + hashlib.sha256(PLAN_DOMAIN + canonical(body)).hexdigest()
    return body


def sha(index: int) -> str:
    return "sha256:" + f"{index:064x}"


def stat(*, size: int = 0, mode: str = "0700") -> dict[str, object]:
    return {"device": 1, "inode": 2, "linkCount": 1, "mode": mode,
            "size": size, "uid": 501}


def make_inputs(*, mode: str = "create"):
    return contract.PreparedBeadsStorePayloadInputsV1(
        preparation_mode=mode, repository_locator_sha256=sha(1),
        project_root_locator_sha256=sha(2), beads_root_locator_sha256=sha(3),
        beads_root_stat=stat(), embedded_data_root_stat=stat(),
        database_name="startup_factory", database_root_stat=stat(),
        database_dolt_root_stat=stat(),
        executable={"device": 8, "inode": 9, "linkCount": 1, "mode": "0500",
                    "mtimeNs": 1_777_000_000_000_000_000, "pathLocatorSha256": sha(4),
                    "sha256": sha(5), "size": 1_024, "sourceCommit": SOURCE_COMMIT,
                    "uid": 501, "version": "1.1.2"},
        immutable_files=(
            {"path": ".local_version", "sha256": sha(6), "size": 5,
             "stat": stat(size=5, mode="0600")},
            {"path": "metadata.json", "sha256": sha(7), "size": 128,
             "stat": stat(size=128, mode="0600")},
        ),
        metadata={"backend": "dolt", "database": "dolt",
                  "doltDatabase": "startup_factory", "doltMode": "embedded",
                  "projectId": "0198d4be-frozen-project", "sha256": sha(8)},
        status_profile_payload_sha256=sha(9), status_profile_static_bindings_sha256=sha(10),
        status_profile_derivation_policy_sha256=sha(11),
        status_profile_dynamic_bindings_sha256=sha(12),
        status_profile_expected_bindings_sha256=sha(13),
        derivation_journal_head_sha256=sha(14), runtime_api_manifest_sha256=sha(15),
        release_manifest_sha256=sha(16), generic_status_config_sha256=sha(17),
        pre_store_observation_sha256=sha(18), post_store_observation_sha256=sha(19),
        store_state_sha256=sha(20), config_envelope_canonical_sha256=sha(21),
        cleanup_observation_sha256=sha(22) if mode == "create" else None,
        preparation_plan_sha256=sha(23), authority_epoch="0123456789abcdef0123456789abcdef",
        predecessor_prepared_store_payload_sha256=None if mode == "create" else sha(25),
    )


def make_expected(*, mode: str = "create"):
    """Independent golden binding; never projected from builder inputs."""

    return contract.PreparedBeadsStoreExpectedBindingsV1(
        preparation_mode=mode,
        repository_locator_sha256=sha(1),
        project_root_locator_sha256=sha(2),
        beads_root_locator_sha256=sha(3),
        database_name="startup_factory",
        metadata_sha256=sha(8),
        status_profile_payload_sha256=sha(9),
        status_profile_static_bindings_sha256=sha(10),
        status_profile_derivation_policy_sha256=sha(11),
        status_profile_dynamic_bindings_sha256=sha(12),
        status_profile_expected_bindings_sha256=sha(13),
        derivation_journal_head_sha256=sha(14),
        runtime_api_manifest_sha256=sha(15),
        release_manifest_sha256=sha(16),
        generic_status_config_sha256=sha(17),
        pre_store_observation_sha256=sha(18),
        post_store_observation_sha256=sha(19),
        store_state_sha256=sha(20),
        config_envelope_canonical_sha256=sha(21),
        cleanup_observation_sha256=sha(22) if mode == "create" else None,
        preparation_plan_sha256=sha(23),
        authority_epoch="0123456789abcdef0123456789abcdef",
        predecessor_prepared_store_payload_sha256=None if mode == "create" else sha(25),
        read_back_plan_candidate_sha256=(
            "sha256:fe7dd91760b115a3c0b6dda7c191de272808606468fa9d38056456efa60847b8"
        ),
        payload_sha256=(
            "sha256:d020688edfbcd679d4c408f6bba8065e94467e909db118b7caac25b9245b0cd8"
            if mode == "create"
            else "sha256:5fe2b2493d7ec9281b25163feedca1697394415a8c4f03852fcbe06c12466743"
        ),
    )


def mutate(data: bytes, change) -> bytes:
    value = json.loads(data)
    change(value)
    return canonical(value)


class ReadBackCandidateTest(unittest.TestCase):
    def test_exact_bytes_domain_argv_shapes_counts_completeness_and_bounds(self) -> None:
        candidate = contract._build_beads_read_back_plan_candidate_v1()
        expected = expected_candidate()
        self.assertEqual(candidate.payload, expected)
        self.assertEqual(candidate.canonical_bytes, canonical(expected))
        self.assertFalse(candidate.canonical_bytes.endswith(b"\n"))
        self.assertEqual(candidate.plan_sha256,
                         "sha256:fe7dd91760b115a3c0b6dda7c191de272808606468fa9d38056456efa60847b8")
        self.assertEqual(len(candidate.canonical_bytes), 1_449)
        self.assertEqual(contract._validate_beads_read_back_plan_candidate_v1(
            candidate.canonical_bytes), candidate)
        self.assertEqual([step["ordinal"] for step in expected["steps"]], [0, 1, 2, 3])
        self.assertEqual(expected["steps"], EXPECTED_BODY["steps"])

    def test_wrong_task_schema_argv_order_extra_missing_alias_and_digest_fail(self) -> None:
        changes = (
            lambda v: v["steps"][0]["argvShape"].__setitem__(8, "TASK-2"),
            lambda v: v.__setitem__("schemaVersion", 2),
            lambda v: v["envelope"].__setitem__("schemaVersion", True),
            lambda v: v["steps"][1]["argvShape"].__setitem__(6, "labels"),
            lambda v: v["steps"].__setitem__(slice(0, 2), v["steps"][1::-1]),
            lambda v: v["steps"][3]["argvShape"].__setitem__(8, "$TASK_ID"),
            lambda v: v.__setitem__("extra", None), lambda v: v.pop("maxStringBytes"),
        )
        for change in changes:
            value = expected_candidate()
            change(value)
            body = {k: item for k, item in value.items() if k != "planSha256"}
            value["planSha256"] = "sha256:" + hashlib.sha256(PLAN_DOMAIN + canonical(body)).hexdigest()
            with self.assertRaises(ValueError):
                contract._validate_beads_read_back_plan_candidate_v1(canonical(value))
        value = expected_candidate()
        value["planSha256"] = sha(0)
        with self.assertRaises(ValueError):
            contract._validate_beads_read_back_plan_candidate_v1(canonical(value))

    def test_duplicate_bom_trailing_noncanonical_nonfinite_and_oversize_fail(self) -> None:
        good = canonical(expected_candidate())
        hostile = (good.replace(b'{"aggregateDeadlineSeconds":120,',
                                b'{"aggregateDeadlineSeconds":120,"aggregateDeadlineSeconds":120,', 1),
                   b"\xef\xbb\xbf" + good, good + b"{}",
                   json.dumps(expected_candidate(), indent=2).encode(),
                   good.replace(b'"maxSpawnCount":4', b'"maxSpawnCount":NaN'),
                   b"{" + b" " * 32_769 + b"}")
        for value in hostile:
            with self.assertRaises(ValueError):
                contract._validate_beads_read_back_plan_candidate_v1(value)

    def test_terminal_process_token_is_the_only_process_path_authority_value(self) -> None:
        candidate = contract._build_beads_read_back_plan_candidate_v1().payload
        forbidden = ("process", "path", "authority")
        def visit(value: object) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    self.assertFalse(any(word in key.casefold() for word in forbidden))
                    visit(item)
            elif isinstance(value, list):
                for item in value: visit(item)
            elif isinstance(value, str) and any(word in value.casefold() for word in forbidden):
                self.assertEqual(value, "terminal-mutation-process-group")
        visit(candidate)
        for bad in ("pid-42", "/tmp/bd", "protected-authority", "other-process-group"):
            value = expected_candidate()
            value["steps"][0]["requires"] = bad
            body = {k: item for k, item in value.items() if k != "planSha256"}
            value["planSha256"] = "sha256:" + hashlib.sha256(PLAN_DOMAIN + canonical(body)).hexdigest()
            with self.assertRaises(ValueError):
                contract._validate_beads_read_back_plan_candidate_v1(canonical(value))


class PreparedPayloadTest(unittest.TestCase):
    def test_production_builder_emits_exact_closed_canonical_payload(self) -> None:
        inputs = make_inputs()
        data = contract.build_prepared_beads_store_payload_v1(inputs)
        payload = json.loads(data)
        fields = {"authorityEpoch", "beadsRootLocatorSha256", "beadsRootRelative", "beadsRootStat",
                  "cleanupObservationSha256", "configEnvelopeCanonicalSha256", "databaseDoltRootStat",
                  "databaseName", "databaseRootRelative", "databaseRootStat", "derivationJournalHeadSha256",
                  "embeddedDataRootRelative", "embeddedDataRootStat", "executable", "genericStatusConfigSha256",
                  "immutableFiles", "kind", "lastTouchedPolicy", "metadata", "postStoreObservationSha256",
                  "preStoreObservationSha256", "predecessorPreparedStorePayloadSha256", "preparationMode",
                  "preparationPlanSha256", "projectRootLocatorSha256", "readBackPlanCandidate",
                  "readBackPlanCandidateSha256", "releaseManifestSha256", "repositoryLocatorSha256",
                  "runtimeApiManifestSha256", "schemaVersion", "statusProfileDerivationPolicySha256",
                  "statusProfileDynamicBindingsSha256", "statusProfileExpectedBindingsSha256",
                  "statusProfilePayloadSha256", "statusProfileStaticBindingsSha256", "storeStateSha256"}
        self.assertEqual(set(payload), fields)
        self.assertEqual(data, canonical(payload)); self.assertLessEqual(len(data), 32_768)
        self.assertEqual(payload["databaseRootRelative"], "embeddeddolt/startup_factory")
        self.assertEqual(payload["readBackPlanCandidate"], expected_candidate())
        self.assertEqual(payload["readBackPlanCandidateSha256"], expected_candidate()["planSha256"])
        self.assertNotEqual(payload["readBackPlanCandidateSha256"],
                            "sha256:" + hashlib.sha256(canonical(expected_candidate())).hexdigest())
        verified = contract.validate_prepared_beads_store_payload_v1(data, make_expected())
        self.assertEqual(verified.canonical_bytes, data)
        self.assertEqual(verified.payload_sha256,
                         "sha256:" + hashlib.sha256(PAYLOAD_DOMAIN + data).hexdigest())

    def test_modes_and_full_payload_hostile_mutations(self) -> None:
        for mode in ("create", "reattest"):
            inputs = make_inputs(mode=mode)
            data = contract.build_prepared_beads_store_payload_v1(inputs)
            contract.validate_prepared_beads_store_payload_v1(data, make_expected(mode=mode))
        wrong = dataclasses.replace(make_inputs(), predecessor_prepared_store_payload_sha256=sha(31))
        with self.assertRaises(ValueError): contract.build_prepared_beads_store_payload_v1(wrong)

        inputs = make_inputs(); good = contract.build_prepared_beads_store_payload_v1(inputs)
        changes = (
            lambda p: p.pop("readBackPlanCandidate"), lambda p: p.pop("readBackPlanCandidateSha256"),
            lambda p: p.__setitem__("readbackPlanCandidate", p.pop("readBackPlanCandidate")),
            lambda p: p.__setitem__("readBackPlanCandidateSha256", sha(0)),
            lambda p: p["readBackPlanCandidate"].__setitem__("maxSpawnCount", 5),
            lambda p: p.__setitem__("futureJournalHeadSha256", sha(30)),
            lambda p: p.pop("preparationPlanSha256"), lambda p: p["metadata"].__setitem__("alias", "no"),
        )
        for change in changes:
            with self.assertRaises(ValueError):
                contract.validate_prepared_beads_store_payload_v1(mutate(good, change), make_expected())

    def test_forbidden_fields_and_hostile_bytes_fail(self) -> None:
        inputs = make_inputs(); good = contract.build_prepared_beads_store_payload_v1(inputs)
        forbidden = {"hmacSha256": "0" * 64, "protectedLocator": sha(30), "objectSha256": sha(30),
                     "finishResultSha256": sha(30), "currentPointerSha256": sha(30), "generation": 1,
                     "futureJournalHeadSha256": sha(30), "processId": 42, "containerId": "c",
                     "snapshotSha256": sha(30), "outputPath": "/tmp/out", "enablement": True}
        for field, value in forbidden.items():
            with self.assertRaises(ValueError):
                contract.validate_prepared_beads_store_payload_v1(
                    mutate(good, lambda p, f=field, v=value: p.__setitem__(f, v)), make_expected())
        hostile = (good.replace(b'{"authorityEpoch":',
                                b'{"authorityEpoch":"0123456789abcdef0123456789abcdef","authorityEpoch":', 1),
                   b"\xef\xbb\xbf" + good, good + b"{}", json.dumps(json.loads(good), indent=2).encode(),
                   good.replace(b'"maximumBytes":129', b'"maximumBytes":NaN'))
        for value in hostile:
            with self.assertRaises(ValueError):
                contract.validate_prepared_beads_store_payload_v1(value, make_expected())

    def test_production_consumer_expected_binding_and_order_negatives(self) -> None:
        inputs = make_inputs(); built = contract.build_prepared_beads_store_payload_v1(inputs)
        without = mutate(built, lambda p: (p.pop("readBackPlanCandidate"),
                                           p.pop("readBackPlanCandidateSha256")))
        with self.assertRaises(ValueError):
            contract.validate_prepared_beads_store_payload_v1(without, make_expected())
        with self.assertRaises((TypeError, ValueError)):
            contract.build_prepared_beads_store_payload_v1(dataclasses.asdict(inputs))
        mismatch = dataclasses.replace(make_expected(), preparation_plan_sha256=sha(63))
        with self.assertRaises(ValueError):
            contract.validate_prepared_beads_store_payload_v1(built, mismatch)
        with self.assertRaises(ValueError):
            contract.build_prepared_beads_store_payload_v1(
                dataclasses.replace(inputs, immutable_files=tuple(reversed(inputs.immutable_files))))

    def test_candidate_private_package_surface_and_frozen_counts(self) -> None:
        public = {name for name in vars(contract)
                  if not name.startswith("_") and "ReadBackPlanCandidate" in name}
        self.assertEqual(public, set())
        self.assertEqual(
            contract.__all__,
            (
                "PreparedBeadsStorePayloadInputsV1",
                "PreparedBeadsStoreExpectedBindingsV1",
                "PreparedBeadsStorePayloadV1",
                "VerifiedPreparedBeadsStorePayloadV1",
                "build_prepared_beads_store_payload_v1",
                "validate_prepared_beads_store_payload_v1",
            ),
        )
        self.assertFalse(hasattr(contract.PreparedBeadsStoreExpectedBindingsV1, "from_inputs"))
        import startup_factory_cli
        self.assertFalse(hasattr(startup_factory_cli, "BeadsReadBackPlanCandidateV1"))
        from startup_factory_cli import beads_boundary_controller, beads_protected_runtime
        self.assertEqual(len(beads_protected_runtime._TYPE_NAMES), 92)
        self.assertEqual(len(beads_protected_runtime._FUNCTION_EXPORTS), 33)
        self.assertEqual(len(beads_boundary_controller.ALLOWED_OPERATIONS), 30)


if __name__ == "__main__":
    unittest.main()
