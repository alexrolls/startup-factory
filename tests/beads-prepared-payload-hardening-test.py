#!/usr/bin/env python3
"""Independent hostile/golden tests for PreparedBeadsStorePayloadV1."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bin.beads_contract as contract

FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN_PATH = FIXTURES / "prepared-beads-store-payload-v1.golden.json"
SCHEMA_PATH = FIXTURES / "prepared-beads-store-payload-v1.schema.json"
COMPATIBILITY_PATH = FIXTURES / "beads-read-back-plan-candidate-v1.compatibility.json"
PAYLOAD_DOMAIN = b"startup-factory/prepared-beads-store-payload/v1\0"


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def golden(mode: str) -> tuple[bytes, Any]:
    fixture = load_fixture(GOLDEN_PATH)[mode]
    data = fixture["canonicalUtf8"].encode("utf-8")
    expected = contract.PreparedBeadsStoreExpectedBindingsV1(**fixture["expectedBindings"])
    return data, expected


def inputs_from_payload(payload: dict[str, Any]):
    return contract.PreparedBeadsStorePayloadInputsV1(
        preparation_mode=payload["preparationMode"],
        repository_locator_sha256=payload["repositoryLocatorSha256"],
        project_root_locator_sha256=payload["projectRootLocatorSha256"],
        beads_root_locator_sha256=payload["beadsRootLocatorSha256"],
        beads_root_stat=payload["beadsRootStat"],
        embedded_data_root_stat=payload["embeddedDataRootStat"],
        database_name=payload["databaseName"],
        database_root_stat=payload["databaseRootStat"],
        database_dolt_root_stat=payload["databaseDoltRootStat"],
        executable=payload["executable"],
        immutable_files=payload["immutableFiles"],
        metadata=payload["metadata"],
        status_profile_payload_sha256=payload["statusProfilePayloadSha256"],
        status_profile_static_bindings_sha256=payload["statusProfileStaticBindingsSha256"],
        status_profile_derivation_policy_sha256=payload["statusProfileDerivationPolicySha256"],
        status_profile_dynamic_bindings_sha256=payload["statusProfileDynamicBindingsSha256"],
        status_profile_expected_bindings_sha256=payload["statusProfileExpectedBindingsSha256"],
        derivation_journal_head_sha256=payload["derivationJournalHeadSha256"],
        runtime_api_manifest_sha256=payload["runtimeApiManifestSha256"],
        release_manifest_sha256=payload["releaseManifestSha256"],
        generic_status_config_sha256=payload["genericStatusConfigSha256"],
        pre_store_observation_sha256=payload["preStoreObservationSha256"],
        post_store_observation_sha256=payload["postStoreObservationSha256"],
        store_state_sha256=payload["storeStateSha256"],
        config_envelope_canonical_sha256=payload["configEnvelopeCanonicalSha256"],
        cleanup_observation_sha256=payload["cleanupObservationSha256"],
        preparation_plan_sha256=payload["preparationPlanSha256"],
        authority_epoch=payload["authorityEpoch"],
        predecessor_prepared_store_payload_sha256=payload["predecessorPreparedStorePayloadSha256"],
    )


def inputs_from_golden(mode: str):
    return inputs_from_payload(json.loads(golden(mode)[0]))


def replace_path(value: Any, path: tuple[Any, ...], replacement: Any) -> None:
    cursor = value
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement


def leaf_paths(value: Any, path: tuple[Any, ...] = ()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaf_paths(item, path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaf_paths(item, path + (index,))
    else:
        yield path, value


def alternate(value: Any) -> Any:
    if value is None:
        return "sha256:" + "f" * 64
    if isinstance(value, bool):
        return not value
    if type(value) is int:
        return value + 1
    if isinstance(value, str) and value.startswith("sha256:"):
        return value[:-1] + ("e" if value[-1] != "e" else "d")
    if isinstance(value, str):
        return value + "-mutated"
    raise AssertionError(type(value))


class PreparedPayloadHardeningTest(unittest.TestCase):
    def test_golden_create_and_reattest_bytes_and_domain_digests(self) -> None:
        fixture = load_fixture(GOLDEN_PATH)
        exact = {
            "create": "sha256:d020688edfbcd679d4c408f6bba8065e94467e909db118b7caac25b9245b0cd8",
            "reattest": "sha256:5fe2b2493d7ec9281b25163feedca1697394415a8c4f03852fcbe06c12466743",
        }
        for mode, digest in exact.items():
            data, expected = golden(mode)
            self.assertEqual(fixture[mode]["payloadSha256"], digest)
            self.assertEqual("sha256:" + hashlib.sha256(PAYLOAD_DOMAIN + data).hexdigest(), digest)
            self.assertEqual(contract.build_prepared_beads_store_payload_v1(
                inputs_from_golden(mode)), data)
            self.assertEqual(contract.validate_prepared_beads_store_payload_v1(
                data, expected).payload_sha256, digest)

    def test_independent_expected_binding_and_authorized_import_surface(self) -> None:
        self.assertFalse(hasattr(contract.PreparedBeadsStoreExpectedBindingsV1, "from_inputs"))
        expected_exports = (
            "PreparedBeadsStorePayloadInputsV1",
            "PreparedBeadsStoreExpectedBindingsV1",
            "PreparedBeadsStorePayloadV1",
            "VerifiedPreparedBeadsStorePayloadV1",
            "build_prepared_beads_store_payload_v1",
            "validate_prepared_beads_store_payload_v1",
        )
        self.assertEqual(contract.__all__, expected_exports)
        namespace: dict[str, Any] = {}
        exec("from bin.beads_contract import *", namespace)
        self.assertEqual({key for key in namespace if key != "__builtins__"}, set(expected_exports))
        self.assertFalse(any("Candidate" in key for key in namespace))

    def test_non_test_production_consumer_uses_canonical_builder_and_validator(self) -> None:
        from bin import beads_preparation

        data, expected = golden("create")
        verified = beads_preparation._prepare_unsigned_beads_store_payload_v1(
            inputs_from_golden("create"), expected
        )
        self.assertEqual(verified.canonical_bytes, data)

    def test_schema_and_cross_task_compatibility_fixtures_are_exact(self) -> None:
        schema = load_fixture(SCHEMA_PATH)
        compatibility = load_fixture(COMPATIBILITY_PATH)
        create_payload = json.loads(golden("create")[0])
        self.assertEqual(schema["topLevelFields"], sorted(create_payload))
        self.assertEqual(schema["carrierNames"],
                         ["readBackPlanCandidate", "readBackPlanCandidateSha256"])
        self.assertEqual(schema["carrierDigestMeaning"],
                         "nested-domain-separated-planSha256")
        self.assertEqual(schema["payloadDomain"],
                         "startup-factory/prepared-beads-store-payload/v1\\0")
        self.assertEqual(schema["ownershipAndDacPolicy"]["gid"],
                         "not-carried-by-StatV1")
        self.assertEqual(schema["ownershipAndDacPolicy"]["executableMode"], "0500")
        self.assertEqual(compatibility["producerModule"], "bin.beads_contract")
        self.assertEqual(compatibility["candidate"], create_payload["readBackPlanCandidate"])
        self.assertEqual(compatibility["projectedPlanSha256"],
                         create_payload["readBackPlanCandidateSha256"])
        self.assertNotEqual(compatibility["rawCanonicalBytesSha256"],
                            compatibility["projectedPlanSha256"])
        self.assertEqual(compatibility["soleAbstractPrerequisite"],
                         "terminal-mutation-process-group")

    def test_pristine_payload_rejects_wrong_independent_full_payload_digest(self) -> None:
        data, _expected = golden("create")
        expected_fields = dict(
            load_fixture(GOLDEN_PATH)["create"]["expectedBindings"]
        )
        expected_fields["payload_sha256"] = "sha256:" + "0" * 64
        mismatched = contract.PreparedBeadsStoreExpectedBindingsV1(
            **expected_fields
        )
        with self.assertRaises(ValueError):
            contract.validate_prepared_beads_store_payload_v1(data, mismatched)

    def test_exact_twelve_unchanged_expected_exploit_probes(self) -> None:
        data, expected = golden("create")
        payload = json.loads(data)
        probes = (
            ("mutated-root-inode", ("beadsRootStat", "inode"), 77),
            ("mutated-immutable-hash", ("immutableFiles", 0, "sha256"), "sha256:" + "f" * 64),
            ("mutated-executable-hash", ("executable", "sha256"), "sha256:" + "e" * 64),
            ("mutated-project-id", ("metadata", "projectId"), "different-project"),
            ("group-writable-root", ("databaseRootStat", "mode"), "0770"),
            ("group-writable-file", ("immutableFiles", 1, "stat", "mode"), "0660"),
            ("wrong-executable-mode", ("executable", "mode"), "0700"),
            ("zero-root-links", ("embeddedDataRootStat", "linkCount"), 0),
            ("hardlinked-file", ("immutableFiles", 0, "stat", "linkCount"), 2),
            ("hardlinked-executable", ("executable", "linkCount"), 2),
            ("relative-newline", ("immutableFiles", 0, "path"), "bad\nname"),
            ("relative-c1-control", ("immutableFiles", 0, "path"), "bad\u0085name"),
        )
        self.assertEqual(len(probes), 12)
        for label, path, replacement in probes:
            mutated = copy.deepcopy(payload)
            replace_path(mutated, path, replacement)
            with self.subTest(label=label), self.assertRaises(ValueError):
                contract.validate_prepared_beads_store_payload_v1(canonical(mutated), expected)

    def test_exhaustive_all_37_fields_and_every_nested_leaf_keep_expected_unchanged(self) -> None:
        data, expected = golden("create")
        payload = json.loads(data)
        self.assertEqual(len(payload), 37)
        for field, value in payload.items():
            mutated = copy.deepcopy(payload)
            mutated[field] = {} if isinstance(value, dict) else ([] if isinstance(value, list) else alternate(value))
            with self.subTest(top_level=field), self.assertRaises(ValueError):
                contract.validate_prepared_beads_store_payload_v1(canonical(mutated), expected)
        paths = list(leaf_paths(payload))
        self.assertEqual(len(paths), 163)
        self.assertEqual(len(payload) + len(paths), 200)
        for path, value in paths:
            mutated = copy.deepcopy(payload)
            replace_path(mutated, path, alternate(value))
            with self.subTest(path=path), self.assertRaises(ValueError):
                contract.validate_prepared_beads_store_payload_v1(canonical(mutated), expected)

    def test_dac_link_and_uid_relationships_fail_in_builder(self) -> None:
        cases = (
            ("root-mode", ("beadsRootStat", "mode"), "0777"),
            ("file-mode", ("immutableFiles", 0, "stat", "mode"), "0666"),
            ("executable-mode", ("executable", "mode"), "0510"),
            ("file-link", ("immutableFiles", 0, "stat", "linkCount"), 2),
            ("executable-link", ("executable", "linkCount"), 2),
            ("root-owner", ("databaseRootStat", "uid"), 502),
            ("file-owner", ("immutableFiles", 0, "stat", "uid"), 502),
            ("executable-owner", ("executable", "uid"), 502),
        )
        for label, path, replacement in cases:
            payload = json.loads(golden("create")[0])
            replace_path(payload, path, replacement)
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    contract.build_prepared_beads_store_payload_v1(
                        inputs_from_payload(payload)
                    )


if __name__ == "__main__":
    unittest.main()
