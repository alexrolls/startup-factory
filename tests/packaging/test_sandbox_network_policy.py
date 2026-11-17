"""Data-only replay of real v0.54 policy snapshots; no daemon or guest code."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli import sandbox_network_policy as policy  # noqa: E402
from startup_factory_cli.execution_backend import DockerProfile  # noqa: E402

FIXTURES = ROOT / "tests/fixtures/sandbox"
NAME = "sfq-policy-20261117-27f520c1"


def descriptor():
    return {"schemaVersion": 1, "namespace": "sf-unit", "preset": "deny-all", "provider": "openai",
            "rules": [{"host": "api.openai.com:443", "method": "POST", "path": "/v1/responses"}]}


def snapshot(stage):
    return json.loads((FIXTURES / ("sbx-v0.54.0-policy-" + stage + ".json")).read_bytes())


class NetworkPolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = policy.ModelNetworkPolicy.from_dict(descriptor())

    def test_real_observed_stages_are_accepted_without_claiming_containment(self):
        for stage in ("global", "locked", "staged", "active"):
            with self.subTest(stage=stage):
                result = policy.verify_effective_policy(self.policy, snapshot(stage),
                    sandbox_name=None if stage == "global" else NAME, stage=stage)
                self.assertEqual(result["stage"], stage)
                self.assertEqual(result["lockRuleId"] is not None, stage in {"locked", "staged"})
                self.assertNotIn("qualified", result)
                data = snapshot(stage);data["rules"].reverse()
                self.assertEqual(result, policy.verify_effective_policy(self.policy, data,
                    sandbox_name=None if stage == "global" else NAME, stage=stage))

    def test_stage_and_exact_scope_cannot_be_inferred_from_other_snapshot(self):
        for source in ("global", "locked", "staged", "active"):
            for expected in ("global", "locked", "staged", "active"):
                if source == expected:
                    continue
                with self.subTest(source=source, expected=expected), self.assertRaises(policy.NetworkPolicyError):
                    policy.verify_effective_policy(self.policy, snapshot(source),
                        sandbox_name=None if expected == "global" else NAME, stage=expected)
        with self.assertRaises(policy.NetworkPolicyError):
            policy.verify_effective_policy(self.policy, snapshot("active"), sandbox_name="sf-other", stage="active")

    def test_extra_rules_duplicate_or_changed_defaults_fail_closed(self):
        for change in ("extra-allow", "duplicate", "missing-deny", "default-write", "boolean-as-integer", "kit", "unknown-field", "method", "path", "wildcard"):
            data = snapshot("active")
            http = next(row for row in data["rules"] if row["resource_type"] == "http")
            if change == "extra-allow":
                extra = copy.deepcopy(http);extra["id"] = extra["name"] = "11111111-1111-4111-8111-111111111111";data["rules"].append(extra)
            elif change == "duplicate":data["rules"].append(copy.deepcopy(data["rules"][0]))
            elif change == "missing-deny":data["rules"] = [row for row in data["rules"] if row["id"] != "default-deny-all"]
            elif change == "default-write":data["rules"][0]["editable"] = True
            elif change == "boolean-as-integer":data["rules"][0]["editable"] = 0
            elif change == "kit":http["origin"] = "kit"
            elif change == "unknown-field":http["future"] = "allow"
            elif change == "method":http["methods"] = ["ANY"]
            elif change == "path":http["http_targets"][0]["path"] = "/v1/organization/admin_api_keys"
            else:http["resources"] = ["**"]
            with self.subTest(change=change), self.assertRaises(policy.NetworkPolicyError):
                policy.verify_effective_policy(self.policy, data, sandbox_name=NAME, stage="active")

    def test_closed_intent_no_arbitrary_provider_host_path_or_options(self):
        for key, value in (("preset", "balanced"), ("provider", "github"), ("namespace", "sf-qualification"), ("env", {})):
            data = descriptor();data[key] = value
            with self.subTest(key=key), self.assertRaises(policy.NetworkPolicyError):
                policy.ModelNetworkPolicy.from_dict(data)
        for key, value in (("host", "*.openai.com"), ("path", "/v1/responses?x=1"), ("method", "ANY"), ("secret", "x")):
            data = descriptor();data["rules"][0][key] = value
            with self.subTest(key=key), self.assertRaises(policy.NetworkPolicyError):
                policy.ModelNetworkPolicy.from_dict(data)
        data = descriptor();data["rules"] *= 2
        with self.assertRaises(policy.NetworkPolicyError):policy.ModelNetworkPolicy.from_dict(data)

    def test_raw_digest_binding_and_constructor_cannot_forge_different_rules(self):
        raw = json.dumps(descriptor(), indent=2).encode() + b"\n"
        parsed = policy.parse_network_policy(raw)
        self.assertEqual(parsed.digest, "sha256:" + hashlib.sha256(raw).hexdigest())
        self.assertNotEqual(parsed.digest, self.policy.digest)
        with self.assertRaises(policy.NetworkPolicyError):
            dataclasses.replace(parsed, rules=(policy.HttpRule("GET", "/v1/models"),))
        with self.assertRaises(policy.NetworkPolicyError):
            dataclasses.replace(parsed, source_bytes=raw.replace(b'"schemaVersion": 1', b'"schemaVersion": true'))
        for raw in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"x":NaN}', b'{"x":1e999}', b'[' * 10 + b']' * 10):
            with self.assertRaises(policy.NetworkPolicyError):policy.parse_network_policy(raw)

    def test_protected_loader_requires_raw_pin_and_profile_namespace(self):
        selected = DockerProfile.from_dict({"schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
            "controllerUid": 501, "sbxPath": "/opt/factory/sbx", "sbxSha256": "1" * 64,
            "namespace": "sf-unit", "image": "docker.io/sbx/shell@sha256:" + "2" * 64,
            "guestWorkdir": "/workspace/project", "policyDigest": self.policy.digest, "qualificationDigest": "sha256:" + "b" * 64,
            "limits": {"cpus": 1, "memoryMiB": 512, "rootDiskMiB": 2048, "dockerDiskMiB": 512, "wallSeconds": 30, "maxOutputBytes": 65536}})
        with mock.patch.object(policy, "read_root_protected", return_value=(self.policy.source_bytes, self.policy.digest)) as reader:
            self.assertEqual(policy.load_network_policy(Path("/protected/policy.json"), selected), self.policy)
            reader.assert_called_once()
            with self.assertRaises(policy.NetworkPolicyError):
                policy.load_network_policy(Path("/protected/policy.json"), dataclasses.replace(selected, policy_digest="sha256:" + "f" * 64))


if __name__ == "__main__":
    unittest.main()
