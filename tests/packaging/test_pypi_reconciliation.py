#!/usr/bin/env python3
"""Fail-closed PyPI publication reconciliation tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import urllib.request
import urllib.response
from email.message import Message
from pathlib import Path
from typing import Callable
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "packaging" / "reconcile_pypi_release.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SPEC = importlib.util.spec_from_file_location("reconcile_pypi_release", HELPER)
assert SPEC is not None and SPEC.loader is not None
reconcile = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reconcile
SPEC.loader.exec_module(reconcile)


VERSION = "0.2.0"


class Routes:
    def __init__(self, values: dict[str, object | None]) -> None:
        self.values = values
        self.calls: list[tuple[str, str, int, float]] = []

    def __call__(
        self, url: str, *, accept: str, limit: int, timeout: float
    ) -> object | None:
        self.calls.append((url, accept, limit, timeout))
        if url not in self.values:
            raise AssertionError(f"unexpected URL: {url}")
        return copy.deepcopy(self.values[url])


def provenance(name: str, digest: str) -> dict[str, object]:
    statement = {
        "_type": reconcile.STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": digest}}],
        "predicateType": reconcile.PUBLISH_PREDICATE,
        "predicate": None,
    }
    encoded = base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).decode("ascii")
    return {
        "version": 1,
        "attestation_bundles": [
            {
                "publisher": {
                    "kind": "GitHub",
                    "repository": reconcile.PUBLISHER_REPOSITORY,
                    "workflow": reconcile.PUBLISHER_WORKFLOW,
                    "environment": reconcile.PUBLISHER_ENVIRONMENT,
                },
                "attestations": [
                    {
                        "version": 1,
                        "envelope": {
                            "signature": base64.b64encode(b"signed").decode("ascii"),
                            "statement": encoded,
                        },
                        "verification_material": {
                            "certificate": base64.b64encode(b"certificate").decode("ascii"),
                            "transparency_entries": [{"logIndex": "1"}],
                        },
                    }
                ],
            }
        ],
    }


class ReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".pypi-reconcile-test-", dir=ROOT
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.dist = self.root / "dist"
        self.dist.mkdir(mode=0o700)
        self.wheel = f"startup_factory-{VERSION}-py3-none-any.whl"
        self.sdist = f"startup_factory-{VERSION}.tar.gz"
        (self.dist / self.wheel).write_bytes(b"exact wheel\n")
        (self.dist / self.sdist).write_bytes(b"exact sdist\n")
        self.digests = {
            name: hashlib.sha256((self.dist / name).read_bytes()).hexdigest()
            for name in (self.wheel, self.sdist)
        }
        self.release_url = f"{reconcile.PYPI_ORIGIN}/pypi/{reconcile.PROJECT}/{VERSION}/json"

    def release(self, *names: str) -> dict[str, object]:
        return {
            "info": {"name": "startup-factory", "version": VERSION},
            "urls": [
                {
                    "filename": name,
                    "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
                    "yanked": False,
                    "digests": {"sha256": self.digests.get(name, "0" * 64)},
                }
                for name in names
            ],
        }

    def provenance_url(self, name: str) -> str:
        return (
            f"{reconcile.PYPI_ORIGIN}/integrity/{reconcile.PROJECT}/{VERSION}/"
            f"{name}/provenance"
        )

    def route_values(self, *published: str) -> dict[str, object | None]:
        values: dict[str, object | None] = {
            self.release_url: self.release(*published),
        }
        for name in published:
            values[self.provenance_url(name)] = provenance(name, self.digests[name])
        return values

    def test_absent_release_prepares_both_exact_artifacts_privately(self) -> None:
        upload = self.root / "upload"
        result = reconcile.reconcile_release(
            version=VERSION,
            distributions=self.dist,
            fetch_json=Routes({self.release_url: None}),
            prepare_upload=upload,
        )
        self.assertEqual(result["state"], "absent")
        self.assertEqual(result["publishedArtifacts"], [])
        self.assertEqual(result["uploadArtifacts"], sorted([self.wheel, self.sdist]))
        self.assertEqual({path.name for path in upload.iterdir()}, {self.wheel, self.sdist})
        self.assertEqual(stat.S_IMODE(upload.stat().st_mode), 0o700)
        for name in (self.wheel, self.sdist):
            self.assertEqual((upload / name).read_bytes(), (self.dist / name).read_bytes())
            self.assertEqual(stat.S_IMODE((upload / name).stat().st_mode), 0o600)

    def test_partial_exact_release_prepares_only_the_missing_artifact(self) -> None:
        upload = self.root / "upload"
        result = reconcile.reconcile_release(
            version=VERSION,
            distributions=self.dist,
            fetch_json=Routes(self.route_values(self.wheel)),
            prepare_upload=upload,
        )
        self.assertEqual(result["state"], "partial-exact")
        self.assertEqual(result["publishedArtifacts"], [self.wheel])
        self.assertEqual(result["missingArtifacts"], [self.sdist])
        self.assertEqual(result["uploadArtifacts"], [self.sdist])
        self.assertEqual([path.name for path in upload.iterdir()], [self.sdist])

    def test_complete_exact_release_skips_upload_materialization(self) -> None:
        upload = self.root / "upload"
        result = reconcile.reconcile_release(
            version=VERSION,
            distributions=self.dist,
            fetch_json=Routes(self.route_values(self.wheel, self.sdist)),
            prepare_upload=upload,
        )
        self.assertEqual(result["state"], "complete-exact")
        self.assertEqual(result["missingArtifacts"], [])
        self.assertEqual(result["uploadArtifacts"], [])
        self.assertIsNone(result["uploadDirectory"])
        self.assertFalse(upload.exists())

    def test_current_and_nullable_publisher_schemas_are_accepted(self) -> None:
        for label, include_nullable_claims in (
            ("current PyPI schema", False),
            ("nullable claims compatibility", True),
        ):
            with self.subTest(label=label):
                values = self.route_values(self.wheel, self.sdist)
                for name in (self.wheel, self.sdist):
                    publisher = values[self.provenance_url(name)][
                        "attestation_bundles"
                    ][0]["publisher"]
                    if include_nullable_claims:
                        publisher["claims"] = None
                    self.assertEqual(
                        set(publisher),
                        {"kind", "repository", "workflow", "environment"}
                        | ({"claims"} if include_nullable_claims else set()),
                    )
                result = reconcile.reconcile_release(
                    version=VERSION,
                    distributions=self.dist,
                    fetch_json=Routes(values),
                )
                self.assertEqual(result["state"], "complete-exact")

    def test_remote_conflicts_never_prepare_an_upload(self) -> None:
        cases: list[tuple[str, Callable[[dict[str, object | None]], None], str]] = [
            (
                "digest mismatch",
                lambda values: values[self.release_url]["urls"][0]["digests"].__setitem__(
                    "sha256", "f" * 64
                ),
                "digest-mismatch",
            ),
            (
                "yanked file",
                lambda values: values[self.release_url]["urls"][0].__setitem__("yanked", True),
                "yanked-file",
            ),
            (
                "unexpected file",
                lambda values: values[self.release_url]["urls"][0].__setitem__(
                    "filename", "other-0.2.0.tar.gz"
                ),
                "unexpected-file",
            ),
            (
                "missing provenance",
                lambda values: values.__setitem__(self.provenance_url(self.wheel), None),
                "missing-provenance",
            ),
            (
                "foreign publisher",
                lambda values: values[self.provenance_url(self.wheel)][
                    "attestation_bundles"
                ][0]["publisher"].__setitem__("repository", "attacker/project"),
                "foreign-provenance",
            ),
            (
                "unexpected publisher claims",
                lambda values: values[self.provenance_url(self.wheel)][
                    "attestation_bundles"
                ][0]["publisher"].__setitem__("claims", {"untrusted": True}),
                "foreign-provenance",
            ),
            (
                "unknown publisher field",
                lambda values: values[self.provenance_url(self.wheel)][
                    "attestation_bundles"
                ][0]["publisher"].__setitem__("unrecognized", True),
                "foreign-provenance",
            ),
            (
                "missing publisher field",
                lambda values: values[self.provenance_url(self.wheel)][
                    "attestation_bundles"
                ][0]["publisher"].pop("workflow"),
                "foreign-provenance",
            ),
            (
                "multiple bundles",
                lambda values: values[self.provenance_url(self.wheel)][
                    "attestation_bundles"
                ].append(
                    copy.deepcopy(
                        values[self.provenance_url(self.wheel)]["attestation_bundles"][0]
                    )
                ),
                "invalid-provenance",
            ),
            (
                "missing certificate",
                lambda values: values[self.provenance_url(self.wheel)][
                    "attestation_bundles"
                ][0]["attestations"][0].__setitem__("verification_material", {}),
                "invalid-provenance",
            ),
            (
                "missing transparency entry",
                lambda values: values[self.provenance_url(self.wheel)][
                    "attestation_bundles"
                ][0]["attestations"][0]["verification_material"].__setitem__(
                    "transparency_entries", []
                ),
                "invalid-provenance",
            ),
            (
                "malformed signature",
                lambda values: values[self.provenance_url(self.wheel)][
                    "attestation_bundles"
                ][0]["attestations"][0]["envelope"].__setitem__("signature", "not base64!"),
                "invalid-provenance",
            ),
            (
                "unknown provenance field",
                lambda values: values[self.provenance_url(self.wheel)].__setitem__(
                    "unrecognized", True
                ),
                "invalid-provenance",
            ),
        ]
        for label, mutate, expected_code in cases:
            with self.subTest(label=label):
                values = self.route_values(self.wheel)
                mutate(values)
                upload = self.root / ("upload-" + expected_code)
                result = reconcile.reconcile_release(
                    version=VERSION,
                    distributions=self.dist,
                    fetch_json=Routes(values),
                    prepare_upload=upload,
                )
                self.assertEqual(result["state"], "conflict")
                self.assertFalse(result["ok"])
                self.assertEqual(result["reasonCode"], expected_code)
                self.assertFalse(upload.exists())

    def test_publish_statement_must_bind_the_exact_name_and_digest(self) -> None:
        for field in ("name", "digest"):
            with self.subTest(field=field):
                values = self.route_values(self.wheel)
                item = values[self.provenance_url(self.wheel)]
                statement = json.loads(
                    base64.b64decode(
                        item["attestation_bundles"][0]["attestations"][0]["envelope"][
                            "statement"
                        ]
                    )
                )
                if field == "name":
                    statement["subject"][0]["name"] = self.sdist
                    expected = "provenance-subject-mismatch"
                else:
                    statement["subject"][0]["digest"]["sha256"] = "e" * 64
                    expected = "provenance-digest-mismatch"
                item["attestation_bundles"][0]["attestations"][0]["envelope"][
                    "statement"
                ] = base64.b64encode(
                    json.dumps(statement, separators=(",", ":")).encode("ascii")
                ).decode("ascii")
                result = reconcile.reconcile_release(
                    version=VERSION,
                    distributions=self.dist,
                    fetch_json=Routes(values),
                )
                self.assertEqual(result["state"], "conflict")
                self.assertEqual(result["reasonCode"], expected)

    def test_local_inventory_is_exact_and_upload_directory_cannot_be_reused(self) -> None:
        (self.dist / "unexpected.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(reconcile.ReconciliationError, "wrong exact inventory"):
            reconcile.reconcile_release(
                version=VERSION,
                distributions=self.dist,
                fetch_json=Routes({self.release_url: None}),
            )
        (self.dist / "unexpected.txt").unlink()
        upload = self.root / "upload"
        upload.mkdir()
        with self.assertRaisesRegex(reconcile.ReconciliationError, "already exists"):
            reconcile.reconcile_release(
                version=VERSION,
                distributions=self.dist,
                fetch_json=Routes({self.release_url: None}),
                prepare_upload=upload,
            )

    def test_untrusted_json_rejects_duplicate_keys_and_excessive_shape(self) -> None:
        with self.assertRaisesRegex(reconcile.ReconciliationError, "canonical JSON"):
            reconcile._decode_json(b'{"x":1,"x":2}', label="fixture")
        value: object = None
        for _ in range(reconcile.MAX_JSON_DEPTH + 2):
            value = [value]
        with self.assertRaisesRegex(reconcile.ReconciliationError, "canonical JSON"):
            reconcile._decode_json(json.dumps(value).encode(), label="fixture")


class FakeResponse:
    def __init__(self, payload: bytes, *, content_length: str | None = None) -> None:
        self.payload = payload
        self.status = 200
        self.headers = {} if content_length is None else {"Content-Length": content_length}

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return "https://pypi.org/pypi/startup-factory/0.2.0/json"

    def read(self, count: int) -> bytes:
        return self.payload[:count]


class HttpBoundaryTests(unittest.TestCase):
    class ScriptedHttpsHandler(urllib.request.HTTPSHandler):
        def __init__(self, responses: dict[str, tuple[int, str | None, bytes]]) -> None:
            super().__init__()
            self.responses = responses
            self.visited: list[str] = []

        def https_open(self, request: urllib.request.Request) -> object:
            url = request.full_url
            self.visited.append(url)
            code, location, payload = self.responses[url]
            headers = Message()
            if location is not None:
                headers["Location"] = location
            response = urllib.response.addinfourl(
                io.BytesIO(payload), headers, url, code=code
            )
            response.msg = "scripted response"
            return response

    def scripted_opener(
        self, responses: dict[str, tuple[int, str | None, bytes]]
    ) -> tuple[object, "HttpBoundaryTests.ScriptedHttpsHandler"]:
        handler = self.ScriptedHttpsHandler(responses)
        opener = urllib.request.build_opener(handler, reconcile._RejectRedirects())
        return opener, handler

    def test_http_response_has_a_hard_byte_limit(self) -> None:
        response = FakeResponse(b"{}", content_length=str(MAX := 513 * 1024))
        self.assertGreater(MAX, reconcile.MAX_RELEASE_JSON_BYTES)
        with mock.patch.object(reconcile.PYPI_OPENER, "open", return_value=response):
            with self.assertRaisesRegex(reconcile.ReconciliationError, "size limit"):
                reconcile._fetch_json(
                    "https://pypi.org/pypi/startup-factory/0.2.0/json",
                    accept="application/json",
                    limit=reconcile.MAX_RELEASE_JSON_BYTES,
                )

    def test_direct_fixed_endpoint_404_is_the_only_not_found_result(self) -> None:
        url = "https://pypi.org/pypi/startup-factory/0.2.0/json"
        opener, handler = self.scripted_opener({url: (404, None, b"")})
        with mock.patch.object(reconcile, "PYPI_OPENER", opener):
            self.assertIsNone(
                reconcile._fetch_json(
                    url,
                    accept="application/json",
                    limit=reconcile.MAX_RELEASE_JSON_BYTES,
                )
            )
        self.assertEqual(handler.visited, [url])

    def test_direct_3xx_is_rejected_without_following_it(self) -> None:
        url = "https://pypi.org/pypi/startup-factory/0.2.0/json"
        target = "https://pypi.org/pypi/startup-factory/json"
        opener, handler = self.scripted_opener(
            {url: (302, target, b""), target: (200, None, b"{}")}
        )
        with mock.patch.object(reconcile, "PYPI_OPENER", opener):
            with self.assertRaisesRegex(reconcile.ReconciliationError, "fixed endpoint"):
                reconcile._fetch_json(
                    url,
                    accept="application/json",
                    limit=reconcile.MAX_RELEASE_JSON_BYTES,
                )
        self.assertEqual(handler.visited, [url])

    def test_redirect_to_404_cannot_be_misclassified_as_absent(self) -> None:
        url = "https://pypi.org/pypi/startup-factory/0.2.0/json"
        missing = "https://pypi.org/pypi/startup-factory/missing/json"
        opener, handler = self.scripted_opener(
            {url: (302, missing, b""), missing: (404, None, b"")}
        )
        with mock.patch.object(reconcile, "PYPI_OPENER", opener):
            with self.assertRaisesRegex(reconcile.ReconciliationError, "fixed endpoint"):
                reconcile._fetch_json(
                    url,
                    accept="application/json",
                    limit=reconcile.MAX_RELEASE_JSON_BYTES,
                )
        self.assertEqual(handler.visited, [url])

    def test_away_and_back_redirect_chain_stops_before_the_first_hop(self) -> None:
        url = "https://pypi.org/pypi/startup-factory/0.2.0/json"
        away = "https://example.invalid/hop"
        opener, handler = self.scripted_opener(
            {url: (302, away, b""), away: (302, url, b"")}
        )
        with mock.patch.object(reconcile, "PYPI_OPENER", opener):
            with self.assertRaisesRegex(reconcile.ReconciliationError, "fixed endpoint"):
                reconcile._fetch_json(
                    url,
                    accept="application/json",
                    limit=reconcile.MAX_RELEASE_JSON_BYTES,
                )
        self.assertEqual(handler.visited, [url])


class WorkflowRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".pypi-workflow-recovery-test-", dir=ROOT
        )
        self.addCleanup(self.temporary.cleanup)
        self.dist = Path(self.temporary.name) / "dist"
        self.dist.mkdir()
        self.wheel = f"startup_factory-{VERSION}-py3-none-any.whl"
        self.sdist = f"startup_factory-{VERSION}.tar.gz"
        (self.dist / self.wheel).write_bytes(b"exact wheel\n")
        (self.dist / self.sdist).write_bytes(b"exact sdist\n")
        self.digests = {
            name: hashlib.sha256((self.dist / name).read_bytes()).hexdigest()
            for name in (self.wheel, self.sdist)
        }

    def release(self) -> dict[str, object]:
        return {
            "info": {"name": "startup-factory", "version": VERSION},
            "urls": [
                {
                    "filename": name,
                    "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
                    "yanked": False,
                    "digests": {"sha256": self.digests[name]},
                }
                for name in (self.wheel, self.sdist)
            ],
        }

    def route_values(self, *, missing_provenance: bool) -> dict[str, object | None]:
        release_url = f"{reconcile.PYPI_ORIGIN}/pypi/{reconcile.PROJECT}/{VERSION}/json"
        values: dict[str, object | None] = {release_url: self.release()}
        for index, name in enumerate((self.wheel, self.sdist)):
            url = (
                f"{reconcile.PYPI_ORIGIN}/integrity/{reconcile.PROJECT}/{VERSION}/"
                f"{name}/provenance"
            )
            values[url] = None if missing_provenance and index == 0 else provenance(
                name, self.digests[name]
            )
        return values

    def test_post_action_missing_provenance_is_retryable_then_complete(self) -> None:
        missing = reconcile.reconcile_release(
            version=VERSION,
            distributions=self.dist,
            fetch_json=Routes(self.route_values(missing_provenance=True)),
        )
        complete = reconcile.reconcile_release(
            version=VERSION,
            distributions=self.dist,
            fetch_json=Routes(self.route_values(missing_provenance=False)),
        )
        self.assertEqual(missing["reasonCode"], "missing-provenance")
        self.assertEqual(complete["state"], "complete-exact")
        arguments = [
            "--version",
            VERSION,
            "--distributions",
            str(self.dist),
            "--require-complete",
            "--retry-transient",
            "--json",
        ]
        output = io.StringIO()
        with mock.patch.object(
            reconcile, "reconcile_release", side_effect=[missing, complete]
        ), mock.patch("sys.stdout", output):
            self.assertEqual(reconcile.main(arguments), 1)
            self.assertEqual(reconcile.main(arguments), 0)
        reports = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([report["state"] for report in reports], ["conflict", "complete-exact"])

    def test_preflight_and_deterministic_postflight_conflicts_remain_strict(self) -> None:
        missing = reconcile.reconcile_release(
            version=VERSION,
            distributions=self.dist,
            fetch_json=Routes(self.route_values(missing_provenance=True)),
        )
        conflict = copy.deepcopy(missing)
        conflict["reasonCode"] = "digest-mismatch"
        arguments = [
            "--version",
            VERSION,
            "--distributions",
            str(self.dist),
            "--require-complete",
            "--json",
        ]
        with mock.patch.object(reconcile, "reconcile_release", return_value=missing), mock.patch(
            "sys.stdout", io.StringIO()
        ):
            self.assertEqual(reconcile.main(arguments), 2)
        arguments.insert(-1, "--retry-transient")
        with mock.patch.object(reconcile, "reconcile_release", return_value=conflict), mock.patch(
            "sys.stdout", io.StringIO()
        ):
            self.assertEqual(reconcile.main(arguments), 2)

    def test_workflow_reconciles_before_and_after_the_single_publish_action(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        publish = workflow.split("  publish:\n", 1)[1].split("\n  verify-uvx:\n", 1)[0]
        preflight = publish.index("Reconcile exact existing PyPI publication")
        action = publish.index("pypa/gh-action-pypi-publish")
        postflight = publish.index("Require a complete exact PyPI publication")
        self.assertLess(preflight, action)
        self.assertLess(action, postflight)
        self.assertIn("packaging/reconcile_pypi_release.py", publish)
        self.assertIn("--prepare-upload", publish)
        self.assertIn("--require-complete", publish)
        self.assertIn("--retry-transient", publish[postflight:])
        self.assertNotIn("--retry-transient", publish[:action])
        self.assertIn("if: steps.pypi-reconcile.outputs.publish_needed == 'true'", publish)
        self.assertIn('upload_dir="$GITHUB_WORKSPACE/.pypi-upload"', publish)
        self.assertIn("packages-dir: .pypi-upload/", publish)
        self.assertNotIn("skip-existing:", publish)


if __name__ == "__main__":
    unittest.main()
