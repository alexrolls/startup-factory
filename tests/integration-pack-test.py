#!/usr/bin/env python3
"""Focused security and lifecycle tests for data-only integration packs."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Iterator, Mapping
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import startup_factory_cli.integration_packs as integration_packs  # noqa: E402
import startup_factory_cli.project_config as project_config  # noqa: E402
from startup_factory_cli.integration_packs import (  # noqa: E402
    MAX_DISCOVERED_PACKS,
    MAX_DISCOVERY_DEPTH,
    MAX_PACK_BYTES,
    IntegrationPackError,
    PackPlan,
    RUNTIME_VERSION,
    apply_pack_plan,
    decode_plan,
    doctor_pack,
    list_packs,
    load_plan,
    preview_pack,
    validate_pack,
)
from startup_factory_cli.secret_safety import (  # noqa: E402
    contains_secret_like,
    redact_secret_like,
)


def _synthetic_provider_value(*parts: str) -> str:
    """Build scanner fixtures at runtime without embedding provider tokens in Git."""

    return "".join(parts)


def _declared_runtime_version(root: Path) -> str:
    """Read source or installed-bundle version metadata on Python 3.10+."""

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8")
        project = re.search(r"(?ms)^\[project\]\s*$([\s\S]*?)(?=^\[|\Z)", text)
        if project is None:
            raise AssertionError("pyproject.toml has no [project] table")
        versions = re.findall(
            r'(?m)^version\s*=\s*"(\d+\.\d+\.\d+)"\s*(?:#.*)?$',
            project.group(1),
        )
        if len(versions) != 1:
            raise AssertionError("pyproject.toml must contain one static numeric version")
        return versions[0]
    manifest = root / ".startup-factory-bundle.json"
    if manifest.is_file():
        value = json.loads(manifest.read_text(encoding="utf-8"))
        version = value.get("version") if isinstance(value, dict) else None
        if not isinstance(version, str) or re.fullmatch(r"\d+\.\d+\.\d+", version) is None:
            raise AssertionError("bundle manifest has no numeric version")
        return version
    raise AssertionError("runtime has neither source nor installed-bundle version metadata")


REFERENCE_ROOT = ROOT / "extensions" / "integration-packs"
SCRIPT = ROOT / "bin" / "integration_pack.py"


class PresenceOnlyEnvironment(Mapping[str, str]):
    """Mapping that proves doctor never reads credential values."""

    def __init__(self, names: set[str]) -> None:
        self.names = names

    def __contains__(self, key: object) -> bool:
        return key in self.names

    def __getitem__(self, key: str) -> str:
        raise AssertionError("doctor must not read a credential value")

    def __iter__(self) -> Iterator[str]:
        return iter(self.names)

    def __len__(self) -> int:
        return len(self.names)


class IntegrationPackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="integration-pack-test-")
        # macOS exposes /var through /private/var. Resolve it so the security
        # checks receive an unambiguous, symlink-free root spelling.
        self.scratch = Path(self.temporary.name).resolve()
        self.project = self.scratch / "project"
        self.project.mkdir()
        self.runtime = self.scratch / "installed-runtime"
        (self.runtime / "config").mkdir(parents=True)
        (self.runtime / "adapters").mkdir()
        (self.runtime / "config" / "project-management.config.md").write_text(
            "# keep this byte-for-byte\n"
            "PRODUCT_MANAGEMENT_TOOL=Markdown # editable\n"
            "TEAM_MODE=false\n"
            "UNCHANGED=preserved\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _reference(self, relative: str) -> Path:
        return REFERENCE_ROOT / relative

    def _document(self, relative: str = "tracker/markdown.json") -> dict[str, object]:
        return json.loads(self._reference(relative).read_text(encoding="utf-8"))

    def _write_pack(self, name: str, document: object) -> Path:
        directory = self.scratch / "packs"
        directory.mkdir(exist_ok=True)
        path = directory / name
        path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        return path

    def _assert_invalid(self, document: object, pattern: str) -> None:
        path = self._write_pack("invalid.json", document)
        with self.assertRaisesRegex(IntegrationPackError, pattern):
            validate_pack(path)

    def _preview(self, pack, project: Path | None = None, **kwargs):
        return preview_pack(
            pack,
            project or self.project,
            runtime_root=self.runtime,
            **kwargs,
        )

    def _apply(self, plan, project: Path | None = None):
        return apply_pack_plan(
            plan,
            project_root=project or self.project,
            runtime_root=self.runtime,
        )

    def _doctor(self, pack, project: Path | None = None, **kwargs):
        return doctor_pack(
            pack,
            project or self.project,
            runtime_root=self.runtime,
            **kwargs,
        )

    def test_reference_catalog_is_complete_deterministic_and_secret_free(self) -> None:
        schema = json.loads((REFERENCE_ROOT / "schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        packs = list_packs(REFERENCE_ROOT)
        self.assertEqual(
            [(pack.kind, pack.pack_id) for pack in packs],
            [
                ("ci", "github-actions-exact-commit"),
                ("deployment", "deployment-docker-compose"),
                ("deployment", "deployment-kubernetes"),
                ("tracker", "tracker-github-issues"),
                ("tracker", "tracker-jira"),
                ("tracker", "tracker-linear"),
                ("tracker", "tracker-markdown"),
            ],
        )
        for pack in packs:
            self.assertTrue(pack.source_digest.startswith("sha256:"))
            self.assertNotIn("windows", pack.compatibility["platforms"])
            raw = pack.source_path.read_text(encoding="utf-8").lower()
            self.assertNotIn("-----begin", raw)
            self.assertNotIn("password=", raw)
            self.assertNotIn("token=", raw)
            self.assertNotIn("secret=", raw)
        ci_pack = next(pack for pack in packs if pack.kind == "ci")
        self.assertEqual(
            ci_pack.capability["template"]["requiredChecks"],
            ["Runtime, package, and reproducible artifacts"],
        )
        self.assertEqual(
            schema["allOf"][4]["then"]["properties"]["capability"]
            ["properties"]["template"]["properties"]["requiredChecks"]["minItems"],
            1,
        )

    def test_relative_path_without_explicit_root_uses_its_parent_once(self) -> None:
        previous = Path.cwd()
        try:
            os.chdir(ROOT)
            pack = validate_pack(Path("extensions/integration-packs/tracker/markdown.json"))
        finally:
            os.chdir(previous)
        self.assertEqual(pack.pack_id, "tracker-markdown")
        self.assertEqual(pack.source_relative, "markdown.json")

    def test_strict_json_rejects_duplicates_non_finite_and_oversize(self) -> None:
        directory = self.scratch / "packs"
        directory.mkdir()
        duplicate = directory / "duplicate.json"
        duplicate.write_text(
            '{"schemaVersion":1,"schemaVersion":1,"id":"tracker-markdown"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(IntegrationPackError, "duplicate JSON key"):
            validate_pack(duplicate)

        non_finite = directory / "non-finite.json"
        non_finite.write_text('{"schemaVersion":NaN}', encoding="utf-8")
        with self.assertRaisesRegex(IntegrationPackError, "non-finite"):
            validate_pack(non_finite)

        oversize = directory / "oversize.json"
        oversize.write_bytes(b"{" + b" " * MAX_PACK_BYTES + b"}")
        with self.assertRaisesRegex(IntegrationPackError, "bounded|exceeds"):
            validate_pack(oversize)

    def test_escaped_unicode_surrogates_fail_validation_and_cli_cleanly(self) -> None:
        cases = []
        display_name = self._document()
        display_name["displayName"] = "invalid\ud800"
        cases.append(("display-name", display_name))

        check_name = self._document("ci/github-actions-exact-commit.json")
        check_name["capability"]["template"]["requiredChecks"] = [  # type: ignore[index]
            "Check\udfff"
        ]
        cases.append(("required-check", check_name))

        invalid_key = self._document()
        invalid_key["invalid\ud800"] = True
        cases.append(("key", invalid_key))

        for name, document in cases:
            with self.subTest(name=name):
                path = self._write_pack(f"surrogate-{name}.json", document)
                with self.assertRaisesRegex(IntegrationPackError, "invalid Unicode surrogate"):
                    validate_pack(path)
                command = "preview" if name == "required-check" else "validate"
                argv = [sys.executable, str(SCRIPT), command, str(path)]
                if command == "preview":
                    argv.extend(("--project-root", str(self.project)))
                completed = subprocess.run(
                    argv,
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertIn("invalid Unicode surrogate", completed.stderr)
                self.assertNotIn("Traceback", completed.stderr)

    def test_exact_schema_versions_states_and_capabilities_fail_closed(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []
        unknown = self._document()
        unknown["unexpected"] = True
        cases.append((unknown, "invalid keys"))
        version = self._document()
        version["schemaVersion"] = True
        cases.append((version, "schemaVersion"))
        state = self._document()
        state["compatibility"]["state"] = "maybe"  # type: ignore[index]
        cases.append((state, "compatibility state"))
        capability = self._document()
        capability["capability"]["adapter"] = "Anything"  # type: ignore[index]
        cases.append((capability, "tracker adapter"))
        wrong_kind = self._document()
        wrong_kind["kind"] = "plugin"
        cases.append((wrong_kind, "pack kind"))
        for index, (document, pattern) in enumerate(cases):
            with self.subTest(index=index):
                path = self._write_pack(f"invalid-{index}.json", document)
                with self.assertRaisesRegex(IntegrationPackError, pattern):
                    validate_pack(path)

    def test_ci_pack_requires_real_nonempty_check_names(self) -> None:
        empty = self._document("ci/github-actions-exact-commit.json")
        empty["capability"]["template"]["requiredChecks"] = []  # type: ignore[index]
        self._assert_invalid(empty, "at least one")

        whitespace = self._document("ci/github-actions-exact-commit.json")
        whitespace["capability"]["template"]["requiredChecks"] = [  # type: ignore[index]
            " build"
        ]
        self._assert_invalid(whitespace, "leading or trailing")

        realistic = self._document("ci/github-actions-exact-commit.json")
        realistic["capability"]["template"]["requiredChecks"] = [  # type: ignore[index]
            "Package CI / Runtime, package, and reproducible artifacts"
        ]
        pack = validate_pack(self._write_pack("realistic-check.json", realistic))
        self.assertEqual(
            pack.capability["template"]["requiredChecks"],
            ["Package CI / Runtime, package, and reproducible artifacts"],
        )

    def test_malicious_content_and_unsafe_names_are_rejected(self) -> None:
        shell_field = self._document()
        shell_field["capability"]["command"] = ["curl", "example.invalid"]  # type: ignore[index]
        self._assert_invalid(shell_field, "forbidden field")

        interpolation = self._document()
        interpolation["summary"] = "Load ${TOKEN} at runtime"
        self._assert_invalid(interpolation, "executable or interpolated")

        secret = self._document()
        secret["summary"] = "token=super-sensitive-value"
        self._assert_invalid(secret, "secret-like")

        unsafe_environment = self._document()
        unsafe_environment["credentials"] = {
            "policy": "required-environment",
            "required": ["BASH_ENV"],
        }
        self._assert_invalid(unsafe_environment, "unsafe")

        false_conditional = self._document()
        false_conditional["credentials"] = {
            "policy": "adapter-managed",
            "required": ["LINEAR_API_KEY"],
        }
        self._assert_invalid(false_conditional, "must not claim unconditional")

        false_none = self._document("tracker/markdown.json")
        false_none["credentials"] = {
            "policy": "none",
            "required": ["UNEXPECTED_TOKEN"],
        }
        self._assert_invalid(false_none, "must not claim unconditional")

        path_escape = self._document("ci/github-actions-exact-commit.json")
        path_escape["capability"]["outputFile"] = "../escape.json"  # type: ignore[index]
        self._assert_invalid(path_escape, "escape|relative path")

        deep = self._document()
        nested: dict[str, object] = {}
        cursor = nested
        for index in range(10):
            child: dict[str, object] = {}
            cursor[f"level{index}"] = child
            cursor = child
        deep["extra"] = nested
        self._assert_invalid(deep, "nesting is too deep")

        crowded = self._document()
        crowded["extra"] = {f"key{index}": index for index in range(129)}
        self._assert_invalid(crowded, "too many keys")

    def test_provider_tokens_are_rejected_from_ci_checks_without_echoing_them(self) -> None:
        provider_tokens = {
            "gitlab": _synthetic_provider_value("gl", "pat-", "0123456789abcdefghij"),
            "npm": _synthetic_provider_value("np", "m_", "0123456789abcdefghijklmnopqrstuvwxyz"),
            "stripe-live-secret": _synthetic_provider_value("sk_", "live_", "0123456789abcdefghijklmn"),
            "stripe-test-restricted": _synthetic_provider_value("rk_", "test_", "0123456789abcdefghijklmn"),
            "stripe-webhook": _synthetic_provider_value("wh", "sec_", "0123456789abcdefghijklmn"),
            "aws-temporary": _synthetic_provider_value("AS", "IA", "0123456789ABCDEF"),
            "aws-long-lived": _synthetic_provider_value("AK", "IA", "0123456789ABCDEF"),
            "github": _synthetic_provider_value("gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"),
            "openai-compatible": _synthetic_provider_value("sk", "-proj-", "abcdefghijklmnopqrstuvwxyz0123456789"),
            "slack": _synthetic_provider_value("xo", "xb-", "1234567890-abcdefghijkl"),
            "google": _synthetic_provider_value("AI", "za", "A" * 35),
            "pypi": _synthetic_provider_value("py", "pi-", "A" * 50),
            "sendgrid": _synthetic_provider_value("S", "G.", "A" * 16, ".", "b" * 16),
            "hugging-face": _synthetic_provider_value("h", "f_", "A" * 20),
            "shopify": _synthetic_provider_value("sh", "pat_", "a" * 32),
            "digitalocean": _synthetic_provider_value("dop", "_v1_", "a" * 64),
            "linear-api": _synthetic_provider_value("lin_", "api_", "a" * 40),
            "linear-oauth": _synthetic_provider_value("lin_", "oauth_", "b" * 40),
            "jwt": _synthetic_provider_value("ey", "Jabcdefgh", ".abcdefgh", ".abcdefgh"),
            "basic-auth": "https://operator:credential@example.invalid/api",
            "assignment": "client_secret=not-for-output",
            "access-key-assignment": "secret_access_key=not-for-output",
            "refresh-assignment": "refresh_token=not-for-output",
            "authorization-assignment": "authorization=opaque-value-not-for-output",
            "bearer-authorization": (
                "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
            ),
            "connection-assignment": "connection_string=not-for-output",
            "private-key": (
                "-----BEGIN PRIVATE KEY-----\nnot-for-output\n"
                "-----END PRIVATE KEY-----"
            ),
            "certificate": (
                "-----BEGIN CERTIFICATE-----\nnot-for-output\n"
                "-----END CERTIFICATE-----"
            ),
        }
        for provider, token in provider_tokens.items():
            with self.subTest(provider=provider):
                document = self._document("ci/github-actions-exact-commit.json")
                document["capability"]["template"]["requiredChecks"] = [token]  # type: ignore[index]
                path = self._write_pack(f"secret-{provider}.json", document)
                with self.assertRaisesRegex(
                    IntegrationPackError, "secret-like material"
                ) as raised:
                    validate_pack(path)
                self.assertNotIn(token, str(raised.exception))

    def test_provider_token_confusables_remain_valid_ci_check_names(self) -> None:
        check_names = (
            "Security / glpat-rotation-check",
            "Package / npm_publish_validation",
            "Payments / sk_live_contract",
            "Payments / whsec_rotation",
            "Cloud / ASIA-Pacific compatibility",
            "Google / AIza key format documentation",
            "Release / pypi-upload",
            "Email / SG.validation",
            "Models / hf_inference",
            "Shopify / shpat rotation",
            "Cloud / dop_v1_rotation",
            "Tracker / lin_api_ placeholder documentation",
            "Tracker / lin_oauth_ rotation documentation",
            "Auth / token-validation",
            "Auth / refresh-token-validation",
            "Cloud / access-key-rotation",
            "Database / connection-string-check",
            "AI / sk-live-check",
            "Authorization: required",
            "token: required",
            "connection_string: documented",
            "api_key: configured",
        )
        for index, check_name in enumerate(check_names):
            with self.subTest(check_name=check_name):
                document = self._document("ci/github-actions-exact-commit.json")
                document["capability"]["template"]["requiredChecks"] = [  # type: ignore[index]
                    check_name
                ]
                pack = validate_pack(
                    self._write_pack(f"confusable-{index}.json", document)
                )
                self.assertEqual(
                    pack.capability["template"]["requiredChecks"], [check_name]
                )

    def test_unterminated_and_oversize_pem_headers_fail_closed_and_redact(self) -> None:
        cases = (
            "prefix -----BEGIN PRIVATE KEY-----\nunterminated-body-canary",
            (
                "-----BEGIN CERTIFICATE-----\n"
                + "x" * 70_000
                + "\noversize-body-canary\n-----END CERTIFICATE-----"
            ),
        )
        for value in cases:
            with self.subTest(length=len(value)):
                self.assertTrue(contains_secret_like(value))
                redacted = redact_secret_like(value)
                self.assertNotIn("-----BEGIN", redacted)
                self.assertNotIn("body-canary", redacted)
                self.assertIn("[REDACTED SECRET]", redacted)

    def test_pack_symlinks_and_catalog_ambiguity_are_rejected(self) -> None:
        pack = self._write_pack("real.json", self._document())
        link = pack.with_name("link.json")
        link.symlink_to(pack)
        with self.assertRaisesRegex(IntegrationPackError, "symbolic"):
            validate_pack(link, root=link.parent)

        fifo = pack.with_name("pack.fifo")
        os.mkfifo(fifo)
        with self.assertRaisesRegex(IntegrationPackError, "regular file"):
            validate_pack(fifo, root=fifo.parent)

        project_packs = self.project / ".startup-factory" / "integration-packs"
        project_packs.mkdir(parents=True)
        (project_packs / "duplicate.json").write_text(
            self._reference("tracker/markdown.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(IntegrationPackError, "duplicate integration pack id"):
            list_packs(REFERENCE_ROOT, project_root=self.project)

    def test_catalog_discovery_and_project_binding_fail_closed(self) -> None:
        deep_root = self.scratch / "deep-catalog"
        deep_root.mkdir()
        nested = deep_root
        for index in range(MAX_DISCOVERY_DEPTH + 1):
            nested /= f"level-{index}"
            nested.mkdir()
        with self.assertRaisesRegex(IntegrationPackError, "nesting is too deep"):
            list_packs(deep_root)

        crowded_root = self.scratch / "crowded-catalog"
        crowded_root.mkdir()
        for index in range(MAX_DISCOVERED_PACKS + 1):
            (crowded_root / f"pack-{index}.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(IntegrationPackError, "too many packs"):
            list_packs(crowded_root)

        class CountingScan:
            def __init__(self) -> None:
                self.yielded = 0

            def __enter__(self):
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def __iter__(self):
                return self

            def __next__(self):
                self.yielded += 1
                if self.yielded > integration_packs.MAX_DISCOVERY_ENTRIES + 1:
                    raise AssertionError("discovery consumed beyond its entry cap")
                return object()

        scan = CountingScan()
        with mock.patch.object(integration_packs.os, "scandir", return_value=scan):
            with self.assertRaisesRegex(IntegrationPackError, "too many entries"):
                integration_packs._walk_json_files_at(-1)
        self.assertEqual(scan.yielded, integration_packs.MAX_DISCOVERY_ENTRIES + 1)

        pack = validate_pack(self._reference("tracker/linear.json"), root=REFERENCE_ROOT)
        plan = self._preview(pack)
        other = self.scratch / "other-project"
        (other / "config").mkdir(parents=True)
        (other / "config" / "project-management.config.md").write_text(
            "PRODUCT_MANAGEMENT_TOOL=Markdown\nTEAM_MODE=true\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(IntegrationPackError, "does not match"):
            self._apply(plan, other)

        project_link = self.scratch / "project-link"
        project_link.symlink_to(self.project, target_is_directory=True)
        with self.assertRaisesRegex(IntegrationPackError, "unsafe|non-symlink|ambiguous|symbolic"):
            self._preview(pack, project_link)

    def test_tracker_preview_and_apply_change_only_two_existing_assignments(self) -> None:
        before = (self.runtime / "config" / "project-management.config.md").read_bytes()
        pack = validate_pack(self._reference("tracker/jira.json"), root=REFERENCE_ROOT)
        plan = self._preview(pack)
        self.assertEqual(plan.target_relative, "config/project-management.config.md")
        self.assertEqual(
            [change["key"] for change in plan.changes],
            ["PRODUCT_MANAGEMENT_TOOL", "TEAM_MODE"],
        )
        receipt = self._apply(plan)
        self.assertTrue(receipt.applied)
        after = (self.runtime / "config" / "project-management.config.md").read_bytes()
        expected = before.replace(b"PRODUCT_MANAGEMENT_TOOL=Markdown", b"PRODUCT_MANAGEMENT_TOOL=Jira")
        expected = expected.replace(b"TEAM_MODE=false", b"TEAM_MODE=true")
        self.assertEqual(after, expected)
        retry = self._apply(plan)
        self.assertFalse(retry.applied)
        self.assertTrue(retry.idempotent)

    def test_tracker_idempotence_rejects_mode_and_bound_identity_changes(self) -> None:
        config = self.runtime / "config" / "project-management.config.md"
        pack = validate_pack(
            self._reference("tracker/markdown.json"), root=REFERENCE_ROOT
        )
        plan = self._preview(pack)
        self._apply(plan)
        config.chmod(0o666)
        with self.assertRaisesRegex(IntegrationPackError, "mode changed"):
            self._apply(plan)

        config.chmod(0o644)
        already_applied = self._preview(pack)
        self.assertEqual(
            already_applied.target_digest, already_applied.rendered_digest
        )
        raw = config.read_bytes()
        replacement = config.with_name("replacement-project-management.config.md")
        replacement.write_bytes(raw)
        replacement.chmod(0o644)
        os.replace(replacement, config)
        with self.assertRaisesRegex(IntegrationPackError, "identity changed"):
            self._apply(already_applied)

    def test_tampered_plan_and_concurrent_tracker_change_are_rejected(self) -> None:
        pack = validate_pack(self._reference("tracker/linear.json"), root=REFERENCE_ROOT)
        plan = self._preview(pack)
        tampered = plan.as_dict()
        tampered["target"] = "elsewhere.json"
        with self.assertRaisesRegex(IntegrationPackError, "digest"):
            PackPlan.from_dict(tampered)

        config = self.runtime / "config" / "project-management.config.md"
        config.write_bytes(config.read_bytes() + b"CONCURRENT=true\n")
        with self.assertRaisesRegex(IntegrationPackError, "changed"):
            self._apply(plan)

    def test_tracker_apply_does_not_overwrite_a_late_concurrent_change(self) -> None:
        pack = validate_pack(self._reference("tracker/linear.json"), root=REFERENCE_ROOT)
        plan = self._preview(pack)
        config_path = self.runtime / "config" / "project-management.config.md"
        original_exchange = project_config._atomic_exchange_at
        exchanges = 0
        concurrent = config_path.read_bytes() + b"CONCURRENT=true\n"

        def racing_exchange(
            parent_descriptor: int, first_name: str, second_name: str
        ) -> None:
            nonlocal exchanges
            exchanges += 1
            if exchanges == 1:
                config_path.write_bytes(concurrent)
            original_exchange(parent_descriptor, first_name, second_name)

        with mock.patch.object(
            project_config, "_atomic_exchange_at", side_effect=racing_exchange
        ):
            with self.assertRaisesRegex(IntegrationPackError, "changed"):
                self._apply(plan)

        self.assertEqual(exchanges, 2)
        self.assertEqual(config_path.read_bytes(), concurrent)
        self.assertIn(b"PRODUCT_MANAGEMENT_TOOL=Markdown", config_path.read_bytes())
        self.assertEqual(list(config_path.parent.glob(f".{config_path.name}.*.tmp")), [])

    def test_tracker_ambiguity_reports_the_absolute_runtime_recovery_path(self) -> None:
        pack = validate_pack(self._reference("tracker/linear.json"), root=REFERENCE_ROOT)
        plan = self._preview(pack)
        config_path = self.runtime / "config" / "project-management.config.md"
        after_exchange = config_path.read_bytes() + b"CONCURRENT=true\n"
        original_exchange = project_config._atomic_exchange_at
        exchanges = 0

        def racing_exchange(
            parent_descriptor: int, first_name: str, second_name: str
        ) -> None:
            nonlocal exchanges
            exchanges += 1
            original_exchange(parent_descriptor, first_name, second_name)
            if exchanges == 1:
                config_path.write_bytes(after_exchange)

        with mock.patch.object(
            project_config, "_atomic_exchange_at", side_effect=racing_exchange
        ):
            with self.assertRaisesRegex(
                IntegrationPackError, "recoverable original bytes"
            ) as caught:
                self._apply(plan)

        self.assertEqual(exchanges, 1)
        self.assertIn(str(config_path.parent), str(caught.exception))
        recovery = list(config_path.parent.glob(f".{config_path.name}.*.tmp"))
        self.assertEqual(len(recovery), 1)

    def test_apply_revalidates_pack_source(self) -> None:
        document = self._document()
        path = self._write_pack("mutable.json", document)
        plan = self._preview(path)
        document["summary"] = "Changed after preview"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(IntegrationPackError, "source or target changed"):
            self._apply(plan)

    def test_ci_and_deployment_create_one_inactive_idempotent_target(self) -> None:
        for relative in (
            "ci/github-actions-exact-commit.json",
            "deployment/docker-compose.json",
            "deployment/kubernetes.json",
        ):
            with self.subTest(relative=relative):
                isolated = self.scratch / relative.replace("/", "-").replace(".json", "")
                (isolated / "config").mkdir(parents=True)
                (isolated / "config" / "project-management.config.md").write_text(
                    "PRODUCT_MANAGEMENT_TOOL=Markdown\nTEAM_MODE=true\n",
                    encoding="utf-8",
                )
                pack = validate_pack(self._reference(relative), root=REFERENCE_ROOT)
                plan = self._preview(pack, isolated)
                self.assertTrue(plan.target_relative.startswith(f".startup-factory/generated/{pack.kind}/{pack.pack_id}/"))
                receipt = self._apply(plan, isolated)
                self.assertTrue(receipt.applied)
                files = [item for item in isolated.rglob("*") if item.is_file()]
                generated = [item for item in files if ".startup-factory/generated" in item.as_posix()]
                self.assertEqual(len(generated), 1)
                output = json.loads(generated[0].read_text(encoding="utf-8"))
                self.assertIs(output["active"], False)
                if pack.kind == "deployment":
                    self.assertIs(output["configuration"]["enabled"], False)
                    self.assertIs(output["configuration"]["releaseAuthority"], False)
                    self.assertIs(output["configuration"]["containsCredentialValues"], False)
                retry = self._apply(plan, isolated)
                self.assertTrue(retry.idempotent)

    def test_generated_idempotence_requires_mode_and_bound_identity(self) -> None:
        pack = validate_pack(
            self._reference("ci/github-actions-exact-commit.json"), root=REFERENCE_ROOT
        )
        plan = self._preview(pack)
        self._apply(plan)
        target = self.project / plan.target_relative

        target.chmod(0o666)
        with self.assertRaisesRegex(IntegrationPackError, "mode 0644"):
            self._apply(plan)
        with self.assertRaisesRegex(IntegrationPackError, "mode 0644"):
            self._preview(pack)

        target.chmod(0o644)
        already_applied = self._preview(pack)
        self.assertEqual(
            already_applied.target_digest, already_applied.rendered_digest
        )
        raw = target.read_bytes()
        replacement = target.with_name("replacement.json")
        replacement.write_bytes(raw)
        replacement.chmod(0o644)
        os.replace(replacement, target)
        with self.assertRaisesRegex(IntegrationPackError, "identity changed"):
            self._apply(already_applied)

    def test_generated_target_collision_and_symlink_parent_are_rejected(self) -> None:
        pack = validate_pack(
            self._reference("ci/github-actions-exact-commit.json"), root=REFERENCE_ROOT
        )
        plan = self._preview(pack)
        target = self.project / plan.target_relative
        target.parent.mkdir(parents=True)
        target.write_text("different\n", encoding="utf-8")
        with self.assertRaisesRegex(IntegrationPackError, "different bytes"):
            self._apply(plan)

        other = self.scratch / "symlink-project"
        (other / "config").mkdir(parents=True)
        (other / "config" / "project-management.config.md").write_text(
            "PRODUCT_MANAGEMENT_TOOL=Markdown\nTEAM_MODE=true\n", encoding="utf-8"
        )
        outside = self.scratch / "outside"
        outside.mkdir()
        (other / ".startup-factory").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(IntegrationPackError, "unsafe|symbolic"):
            self._preview(pack, other)
        self.assertEqual(list(outside.iterdir()), [])

    def test_generated_target_parent_swap_cannot_escape_held_project_root(self) -> None:
        pack = validate_pack(
            self._reference("ci/github-actions-exact-commit.json"), root=REFERENCE_ROOT
        )
        plan = self._preview(pack)
        outside = self.scratch / "late-swap-outside"
        outside.mkdir()
        original_create = integration_packs._atomic_create_generated_at

        def racing_create(root_descriptor: int, relative: str, content: bytes) -> None:
            (self.project / ".startup-factory").symlink_to(
                outside, target_is_directory=True
            )
            original_create(root_descriptor, relative, content)

        integration_packs._atomic_create_generated_at = racing_create
        try:
            with self.assertRaisesRegex(IntegrationPackError, "non-symlink"):
                self._apply(plan)
        finally:
            integration_packs._atomic_create_generated_at = original_create
        self.assertEqual(list(outside.iterdir()), [])

    def test_doctor_refuses_symlinked_detection_paths(self) -> None:
        pack = validate_pack(self._reference("tracker/jira.json"), root=REFERENCE_ROOT)
        outside = self.scratch / "outside-adapters"
        outside.mkdir()
        (outside / "Jira.md").write_text("outside\n", encoding="utf-8")
        (self.runtime / "adapters").rmdir()
        (self.runtime / "adapters").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(IntegrationPackError, "unsafe|symbolic"):
            self._doctor(pack)

    def test_doctor_never_reads_values_and_separates_three_readiness_states(self) -> None:
        pack = validate_pack(self._reference("tracker/jira.json"), root=REFERENCE_ROOT)
        plan = self._preview(pack)
        self._apply(plan)
        (self.runtime / "adapters" / "Jira.md").write_text("adapter\n", encoding="utf-8")
        environment = PresenceOnlyEnvironment({"JIRA_API_TOKEN", "JIRA_EMAIL"})
        report = self._doctor(pack, environment=environment)
        result = report.as_dict()
        serialized = json.dumps(result)
        self.assertEqual(result["configured"]["status"], "configured")
        self.assertEqual(result["detected"]["status"], "detected")
        self.assertEqual(result["proved"]["status"], "unknown")
        self.assertTrue(
            any("authenticated external integration adapter" in action for action in result["operatorActions"])
        )
        self.assertEqual(
            result["credentials"],
            {
                "policy": "adapter-managed",
                "status": "conditional",
                "message": "credential requirements are conditional on the adapter access mode; this pack does not select or authenticate that mode",
                "required": [],
                "present": [],
                "missing": [],
            },
        )
        self.assertNotIn("super-sensitive", serialized)

        required_document = self._document("tracker/jira.json")
        required_document["id"] = "tracker-jira-rest"
        required_document["credentials"] = {
            "policy": "required-environment",
            "required": ["JIRA_API_TOKEN", "JIRA_BASE_URL", "JIRA_EMAIL"],
        }
        required_pack = validate_pack(self._write_pack("jira-rest.json", required_document))
        required_report = self._doctor(
            required_pack, environment=environment
        ).as_dict()
        required = required_report["credentials"]
        self.assertEqual(required["status"], "missing")
        self.assertEqual(required["present"], ["JIRA_API_TOKEN", "JIRA_EMAIL"])
        self.assertEqual(required["missing"], ["JIRA_BASE_URL"])
        self.assertTrue(
            any("listed credential environment names" in action for action in required_report["operatorActions"])
        )

        evidence = {
            "schemaVersion": 1,
            "packId": pack.pack_id,
            "kind": pack.kind,
            "sourceDigest": pack.source_digest,
            "result": "proved",
            "evidenceDigest": "sha256:" + "a" * 64,
        }
        with self.assertRaisesRegex(IntegrationPackError, "cannot authenticate"):
            self._doctor(
                pack,
                environment=environment,
                protected_evidence=evidence,
            )

    def test_plan_decoder_rejects_duplicate_keys_and_boolean_versions(self) -> None:
        pack = validate_pack(self._reference("tracker/markdown.json"), root=REFERENCE_ROOT)
        plan = self._preview(pack)
        raw = json.dumps(plan.as_dict()).encode("utf-8")
        duplicate = raw.replace(b'{"schemaVersion": 2,', b'{"schemaVersion": 2, "schemaVersion": 2,', 1)
        with self.assertRaisesRegex(IntegrationPackError, "duplicate JSON key"):
            decode_plan(duplicate)
        boolean_version = plan.as_dict()
        boolean_version["schemaVersion"] = True
        with self.assertRaisesRegex(IntegrationPackError, "versions must be integers"):
            PackPlan.from_dict(boolean_version)
        wrong_target_root = plan.as_dict()
        wrong_target_root["targetRoot"] = "project"
        wrong_target_root["planDigest"] = integration_packs._digest(
            integration_packs._canonical(
                {
                    key: value
                    for key, value in wrong_target_root.items()
                    if key != "planDigest"
                }
            )
        )
        with self.assertRaisesRegex(IntegrationPackError, "targetRoot"):
            PackPlan.from_dict(wrong_target_root)
        controlled_path = plan.as_dict()
        controlled_path["projectRoot"] = str(self.project) + "\n"
        with self.assertRaisesRegex(IntegrationPackError, "bounded string"):
            PackPlan.from_dict(controlled_path)

    def test_plan_reader_rejects_fifo_symlinked_parent_and_oversize_without_blocking(self) -> None:
        fifo = self.scratch / "plan.fifo"
        os.mkfifo(fifo)
        started = time.monotonic()
        with self.assertRaisesRegex(IntegrationPackError, "regular file"):
            load_plan(fifo)
        self.assertLess(time.monotonic() - started, 1.0)

        real_parent = self.scratch / "real-plans"
        real_parent.mkdir()
        (real_parent / "plan.json").write_text("{}", encoding="utf-8")
        linked_parent = self.scratch / "linked-plans"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(IntegrationPackError, "unsafe"):
            load_plan(linked_parent / "plan.json")

        oversized = self.scratch / "oversized-plan.json"
        oversized.write_bytes(b"{" + b" " * integration_packs.MAX_PLAN_BYTES + b"}")
        with self.assertRaisesRegex(IntegrationPackError, "bounded|exceeds"):
            load_plan(oversized)

    def test_plan_binds_source_project_and_runtime_directory_identities(self) -> None:
        ci = validate_pack(
            self._reference("ci/github-actions-exact-commit.json"), root=REFERENCE_ROOT
        )
        project_plan = self._preview(ci)
        displaced_project = self.scratch / "original-project"
        self.project.rename(displaced_project)
        self.project.mkdir()
        with self.assertRaisesRegex(IntegrationPackError, "project root identity"):
            self._apply(project_plan)

        tracker_document = self._document("tracker/linear.json")
        source = self._write_pack("identity-linear.json", tracker_document)
        runtime_plan = self._preview(source, project=displaced_project)
        displaced_runtime = self.scratch / "original-runtime"
        self.runtime.rename(displaced_runtime)
        (self.runtime / "config").mkdir(parents=True)
        (self.runtime / "adapters").mkdir()
        shutil.copy2(
            displaced_runtime / "config" / "project-management.config.md",
            self.runtime / "config" / "project-management.config.md",
        )
        with self.assertRaisesRegex(IntegrationPackError, "runtime root identity"):
            self._apply(runtime_plan, displaced_project)

        # Restore the runtime identity used by the rest of this test, then prove
        # an identically named replacement source directory cannot satisfy a plan.
        shutil.rmtree(self.runtime)
        displaced_runtime.rename(self.runtime)
        source_plan = self._preview(source, project=displaced_project)
        source_parent = source.parent
        old_source_parent = self.scratch / "old-packs"
        source_parent.rename(old_source_parent)
        source_parent.mkdir()
        shutil.copy2(old_source_parent / source.name, source_parent / source.name)
        with self.assertRaisesRegex(IntegrationPackError, "source or target changed"):
            self._apply(source_plan, displaced_project)

    def test_runtime_platform_distinguishes_wsl1_wsl2_and_ordinary_linux(self) -> None:
        cases = (
            (
                "4.4.0-19041-generic",
                "#1237-Microsoft Thu Sep 12 12:00:00 PST 2024",
                "wsl1",
            ),
            (
                "5.15.153.1-microsoft-standard-WSL2",
                "#1 SMP Fri Mar 29 23:14:13 UTC 2024",
                "wsl2",
            ),
            (
                "6.8.0-79-generic",
                "#79-Ubuntu SMP PREEMPT_DYNAMIC",
                "linux",
            ),
        )
        for release, version, expected in cases:
            with self.subTest(expected=expected):
                kernel = mock.Mock(release=release, version=version)
                with mock.patch.object(
                    integration_packs.sys, "platform", "linux"
                ), mock.patch.object(
                    integration_packs.os,
                    "uname",
                    return_value=kernel,
                ):
                    self.assertEqual(integration_packs._runtime_platform(), expected)

    def test_wsl_requires_opt_in_and_doctor_reports_experimental_runtime(self) -> None:
        pack = validate_pack(
            self._reference("tracker/markdown.json"), root=REFERENCE_ROOT
        )
        wsl2 = mock.Mock(
            release="5.15.153.1-microsoft-standard-WSL2",
            version="#1 SMP Fri Mar 29 23:14:13 UTC 2024",
        )
        with mock.patch.object(
            integration_packs.sys, "platform", "linux"
        ), mock.patch.object(
            integration_packs.os,
            "uname",
            return_value=wsl2,
        ):
            with self.assertRaisesRegex(
                IntegrationPackError,
                "wsl2 is experimental and requires explicit preview opt-in",
            ):
                self._preview(pack)

            report = self._doctor(pack).as_dict()["compatibility"]
            self.assertEqual(report["status"], "incompatible")
            self.assertEqual(report["platform"], "wsl2")
            self.assertEqual(report["compatibilityPlatform"], "linux")
            self.assertEqual(report["runtimeState"], "experimental")
            self.assertFalse(report["experimentalAllowed"])
            self.assertTrue(
                any("explicit preview opt-in" in reason for reason in report["reasons"])
            )

            opted_in = self._doctor(pack, allow_experimental=True).as_dict()[
                "compatibility"
            ]
            self.assertEqual(opted_in["status"], "compatible")
            self.assertEqual(opted_in["platform"], "wsl2")
            self.assertEqual(opted_in["runtimeState"], "experimental")
            self.assertTrue(opted_in["experimentalAllowed"])
            self.assertEqual(opted_in["reasons"], [])

            plan = self._preview(pack, allow_experimental=True)
            self.assertEqual(plan.runtime_platform, "wsl2")
            self.assertTrue(plan.allow_experimental)

        linux = mock.Mock(
            release="6.8.0-79-generic",
            version="#79-Ubuntu SMP PREEMPT_DYNAMIC",
        )
        with mock.patch.object(
            integration_packs.sys, "platform", "linux"
        ), mock.patch.object(
            integration_packs.os,
            "uname",
            return_value=linux,
        ):
            report = self._doctor(pack).as_dict()["compatibility"]
            self.assertEqual(report["status"], "compatible")
            self.assertEqual(report["platform"], "linux")
            self.assertEqual(report["compatibilityPlatform"], "linux")
            self.assertEqual(report["runtimeState"], "supported")

    def test_saved_plan_binds_wsl_generation_and_linux_environment(self) -> None:
        pack = validate_pack(
            self._reference("tracker/markdown.json"), root=REFERENCE_ROOT
        )
        wsl2 = mock.Mock(
            release="5.15.153.1-microsoft-standard-WSL2",
            version="#1 SMP Fri Mar 29 23:14:13 UTC 2024",
        )
        with mock.patch.object(
            integration_packs.sys, "platform", "linux"
        ), mock.patch.object(
            integration_packs.os,
            "uname",
            return_value=wsl2,
        ):
            plan = self._preview(pack, allow_experimental=True)

        changed_environments = (
            mock.Mock(
                release="4.4.0-19041-Microsoft",
                version="#1-Microsoft Thu Sep 12 12:00:00 PST 2024",
            ),
            mock.Mock(
                release="6.8.0-79-generic",
                version="#79-Ubuntu SMP PREEMPT_DYNAMIC",
            ),
        )
        for kernel in changed_environments:
            with self.subTest(release=kernel.release), mock.patch.object(
                integration_packs.sys, "platform", "linux"
            ), mock.patch.object(integration_packs.os, "uname", return_value=kernel):
                with self.assertRaisesRegex(
                    IntegrationPackError, "runtime version or platform changed"
                ):
                    PackPlan.from_dict(plan.as_dict())

    def test_compatibility_is_enforced_and_doctor_is_descriptive(self) -> None:
        experimental = self._document("tracker/linear.json")
        experimental["id"] = "tracker-linear-preview"
        experimental["compatibility"]["state"] = "experimental"  # type: ignore[index]
        experimental_pack = validate_pack(
            self._write_pack("experimental.json", experimental)
        )
        with self.assertRaisesRegex(IntegrationPackError, "explicit preview opt-in"):
            self._preview(experimental_pack)
        report = self._doctor(experimental_pack).as_dict()["compatibility"]
        self.assertEqual(report["status"], "incompatible")
        self.assertIn("explicit preview opt-in", report["reasons"][0])
        plan = self._preview(experimental_pack, allow_experimental=True)
        self.assertTrue(plan.allow_experimental)
        self.assertTrue(self._apply(plan).applied)

        unsupported = self._document("ci/github-actions-exact-commit.json")
        unsupported["id"] = "ci-unsupported"
        unsupported["compatibility"]["state"] = "unsupported"  # type: ignore[index]
        unsupported_pack = validate_pack(self._write_pack("unsupported.json", unsupported))
        with self.assertRaisesRegex(IntegrationPackError, "unsupported"):
            self._preview(unsupported_pack)

        future = self._document("ci/github-actions-exact-commit.json")
        future["id"] = "ci-future"
        future["compatibility"]["minimumVersion"] = "999.0.0"  # type: ignore[index]
        future_pack = validate_pack(self._write_pack("future.json", future))
        with self.assertRaisesRegex(IntegrationPackError, "older than required"):
            self._preview(future_pack)

        windows = self._document("tracker/markdown.json")
        windows["id"] = "tracker-markdown-windows"
        windows["compatibility"]["platforms"] = ["windows"]  # type: ignore[index]
        windows_pack = validate_pack(self._write_pack("windows.json", windows))
        with mock.patch.object(integration_packs.sys, "platform", "win32"):
            with self.assertRaisesRegex(
                IntegrationPackError, "core runtime platform windows is unsupported"
            ):
                self._preview(windows_pack, allow_experimental=True)
            report = self._doctor(
                windows_pack, allow_experimental=True
            ).as_dict()["compatibility"]
            self.assertEqual(report["status"], "incompatible")
            self.assertEqual(report["runtimeState"], "unsupported")
            self.assertTrue(
                any(
                    "core runtime platform windows is unsupported" in reason
                    for reason in report["reasons"]
                )
            )

    def test_runtime_version_constant_matches_packaging_metadata(self) -> None:
        self.assertEqual(RUNTIME_VERSION, _declared_runtime_version(ROOT))

    def test_runtime_version_uses_installed_bundle_manifest_without_tomllib(self) -> None:
        installed = self.scratch / "bundle-runtime"
        installed.mkdir()
        (installed / ".startup-factory-bundle.json").write_text(
            json.dumps({"schemaVersion": 1, "version": RUNTIME_VERSION}),
            encoding="utf-8",
        )
        self.assertEqual(RUNTIME_VERSION, _declared_runtime_version(installed))

    def test_thin_script_lists_validates_previews_applies_and_doctors(self) -> None:
        listed = subprocess.run(
            [sys.executable, str(SCRIPT), "list"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertEqual(len(json.loads(listed.stdout)["packs"]), 7)

        validated = subprocess.run(
            [sys.executable, str(SCRIPT), "validate", "tracker-linear"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertTrue(json.loads(validated.stdout)["valid"])

        previewed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "preview",
                "github-actions-exact-commit",
                "--project-root",
                str(self.project),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        plan_path = self.scratch / "plan.json"
        plan_path.write_text(previewed.stdout, encoding="utf-8")
        applied = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "apply",
                str(plan_path),
                "--project-root",
                str(self.project),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertTrue(json.loads(applied.stdout)["applied"])

        missing_root = subprocess.run(
            [sys.executable, str(SCRIPT), "apply", str(plan_path)],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(missing_root.returncode, 2)
        self.assertIn("--project-root", missing_root.stderr)

        env = dict(os.environ)
        env["LINEAR_API_KEY"] = "must-never-appear-in-output"
        examined = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "doctor",
                "github-actions-exact-commit",
                "--project-root",
                str(self.project),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=env,
        )
        self.assertEqual(examined.returncode, 1, examined.stderr)
        self.assertNotIn(env["LINEAR_API_KEY"], examined.stdout)
        examined_report = json.loads(examined.stdout)
        self.assertEqual(examined_report["proved"]["status"], "unknown")
        self.assertFalse(examined_report["ready"])

    def test_thin_script_runs_from_a_bundle_like_tree_with_packaged_sources(self) -> None:
        bundle = self.scratch / "installed-skill"
        (bundle / "bin").mkdir(parents=True)
        (bundle / "extensions").mkdir()
        shutil.copy2(SCRIPT, bundle / "bin" / "integration_pack.py")
        shutil.copytree(ROOT / "src" / "startup_factory_cli", bundle / "src" / "startup_factory_cli")
        shutil.copytree(REFERENCE_ROOT, bundle / "extensions" / "integration-packs")
        shutil.copytree(ROOT / "config", bundle / "config")
        shutil.copytree(ROOT / "adapters", bundle / "adapters")
        completed = subprocess.run(
            [sys.executable, str(bundle / "bin" / "integration_pack.py"), "validate", "tracker-markdown"],
            cwd=self.scratch,
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertEqual(json.loads(completed.stdout)["pack"]["id"], "tracker-markdown")

        previewed = subprocess.run(
            [
                sys.executable,
                str(bundle / "bin" / "integration_pack.py"),
                "preview",
                "tracker-linear",
                "--project-root",
                str(self.project),
            ],
            cwd=self.scratch,
            check=True,
            text=True,
            capture_output=True,
        )
        plan = json.loads(previewed.stdout)
        self.assertEqual(plan["projectRoot"], str(self.project))
        self.assertEqual(plan["runtimeRoot"], str(bundle))
        self.assertEqual(plan["targetRoot"], "runtime")
        plan_path = self.scratch / "bundle-plan.json"
        plan_path.write_text(previewed.stdout, encoding="utf-8")
        applied = subprocess.run(
            [
                sys.executable,
                str(bundle / "bin" / "integration_pack.py"),
                "apply",
                str(plan_path),
                "--project-root",
                str(self.project),
            ],
            cwd=self.scratch,
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertTrue(json.loads(applied.stdout)["applied"])
        self.assertIn(
            "PRODUCT_MANAGEMENT_TOOL=Linear",
            (bundle / "config" / "project-management.config.md").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse((self.project / "config").exists())

    def test_thin_script_refuses_a_symlinked_plan_file(self) -> None:
        pack = validate_pack(self._reference("tracker/linear.json"), root=REFERENCE_ROOT)
        plan_path = self.scratch / "plan.json"
        plan_path.write_text(json.dumps(self._preview(pack).as_dict()), encoding="utf-8")
        link = self.scratch / "plan-link.json"
        link.symlink_to(plan_path)
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "apply",
                str(link),
                "--project-root",
                str(self.project),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertRegex(completed.stderr, "symbolic|Too many levels")


if __name__ == "__main__":
    unittest.main(verbosity=2)
