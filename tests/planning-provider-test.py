#!/usr/bin/env python3
"""Exercise optional planning providers through their public CLI and real Git inputs."""

from __future__ import annotations

import hashlib
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin/planning.py"
LEGACY = ROOT / "bin/superpowers-planning.py"
BUNDLE_FILES = tuple(
    relative for relative in runpy.run_path(str(SCRIPT))["EGM_REQUIRED_FILES"]
    if relative != "plugin.json"
)


class PlanningProviderTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sf-planning-provider-")
        self.addCleanup(temporary.cleanup)
        self.temp = Path(temporary.name).resolve()
        self.repo = self.temp / "project"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Planning fixture")
        (self.repo / ".gitignore").write_text(".teamwork/\n", encoding="utf-8")
        self.git("add", ".gitignore")
        self.git("commit", "-qm", "initialize disposable planning fixture")
        self.config = self.temp / "planning.config.md"

    def git(self, *arguments: str) -> str:
        process = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        return process.stdout.strip()

    def configure(self, provider: str | None = None, **values: str) -> Path:
        settings = {"USE_SUPERPOWERS": "true"}
        if provider is not None:
            settings["PLANNING_PROVIDER"] = provider
        settings.update(values)
        self.config.write_text(
            "```\n" + "".join(f'{key}="{value}"\n' for key, value in settings.items()) + "```\n",
            encoding="utf-8",
        )
        return self.config

    def invoke(self, *arguments: str, legacy: bool = False, succeeds: bool = True):
        process = subprocess.run(
            [sys.executable, str(LEGACY if legacy else SCRIPT), "--config", str(self.config), *arguments],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )
        diagnostic = f"stdout={process.stdout!r}\nstderr={process.stderr!r}"
        if succeeds:
            self.assertEqual(process.returncode, 0, diagnostic)
        else:
            self.assertNotEqual(process.returncode, 0, diagnostic)
            self.assertNotIn("Traceback", process.stderr, diagnostic)
        return process

    def result(self, *arguments: str, legacy: bool = False):
        return json.loads(self.invoke(*arguments, legacy=legacy).stdout)

    def documents(self, provider: str = "egm") -> tuple[str, str]:
        base = {"egm": "docs/egm", "superpowers": "docs/superpowers", "native": "docs"}[provider]
        paths = (f"{base}/specs/export.md", f"{base}/plans/export.md")
        for relative, content in zip(
            paths,
            ("# CSV export\n\nREQ-1: Export the visible report rows.\n", "# Implementation\n\nImplement REQ-1 and verify quoted CSV fields.\n"),
        ):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.git("add", "--", *paths)
        self.git("commit", "-qm", "commit specification and implementation plan")
        return paths

    def bundle(self) -> Path:
        bundle = self.temp / "egm bundle"
        bundle.mkdir()
        (bundle / "plugin.json").write_text(
            json.dumps({"name": "egm", "version": "0.1.1"}) + "\n",
            encoding="utf-8",
        )
        for relative in BUNDLE_FILES:
            path = bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"# Fixture {relative}\n", encoding="utf-8")
        return bundle

    def egm_inputs(self):
        bundle = self.bundle()
        self.configure("egm", EGM_PLUGIN_ROOT=str(bundle))
        spec, plan = self.documents()
        return bundle, spec, plan

    def handoff(self, spec: str, plan: str, *, runtime: str = "codex", legacy: bool = False):
        output = self.repo / ".teamwork/exports/planning/handoff.json"
        arguments = [
            "create-handoff", "--repo", str(self.repo), "--team", "exports",
            "--spec", spec, "--plan", plan, "--output", str(output),
            "--intake", "spec-provided",
        ]
        if not legacy:
            arguments.extend(("--runtime", runtime))
        result = self.result(*arguments, legacy=legacy)
        self.assertEqual(Path(result["handoff"]), output)
        return output, json.loads(output.read_text(encoding="utf-8"))

    def validate(self, output: Path, *arguments: str, succeeds: bool = True):
        return self.invoke(
            "validate-handoff", "--repo", str(self.repo), "--handoff", str(output),
            *arguments, succeeds=succeeds,
        )

    def test_native_selection_does_not_require_optional_plugins(self) -> None:
        self.configure("native")
        for runtime in ("claude", "codex", "deepseek-harness", "other"):
            with self.subTest(runtime=runtime):
                result = self.result("preflight", "--runtime", runtime)
                self.assertEqual(result["provider"], "native")
                self.assertEqual(result["status"], "ready")

    def test_auto_keeps_non_claude_native_and_honors_legacy_opt_out(self) -> None:
        self.configure()
        for runtime in ("codex", "deepseek-harness", "other"):
            with self.subTest(runtime=runtime):
                self.assertEqual(self.result("preflight", "--runtime", runtime)["provider"], "native")
        self.configure(USE_SUPERPOWERS="false")
        self.assertEqual(self.result("preflight", "--runtime", "claude")["provider"], "native")

    def test_explicit_superpowers_is_not_silently_used_on_another_runtime(self) -> None:
        self.configure("superpowers", USE_SUPERPOWERS="false")
        self.invoke("preflight", "--runtime", "codex", succeeds=False)

    def test_auto_claude_and_explicit_superpowers_check_plugin_availability(self) -> None:
        plugins = self.temp / "plugins.json"
        plugins.write_text(json.dumps([
            {"id": "superpowers@claude-plugins-official", "enabled": True, "version": "7.0.2"}
        ]), encoding="utf-8")
        for provider, flag in (("auto", "true"), ("superpowers", "false")):
            with self.subTest(provider=provider):
                self.configure(provider, USE_SUPERPOWERS=flag)
                result = self.result(
                    "preflight", "--runtime", "claude", "--plugin-list-json", str(plugins)
                )
                self.assertEqual(result["provider"], "superpowers")
                self.assertEqual(result["status"], "ready")
        plugins.write_text("[]\n", encoding="utf-8")
        self.invoke(
            "preflight", "--runtime", "claude", "--plugin-list-json", str(plugins), succeeds=False
        )

    def test_invalid_provider_duplicate_keys_and_unsafe_roots_fail(self) -> None:
        for settings in (
            {"PLANNING_PROVIDER": "unknown"},
            {"EGM_SPEC_ROOT": "../outside"},
            {"EGM_PLAN_ROOT": "/tmp/plan"},
            {"NATIVE_SPEC_ROOT": "docs//specs"},
        ):
            with self.subTest(settings=settings):
                self.configure(**settings)
                self.invoke("show-config", succeeds=False)
        self.configure("native")
        with self.config.open("a", encoding="utf-8") as stream:
            stream.write("PLANNING_PROVIDER=egm\n")
        self.invoke("show-config", succeeds=False)

    def test_egm_requires_a_real_bundle(self) -> None:
        self.configure("egm")
        self.invoke("preflight", "--runtime", "codex", succeeds=False)
        self.configure("egm", EGM_PLUGIN_ROOT=str(self.temp / "missing-bundle"))
        self.invoke("preflight", "--runtime", "deepseek-harness", succeeds=False)

    def test_egm_bundle_preflight_is_portable_and_has_content_provenance(self) -> None:
        bundle = self.bundle()
        self.configure("egm", USE_SUPERPOWERS="false", EGM_PLUGIN_ROOT=str(bundle))
        digests = []
        for runtime in ("claude", "claude-code", "codex", "deepseek-harness", "aider", "other"):
            with self.subTest(runtime=runtime):
                result = self.result("preflight", "--runtime", runtime)
                self.assertEqual(result["provider"], "egm")
                self.assertEqual(result["status"], "ready")
                self.assertEqual(result["egmRoot"], str(bundle))
                self.assertRegex(result["resourceDigest"], r"^[0-9a-f]{64}$")
                self.assertTrue(set(BUNDLE_FILES) <= set(result["resourceFiles"]))
                digests.append(result["resourceDigest"])
        self.assertEqual(len(set(digests)), 1)

    def test_partial_bundle_and_escaped_resources_are_not_ready(self) -> None:
        bundle = self.bundle()
        self.configure("egm", EGM_PLUGIN_ROOT=str(bundle))
        for relative in ("agents/comprehension.md", "agents/zoom_out.md", "agents/design_critic.md"):
            with self.subTest(missing_persona=relative):
                persona = bundle / relative
                original = persona.read_text(encoding="utf-8")
                persona.unlink()
                self.invoke("preflight", "--runtime", "codex", succeeds=False)
                persona.write_text(original, encoding="utf-8")
        persona = bundle / "agents/comprehension.md"
        original = persona.read_text(encoding="utf-8")
        persona.unlink()
        outside = self.temp / "untrusted-persona.md"
        outside.write_text(original, encoding="utf-8")
        persona.symlink_to(outside)
        self.invoke("preflight", "--runtime", "codex", succeeds=False)

    def test_bundle_metadata_must_identify_egm(self) -> None:
        bundle = self.bundle()
        self.configure("egm", EGM_PLUGIN_ROOT=str(bundle))
        (bundle / "plugin.json").write_text(
            json.dumps({"name": "another-plugin", "version": "0.1.1"}), encoding="utf-8"
        )
        self.invoke("preflight", "--runtime", "claude", succeeds=False)

    def test_egm_handoff_binds_runtime_documents_and_bundle(self) -> None:
        _, spec, plan = self.egm_inputs()
        preflight = self.result("preflight", "--runtime", "codex")
        for runtime in ("claude", "codex", "deepseek-harness", "other"):
            with self.subTest(runtime=runtime):
                output, manifest = self.handoff(spec, plan, runtime=runtime)
                self.assertEqual(manifest["schemaVersion"], 3)
                self.assertEqual(manifest["provider"], "egm")
                self.assertEqual(manifest["runtime"], runtime)
                self.assertEqual(manifest["executionOwner"], "startup-factory")
                self.assertEqual(manifest["intake"], "spec-provided")
                self.assertEqual(manifest["provenance"]["sha256"], preflight["resourceDigest"])
                self.assertEqual(manifest["spec"]["path"], spec)
                self.assertEqual(manifest["plan"]["path"], plan)
                validated = json.loads(self.validate(output, "--team", "exports", "--require-head").stdout)
                self.assertTrue(validated["valid"])
                self.validate(output, "--team", "another-feature", succeeds=False)

    def test_native_handoff_works_without_egm_bundle(self) -> None:
        self.configure("native")
        spec, plan = self.documents("native")
        output, manifest = self.handoff(spec, plan)
        self.assertEqual(manifest["provider"], "native")
        self.assertEqual(manifest["schemaVersion"], 3)
        self.assertTrue(json.loads(self.validate(output).stdout)["valid"])

    def test_changing_any_bundle_resource_invalidates_existing_handoff(self) -> None:
        bundle, spec, plan = self.egm_inputs()
        output, _ = self.handoff(spec, plan)
        # This resource is outside the required anchor set; provenance covers the
        # complete runtime bundle, not just an availability checklist.
        extra = bundle / "resources/extra-standard.md"
        extra.write_text("# Added review requirement\n", encoding="utf-8")
        self.validate(output, succeeds=False)
        extra.unlink()
        self.assertTrue(json.loads(self.validate(output).stdout)["valid"])

    def test_changes_to_spec_and_plan_invalidate_handoff(self) -> None:
        _, spec, plan = self.egm_inputs()
        output, _ = self.handoff(spec, plan)
        for relative in (spec, plan):
            with self.subTest(document=relative):
                path = self.repo / relative
                original = path.read_text(encoding="utf-8")
                path.write_text(original + "\nChanged requirement.\n", encoding="utf-8")
                self.validate(output, succeeds=False)
                path.write_text(original, encoding="utf-8")
        self.assertTrue(json.loads(self.validate(output).stdout)["valid"])

    def test_uncommitted_specification_cannot_create_handoff(self) -> None:
        _, spec, plan = self.egm_inputs()
        (self.repo / spec).write_text("# Unapproved change\n", encoding="utf-8")
        self.invoke(
            "create-handoff", "--repo", str(self.repo), "--team", "exports",
            "--spec", spec, "--plan", plan, "--output", ".teamwork/exports/planning/handoff.json",
            succeeds=False,
        )

    def test_handoff_rejects_changed_provider_ownership_and_forged_provenance(self) -> None:
        bundle, spec, plan = self.egm_inputs()
        output, original = self.handoff(spec, plan)
        self.configure("native", EGM_PLUGIN_ROOT=str(bundle))
        self.validate(output, succeeds=False)
        self.configure("egm", EGM_PLUGIN_ROOT=str(bundle))
        for key, replacement in (
            ("executionOwner", "egm"),
            ("provenance", {"kind": "egm-bundle", "version": "0.1.1", "sha256": "0" * 64}),
        ):
            with self.subTest(field=key):
                changed = dict(original)
                changed[key] = replacement
                output.write_text(json.dumps(changed), encoding="utf-8")
                self.validate(output, succeeds=False)
        output.write_text(json.dumps(original), encoding="utf-8")
        self.assertTrue(json.loads(self.validate(output).stdout)["valid"])

    def test_source_commit_must_contain_the_recorded_documents(self) -> None:
        before_documents = self.git("rev-parse", "HEAD")
        _, spec, plan = self.egm_inputs()
        output, manifest = self.handoff(spec, plan)
        manifest["sourceCommit"] = before_documents
        output.write_text(json.dumps(manifest), encoding="utf-8")
        self.validate(output, succeeds=False)

    def test_committed_new_spec_cannot_be_attributed_to_old_source_commit(self) -> None:
        _, spec, plan = self.egm_inputs()
        output, manifest = self.handoff(spec, plan)
        path = self.repo / spec
        path.write_text("# Changed export requirement\n\nExport every report row.\n", encoding="utf-8")
        self.git("add", "--", spec)
        self.git("commit", "-qm", "change the approved requirement")
        # Updating the current-file hash must not make the old source commit
        # appear to have contained the newly committed requirement.
        manifest["spec"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        output.write_text(json.dumps(manifest), encoding="utf-8")
        self.validate(output, succeeds=False)

    def test_descendant_commit_is_valid_but_exact_head_check_is_stricter(self) -> None:
        _, spec, plan = self.egm_inputs()
        output, _ = self.handoff(spec, plan)
        (self.repo / "README.md").write_text("# Unrelated documentation\n", encoding="utf-8")
        self.git("add", "README.md")
        self.git("commit", "-qm", "unrelated descendant change")
        self.assertTrue(json.loads(self.validate(output).stdout)["valid"])
        self.validate(output, "--require-head", succeeds=False)

    def test_document_and_output_paths_cannot_escape_repository(self) -> None:
        _, spec, plan = self.egm_inputs()
        for changed in (
            ("--spec", "../outside.md"),
            ("--output", str(self.temp / "escaped-handoff.json")),
        ):
            with self.subTest(argument=changed):
                arguments = [
                    "create-handoff", "--repo", str(self.repo), "--team", "exports",
                    "--spec", spec, "--plan", plan, "--output", ".teamwork/exports/planning/handoff.json",
                ]
                arguments[arguments.index(changed[0]) + 1] = changed[1]
                self.invoke(*arguments, succeeds=False)
        self.assertFalse((self.temp / "escaped-handoff.json").exists())

    def test_symlinked_document_and_handoff_output_are_refused(self) -> None:
        _, spec, plan = self.egm_inputs()
        path = self.repo / spec
        outside = self.temp / "outside-document.md"
        outside.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        path.unlink()
        path.symlink_to(outside)
        self.invoke(
            "create-handoff", "--repo", str(self.repo), "--team", "exports",
            "--spec", spec, "--plan", plan, "--output", ".teamwork/exports/planning/handoff.json",
            succeeds=False,
        )
        path.unlink()
        path.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
        output = self.repo / ".teamwork/exports/planning/handoff.json"
        output.parent.mkdir(parents=True)
        output.symlink_to(outside)
        self.invoke(
            "create-handoff", "--repo", str(self.repo), "--team", "exports",
            "--spec", spec, "--plan", plan, "--output", str(output), succeeds=False,
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), path.read_text(encoding="utf-8"))

    def test_generic_validation_accepts_legacy_superpowers_handoff(self) -> None:
        self.configure()
        spec, plan = self.documents("superpowers")
        output, manifest = self.handoff(spec, plan, legacy=True)
        self.assertEqual(manifest["schemaVersion"], 2)
        self.assertEqual(manifest["executionOwner"], "startup-factory")
        self.assertTrue(json.loads(self.validate(output, "--team", "exports").stdout)["valid"])
        self.validate(output, "--team", "different-team", succeeds=False)


if __name__ == "__main__":
    unittest.main()
