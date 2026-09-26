#!/usr/bin/env python3
"""Adversarial tests for installed authority configuration binding."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "startup_factory_authority_config", ROOT / "bin" / "authority_config.py"
)
assert SPEC and SPEC.loader
AUTHORITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORITY)
AuthorityConfigError = AUTHORITY.AuthorityConfigError


class AuthorityConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        # Positive lifecycle-authority fixtures must not inherit Linux's
        # shared /tmp default, which the production resolver intentionally
        # rejects.
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".sf-authority-",
            dir=str(ROOT),
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.skill = self.root / "installed-skill"
        self.lifecycle = self.root / "lifecycle"
        self.repository.mkdir(mode=0o700)
        self.skill.mkdir(mode=0o700)
        self.lifecycle.mkdir(mode=0o700)
        self.lifecycle.chmod(0o700)
        self.team_config = self.skill / "team.config.md"
        self.pm_config = self.skill / "project-management.config.md"
        self.automation_config = self.skill / "automation.config.json"
        self.team_config.write_text(
            f'BROKER_LIFECYCLE_ROOT="{self.lifecycle}"\n', encoding="utf-8"
        )
        self.pm_config.write_text(
            "PRODUCT_MANAGEMENT_TOOL=Markdown\n", encoding="utf-8"
        )
        self.automation_config.write_text(
            json.dumps({"ignoredTaskLabels": ["human-work", "manual-only"]}),
            encoding="utf-8",
        )

    def test_lifecycle_authority_is_configured_and_exact_repeat_only(self) -> None:
        resolved = AUTHORITY.configured_lifecycle_root(
            self.team_config,
            self.repository,
            self.skill,
            str(self.lifecycle),
            required=True,
        )
        self.assertEqual(resolved, self.lifecycle)
        with self.assertRaisesRegex(AuthorityConfigError, "exactly repeat"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config,
                self.repository,
                self.skill,
                str(self.root / "replacement"),
                required=True,
            )

    def test_manual_absence_is_allowed_but_ambient_cannot_create_authority(self) -> None:
        self.team_config.write_text("BROKER_LIFECYCLE_ROOT=null\n", encoding="utf-8")
        self.assertIsNone(
            AUTHORITY.configured_lifecycle_root(
                self.team_config,
                self.repository,
                self.skill,
                required=False,
            )
        )
        with self.assertRaisesRegex(AuthorityConfigError, "cannot replace"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config,
                self.repository,
                self.skill,
                str(self.lifecycle),
                required=False,
            )
        with self.assertRaisesRegex(AuthorityConfigError, "required"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config,
                self.repository,
                self.skill,
                required=True,
            )

    def test_lifecycle_root_rejects_weak_leaf_symlink_and_boundaries(self) -> None:
        self.lifecycle.chmod(0o750)
        with self.assertRaisesRegex(AuthorityConfigError, "0700"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config, self.repository, self.skill, required=True
            )
        self.lifecycle.chmod(0o700)

        alias = self.root / "lifecycle-alias"
        alias.symlink_to(self.lifecycle, target_is_directory=True)
        self.team_config.write_text(
            f'BROKER_LIFECYCLE_ROOT="{alias}"\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(AuthorityConfigError, "canonical non-symlink"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config, self.repository, self.skill, required=True
            )

        self.team_config.write_text(
            f'BROKER_LIFECYCLE_ROOT="{self.repository}"\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(AuthorityConfigError, "disjoint"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config, self.repository, self.skill, required=True
            )

        self.team_config.write_text(
            f'BROKER_LIFECYCLE_ROOT="{self.lifecycle}/"\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(AuthorityConfigError, "normalized"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config, self.repository, self.skill, required=True
            )

    def test_lifecycle_root_rejects_shared_temporary_directory(self) -> None:
        shared_parent = Path("/tmp").resolve()
        with tempfile.TemporaryDirectory(
            prefix="sf-lifecycle-", dir=str(shared_parent)
        ) as shared_name:
            shared = Path(shared_name).resolve()
            shared.chmod(0o700)
            self.team_config.write_text(
                f'BROKER_LIFECYCLE_ROOT="{shared}"\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(AuthorityConfigError, "shared temporary"):
                AUTHORITY.configured_lifecycle_root(
                    self.team_config, self.repository, self.skill, required=True
                )

    def test_tracker_and_human_work_policy_are_config_bound(self) -> None:
        self.assertEqual(
            AUTHORITY.configured_tracker_adapter(self.pm_config, "Markdown"),
            "Markdown",
        )
        with self.assertRaisesRegex(AuthorityConfigError, "exactly repeat"):
            AUTHORITY.configured_tracker_adapter(self.pm_config, "GitHubIssues")

        self.assertEqual(
            AUTHORITY.configured_ignored_labels(
                self.automation_config, '["human-work","manual-only"]'
            ),
            ("human-work", "manual-only"),
        )
        with self.assertRaisesRegex(AuthorityConfigError, "exactly repeat"):
            AUTHORITY.configured_ignored_labels(
                self.automation_config, '["human-work"]'
            )

    def test_policy_sources_accept_only_bundled_or_protected_external_files(self) -> None:
        external = self.root / "protected-policy"
        external.mkdir(mode=0o700)
        external_config = external / "automation.json"
        external_config.write_text(
            json.dumps({"ignoredTaskLabels": ["manual-only"]}),
            encoding="utf-8",
        )
        external_config.chmod(0o600)

        self.assertEqual(
            AUTHORITY.resolve_policy_source(
                self.automation_config,
                self.repository,
                self.skill,
                label="automation config",
            ),
            self.automation_config,
        )
        self.assertEqual(
            AUTHORITY.resolve_policy_source(
                self.automation_config,
                self.repository,
                self.skill,
                str(external_config),
                label="automation config",
            ),
            external_config,
        )

        repository_config = self.repository / "automation.json"
        repository_config.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(AuthorityConfigError, "disjoint from the repository"):
            AUTHORITY.resolve_policy_source(
                self.automation_config,
                self.repository,
                self.skill,
                str(repository_config),
                label="automation config",
            )

        other_skill_config = self.skill / "other-automation.json"
        other_skill_config.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(AuthorityConfigError, "disjoint from the installed skill"):
            AUTHORITY.resolve_policy_source(
                self.automation_config,
                self.repository,
                self.skill,
                str(other_skill_config),
                label="automation config",
            )

        external_config.chmod(0o666)
        with self.assertRaisesRegex(AuthorityConfigError, "not group/world-writable"):
            AUTHORITY.resolve_policy_source(
                self.automation_config,
                self.repository,
                self.skill,
                str(external_config),
                label="automation config",
            )

    def test_policy_source_rejects_shared_temporary_paths(self) -> None:
        shared = Path("/tmp") / f"sf-policy-source-{os.getpid()}.json"
        try:
            shared.write_text("{}\n", encoding="utf-8")
            shared.chmod(0o600)
            with self.assertRaisesRegex(AuthorityConfigError, "shared temporary"):
                AUTHORITY.resolve_policy_source(
                    self.automation_config,
                    self.repository,
                    self.skill,
                    str(shared),
                    label="automation config",
                )
        finally:
            shared.unlink(missing_ok=True)

    def test_runtime_path_filters_unavailable_and_untrusted_entries(self) -> None:
        repository_bin = self.repository / "bin"
        repository_bin.mkdir()
        shared_bin = Path("/tmp") / f"sf-authority-path-{os.getpid()}"
        missing = self.root / "missing"
        cryptex = Path(
            "/var/run/com.apple.security.cryptexd/codex.system/bootstrap/usr/local/bin"
        )
        value = ":".join(
            str(path)
            for path in (repository_bin, shared_bin, missing, cryptex, Path("/usr/bin"))
        )
        resolved = AUTHORITY.validated_runtime_path(
            value, self.repository, self.skill
        ).split(":")
        self.assertIn(str(Path("/usr/bin").resolve()), resolved)
        self.assertNotIn(str(repository_bin), resolved)
        self.assertNotIn(str(shared_bin), resolved)
        self.assertNotIn(str(missing), resolved)
        if not cryptex.exists():
            self.assertNotIn(str(cryptex), resolved)

    def test_runtime_path_fails_only_when_no_safe_entry_remains(self) -> None:
        with self.assertRaisesRegex(AuthorityConfigError, "no root-owned"):
            AUTHORITY.validated_runtime_path(
                str(self.repository / "missing"), self.repository, self.skill
            )
        self.assertEqual(
            AUTHORITY.validated_runtime_path(
                "relative/bin::/usr/bin", self.repository, self.skill
            ),
            str(Path("/usr/bin").resolve()),
        )

    def test_runtime_path_rejects_user_owned_0700_directory(self) -> None:
        hostile = self.root / "operator-owned-bin"
        hostile.mkdir(mode=0o700)
        (hostile / "git").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (hostile / "git").chmod(0o700)

        resolved = AUTHORITY.validated_runtime_path(
            f"{hostile}:/usr/bin", self.repository, self.skill
        ).split(":")
        self.assertNotIn(str(hostile), resolved)
        self.assertEqual(resolved, [str(Path("/usr/bin").resolve())])
        with self.assertRaisesRegex(AuthorityConfigError, "agent-immutable"):
            AUTHORITY.validated_runtime_path(
                str(hostile), self.repository, self.skill
            )

    def test_config_files_fail_closed_on_duplicate_authority(self) -> None:
        self.team_config.write_text(
            f'BROKER_LIFECYCLE_ROOT="{self.lifecycle}"\n'
            f'BROKER_LIFECYCLE_ROOT="{self.lifecycle}"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AuthorityConfigError, "duplicate configuration key"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config, self.repository, self.skill, required=True
            )

    def test_malformed_unrelated_command_fails_whole_authority_file_closed(self) -> None:
        self.team_config.write_text(
            'FRONTEND_CMD="tool --prompt "$(cat {prompt_file})""\n'
            f'BROKER_LIFECYCLE_ROOT="{self.lifecycle}" # protected store\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AuthorityConfigError, "FRONTEND_CMD"):
            AUTHORITY.configured_lifecycle_root(
                self.team_config, self.repository, self.skill, required=True
            )


if __name__ == "__main__":
    unittest.main()
