#!/usr/bin/env python3
"""Exercise runner selection, isolation, failure reporting, and CI summaries."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests/run-all.sh"
SHARDS = ("dispatch", "launcher", "parallel-integration", "task-runtime", "deployment", "core")
NODE_TEST = "extensions/evidence-providers/playwright/provider.test.mjs"
RESULT = re.compile(
    r"^TEST_RESULT test=(\S+) elapsed_seconds=(\d+) exit_status=(\d+) outcome=(\w+)$",
    re.MULTILINE,
)


class TestRunnerContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-test-runner-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)
        self.runner = self.fixture / "tests/run-all.sh"
        self.runner.parent.mkdir()
        shutil.copy2(RUNNER, self.runner)

    def invoke(self, *arguments: str, fixture: bool = False, environment: dict[str, str] | None = None):
        env = dict(os.environ)
        # Child fixture tests must never append fake results to the outer CI job.
        env.pop("GITHUB_STEP_SUMMARY", None)
        if environment:
            env.update(environment)
        return subprocess.run(
            ["/bin/bash", str(self.runner if fixture else RUNNER), *arguments],
            capture_output=True, text=True, env=env, check=False,
        )

    def selected(self, *arguments: str) -> list[str]:
        result = self.invoke(*arguments, "--list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout.splitlines()

    def write(self, relative: str, source: str) -> Path:
        path = self.fixture / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)
        return path

    def results(self, output: str):
        return {name: (int(seconds), int(status), outcome)
                for name, seconds, status, outcome in RESULT.findall(output)}

    def test_full_inventory_covers_all_test_files_once_and_shards_partition_it(self) -> None:
        full = self.selected()
        self.assertEqual(full, self.selected("--full"))
        self.assertEqual(len(full), len(set(full)))
        expected = {str(path.relative_to(ROOT))
                    for pattern in ("*-test.py", "*-test.sh")
                    for path in (ROOT / "tests").glob(pattern)} | {NODE_TEST}
        self.assertEqual(set(full), expected)
        partition: list[str] = []
        for shard in SHARDS:
            selection = self.selected("--shard", shard)
            self.assertTrue(selection, shard)
            if shard != "core":
                self.assertEqual(selection, [f"tests/{shard}-test.sh"])
            partition.extend(selection)
        self.assertEqual(len(partition), len(set(partition)))
        self.assertEqual(set(partition), set(full))
        self.assertEqual(full.count("tests/heartbeat-status-test.py"), 1)

    def test_smoke_preserves_legacy_subset_without_duplicate_heartbeat(self) -> None:
        smoke = self.selected("--smoke")
        full = set(self.selected())
        full_only = {
            "tests/release-lifecycle-test.py", "tests/custom-tracker-release-snapshot-test.py",
            "tests/task-runtime-test.sh", "tests/parallel-integration-test.sh",
            "tests/dispatch-test.sh", "tests/launcher-test.sh", "tests/pm-monitor-test.sh",
            "tests/deployment-test.sh", NODE_TEST,
        }
        self.assertEqual(set(smoke), full - full_only)
        self.assertEqual(len(smoke), len(set(smoke)))
        self.assertIn("tests/test-runner-test.py", smoke)
        self.assertEqual(smoke, self.selected("--smoke", "--shard", "core"))

    def test_unknown_duplicate_and_empty_selections_fail_before_execution(self) -> None:
        invalid = (
            ("--unknown",), ("extra",), ("--shard",), ("--shard", ""),
            ("--shard", "unknown"), ("--full", "--smoke"), ("--full", "--full"),
            ("--list", "--list"), ("--shard", "core", "--shard", "core"),
            ("--help", "--unknown"), ("--smoke", "--shard", "dispatch"),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("run-all.sh:", result.stderr)
                self.assertNotIn("==>", result.stdout)

    def test_inventory_validation_rejects_duplicate_test_and_missing_shard(self) -> None:
        source = self.runner.read_text()
        row = '  "python|tests/test-runner-test.py|smoke|core"'
        self.runner.write_text(source.replace(row, row + "\n" + row))
        result = self.invoke("--list", fixture=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate inventory test", result.stderr)
        self.runner.write_text(source.replace("|full|deployment\"", "|full|core\""))
        result = self.invoke("--list", fixture=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("no tests for shard: deployment", result.stderr)

    def test_success_reports_real_elapsed_time_without_optional_summary(self) -> None:
        self.write("tests/dispatch-test.sh", "#!/bin/sh\necho child-success\n/bin/sleep 1\n")
        result = self.invoke("--shard", "dispatch", fixture=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        seconds, status, outcome = self.results(result.stdout)["tests/dispatch-test.sh"]
        self.assertGreaterEqual(seconds, 1)
        self.assertEqual((status, outcome), (0, "passed"))
        self.assertIn("child-success", result.stdout)
        self.assertIn("ALL TESTS PASS", result.stdout)

    def test_failure_preserves_child_status_in_output_and_ci_summary(self) -> None:
        self.write("tests/dispatch-test.sh", "#!/bin/sh\necho child-failure\nexit 124\n")
        summary = self.fixture / "summary.md"
        result = self.invoke("--shard", "dispatch", fixture=True,
                             environment={"GITHUB_STEP_SUMMARY": str(summary)})
        self.assertEqual(result.returncode, 1, result.stderr)
        seconds, status, outcome = self.results(result.stdout)["tests/dispatch-test.sh"]
        self.assertEqual((status, outcome), (124, "failed"))
        self.assertIn(f"| `tests/dispatch-test.sh` | {seconds} | 124 | failed |", summary.read_text())
        self.assertIn("1 TEST(S) FAILED", result.stdout)

    def test_missing_test_has_nonzero_timing_record_and_summary(self) -> None:
        summary = self.fixture / "summary.md"
        result = self.invoke("--shard", "dispatch", fixture=True,
                             environment={"GITHUB_STEP_SUMMARY": str(summary)})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.results(result.stdout)["tests/dispatch-test.sh"][1:], (127, "missing"))
        self.assertIn("| 127 | missing |", summary.read_text())

    def stub_core(self, *, node_status: int | None = None) -> dict[str, str]:
        for test in self.selected("--shard", "core"):
            self.write(test, "# fixture contents; runner stubs prevent real execution\n")
        fake_bin = self.fixture / "fake-bin"
        fake_bin.mkdir()
        (fake_bin / "dirname").symlink_to("/usr/bin/dirname")
        self.write("fake-bin/python3", """#!/bin/sh
printf 'python:%s\n' "${1##*/}" >> "$RUNNER_CALLS"
case "$1" in *config-values-test.py) exit 3 ;; esac
""")
        self.write("fake-bin/bash", """#!/bin/sh
printf 'shell:%s:%s\n' "${1##*/}" "$TEAM_RUNNER" >> "$RUNNER_CALLS"
""")
        if node_status is not None:
            self.write("fake-bin/node", f"""#!/bin/sh
printf 'node:%s:%s\n' "$1" "${{2##*/}}" >> "$RUNNER_CALLS"
exit {node_status}
""")
        return {"PATH": str(fake_bin), "RUNNER_CALLS": str(self.fixture / "calls")}

    def test_core_continues_after_failure_and_reports_optional_node_skip(self) -> None:
        environment = self.stub_core()
        result = self.invoke("--shard", "core", fixture=True, environment=environment)
        self.assertEqual(result.returncode, 1, result.stderr)
        records = self.results(result.stdout)
        self.assertEqual(set(records), set(self.selected("--shard", "core")))
        self.assertEqual(records["tests/config-values-test.py"][1:], (3, "failed"))
        self.assertEqual(records[NODE_TEST][1:], (0, "skipped"))
        calls = (self.fixture / "calls").read_text()
        self.assertIn("shell:pm-monitor-test.sh:background", calls)
        self.assertIn("python:tracker-change-token-test.py", calls)

    def test_node_failure_and_missing_optional_file_are_reported(self) -> None:
        environment = self.stub_core(node_status=7)
        result = self.invoke("--shard", "core", fixture=True, environment=environment)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.results(result.stdout)[NODE_TEST][1:], (7, "failed"))
        self.assertIn("node:--test:provider.test.mjs", (self.fixture / "calls").read_text())
        (self.fixture / NODE_TEST).unlink()
        (self.fixture / "fake-bin/node").unlink()
        result = self.invoke("--shard", "core", fixture=True, environment=environment)
        self.assertEqual(self.results(result.stdout)[NODE_TEST][1:], (127, "missing"))


if __name__ == "__main__":
    unittest.main()
