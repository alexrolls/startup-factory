#!/usr/bin/env python3
"""Adversarial tests for exact-commit, fail-closed beta readiness."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "bin" / "beta-readiness.py"
NOW = "2026-09-19T12:00:00Z"
OBSERVED = "2026-09-18T12:00:00Z"
PACKAGE_DIGEST = "a" * 64
WHEEL_DIGEST = "b" * 64
SDIST_DIGEST = "c" * 64
BUNDLE_NAME = "startup-factory-0.2.0.tar.gz"
WHEEL_NAME = "startup_factory-0.2.0-py3-none-any.whl"
SDIST_NAME = "startup_factory-0.2.0.tar.gz"
FIXTURE_COMMIT = "d" * 40
FIXTURE_TASK = "governed-doc-change-v1"
FIXTURE_PACK = "tracker-markdown"
FIXTURE_PACK_DIGEST = "e" * 64
FIXTURE_ENVIRONMENT_DIGEST = "f" * 64

DOCUMENTS = (
    "pyproject.toml",
    "SECURITY.md",
    "reference/quickstart.md",
    "reference/compatibility.md",
    "reference/governed-delivery-example.md",
    "reference/benchmarks.md",
    "reference/beta-readiness.md",
)
EVIDENCE_IDS = (
    "private-disclosure-channel",
    "full-validation",
    "reproducible-package",
    "independent-exact-package-review",
    "exact-candidate-compatibility",
    "governed-walkthrough-execution",
    "first-governed-delivery-under-15m",
    "runtime-usage-observability",
)
PRODUCER_ROLES = {
    "private-disclosure-channel": "release-owner",
    "full-validation": "qa-engineer",
    "reproducible-package": "integrator",
    "independent-exact-package-review": "review-board-recorder",
    "exact-candidate-compatibility": "compatibility-tester",
    "governed-walkthrough-execution": "walkthrough-operator",
    "first-governed-delivery-under-15m": "benchmark-operator",
    "runtime-usage-observability": "usage-recorder",
}


def _synthetic_provider_value(*parts: str) -> str:
    """Build scanner fixtures at runtime without embedding provider tokens in Git."""

    return "".join(parts)


def _load_checker_module():
    spec = importlib.util.spec_from_file_location("beta_readiness_under_test", CHECKER)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise AssertionError("cannot load beta-readiness checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER_MODULE = _load_checker_module()


def _metric(value: int | None, reason: str | None = None) -> dict[str, object]:
    return {"value": value, "unavailableReason": reason}


def _observation(value: str | None, reason: str | None = None) -> dict[str, object]:
    return {"value": value, "unavailableReason": reason}


def _release_set(
    *,
    version: str = "0.2.0",
    bundle_digest: str = PACKAGE_DIGEST,
    wheel_digest: str = WHEEL_DIGEST,
    sdist_digest: str = SDIST_DIGEST,
) -> dict[str, object]:
    manifest: dict[str, object] = {
        "schemaVersion": 1,
        "artifacts": [
            {
                "kind": "bundle",
                "name": f"startup-factory-{version}.tar.gz",
                "sha256": bundle_digest,
            },
            {
                "kind": "wheel",
                "name": f"startup_factory-{version}-py3-none-any.whl",
                "sha256": wheel_digest,
            },
            {
                "kind": "sdist",
                "name": f"startup_factory-{version}.tar.gz",
                "sha256": sdist_digest,
            },
        ],
    }
    raw = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {**manifest, "sha256": hashlib.sha256(raw).hexdigest()}


def _validation_checks() -> list[dict[str, object]]:
    return [
        {
            "id": check_id,
            "argv": list(argv),
            "requiredEnvironment": list(environment),
            "exitCode": 0,
            "testsPassed": 25,
            "testsFailed": 0,
            "testsSkipped": 0,
        }
        for check_id, argv, environment in CHECKER_MODULE.CANONICAL_VALIDATION_CHECKS
    ]


def _nearest_rank(values: list[int], percentile: int) -> int:
    values = sorted(values)
    rank = (percentile * len(values) + 99) // 100
    return values[rank - 1]


def _format_timestamp(value: dt.datetime) -> str:
    timespec = "milliseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _benchmark_run(run_id: str, duration: int, state: str) -> dict[str, object]:
    completed = dt.datetime.fromisoformat(OBSERVED.replace("Z", "+00:00"))
    started = completed - dt.timedelta(milliseconds=duration)
    base, remainder = divmod(duration, 4)
    phase_durations = [base + (1 if index < remainder else 0) for index in range(4)]
    cursor = started
    phase_timings: list[dict[str, object]] = []
    for name, phase_duration in zip(
        ("setup", "implementation-rework", "review", "integration"),
        phase_durations,
    ):
        phase_completed = cursor + dt.timedelta(milliseconds=phase_duration)
        phase_timings.append(
            {
                "phase": name,
                "startedAt": _format_timestamp(cursor),
                "completedAt": _format_timestamp(phase_completed),
                "durationMs": phase_duration,
            }
        )
        cursor = phase_completed
    phase_timings.append(
        {
            "phase": "total",
            "startedAt": _format_timestamp(started),
            "completedAt": _format_timestamp(completed),
            "durationMs": duration,
        }
    )
    return {
        "runId": run_id,
        "state": state,
        "startedAt": _format_timestamp(started),
        "completedAt": _format_timestamp(completed),
        "durationMs": duration,
        "phaseTimings": phase_timings,
        "status": "pass",
        "retryCount": 0,
        "rawEvidenceSha256": hashlib.sha256(run_id.encode("ascii")).hexdigest(),
        "failureReason": None,
    }


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="beta-readiness-test-")
        self.root = Path(self.temporary.name).resolve()
        self.git("init", "-q")
        self.git("config", "user.name", "Beta Test")
        self.git("config", "user.email", "beta@example.invalid")
        for relative in DOCUMENTS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / relative).read_bytes())
        self.commit("beta documents")

    def close(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout.strip()

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def _payload(self, criterion_id: str, observed_at: str) -> dict[str, object]:
        if criterion_id == "private-disclosure-channel":
            return {
                "channel": "github-private-vulnerability-reporting",
                "intakeVerified": True,
                "acknowledgementVerified": True,
                "secretFreeTest": True,
            }
        if criterion_id == "full-validation":
            return {
                "cleanCheckout": True,
                "checks": _validation_checks(),
                "releaseSet": _release_set(),
            }
        if criterion_id == "reproducible-package":
            return {
                "builds": [
                    {
                        "buildId": build_id,
                        "cleanCheckout": True,
                        "releaseSet": _release_set(),
                    }
                    for build_id in ("build-a", "build-b")
                ]
            }
        if criterion_id == "independent-exact-package-review":
            roles = (
                "principal-software-architect",
                "sceptical-architect",
                "senior-qa-engineer",
                "senior-security-engineer",
            )
            return {
                "releaseSet": _release_set(),
                "reviews": [
                    {
                        "role": role,
                        "identity": f"reviewer-{index}@example",
                        "decision": "approve",
                        "reviewedAt": observed_at,
                    }
                    for index, role in enumerate(roles, start=1)
                ],
            }
        if criterion_id == "exact-candidate-compatibility":
            release_set = _release_set()
            candidate = self.git("rev-parse", "HEAD")
            return {
                "releaseSet": release_set,
                "results": [
                    {
                        "environmentId": "linux-python-310",
                        "classification": "tested",
                        "candidateCommit": candidate,
                        "releaseSetSha256": release_set["sha256"],
                        "platform": "linux",
                        "operatingSystem": "Ubuntu 24.04 LTS",
                        "architecture": "x86_64",
                        "pythonVersion": "3.10.18",
                        "gitVersion": "2.43.0",
                        "bashVersion": "5.2.21",
                        "validationScope": "installed-release-smoke",
                        "observedAt": observed_at,
                        "exitCode": 0,
                        "testsPassed": 12,
                        "testsFailed": 0,
                        "testsSkipped": 0,
                        "environmentManifestSha256": "1" * 64,
                        "rawEvidenceSha256": "2" * 64,
                    },
                    {
                        "environmentId": "linux-python-314",
                        "classification": "tested",
                        "candidateCommit": candidate,
                        "releaseSetSha256": release_set["sha256"],
                        "platform": "linux",
                        "operatingSystem": "Ubuntu 24.04 LTS",
                        "architecture": "x86_64",
                        "pythonVersion": "3.14.0",
                        "gitVersion": "2.43.0",
                        "bashVersion": "5.2.21",
                        "validationScope": "full-runtime-package",
                        "observedAt": observed_at,
                        "exitCode": 0,
                        "testsPassed": 60,
                        "testsFailed": 0,
                        "testsSkipped": 1,
                        "environmentManifestSha256": "3" * 64,
                        "rawEvidenceSha256": "4" * 64,
                    },
                ],
            }
        if criterion_id == "governed-walkthrough-execution":
            completed = dt.datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
            started = completed - dt.timedelta(minutes=10)
            return {
                "releaseSet": _release_set(),
                "candidateCommit": self.git("rev-parse", "HEAD"),
                "fixture": {
                    "fixtureCommit": FIXTURE_COMMIT,
                    "taskId": FIXTURE_TASK,
                    "changedFiles": ["README.md"],
                    "environmentManifestSha256": FIXTURE_ENVIRONMENT_DIGEST,
                },
                "profileDecision": {
                    "profile": "micro",
                    "decisionSha256": "5" * 64,
                    "changedFiles": ["README.md"],
                    "reviewGates": [],
                    "exactPackageRequired": True,
                    "coreReviewRequired": True,
                },
                "selectedPack": {
                    "packId": FIXTURE_PACK,
                    "packSha256": FIXTURE_PACK_DIGEST,
                    "planSha256": "6" * 64,
                    "validationStatus": "pass",
                    "doctorConfiguredStatus": "configured",
                    "doctorProofStatus": "unknown",
                },
                "reviewOutcome": {
                    "status": "approved",
                    "reviewReceiptSchemaVersion": 2,
                    "reviewEvidenceSchemaVersion": 8,
                    "reviewPackageSha256": "7" * 64,
                    "approvalEvidenceSha256": "8" * 64,
                    "publicationReceipts": {
                        "review-request": "9" * 64,
                        "team-lead-approval": "a" * 64,
                        "architecture-approval": "b" * 64,
                        "sceptical-architecture-approval": "c" * 64,
                    },
                },
                "integrationOutcome": {
                    "status": "completed",
                    "transactionSchemaVersion": 2,
                    "transactionId": "integration-" + "d" * 32,
                    "commit": "e" * 40,
                    "reviewPackageSha256": "7" * 64,
                    "approvalEvidenceSha256": "8" * 64,
                    "transactionSha256": "d" * 64,
                },
                "authority": {
                    "releaseEnabled": False,
                    "deploymentEnabled": False,
                    "releaseAttempted": False,
                    "deploymentAttempted": False,
                },
                "startedAt": _format_timestamp(started),
                "completedAt": _format_timestamp(completed),
                "durationMs": 600_000,
                "rawEvidenceSha256": "0" * 64,
            }
        if criterion_id == "first-governed-delivery-under-15m":
            cold = [600_000, 650_000, 700_000, 720_000, 750_000]
            warm = [300_000, 320_000, 330_000, 350_000, 370_000]
            return {
                "releaseSet": _release_set(),
                "fixture": {
                    "fixtureCommit": FIXTURE_COMMIT,
                    "taskId": FIXTURE_TASK,
                    "packId": FIXTURE_PACK,
                    "packSha256": FIXTURE_PACK_DIGEST,
                    "environmentManifestSha256": FIXTURE_ENVIRONMENT_DIGEST,
                },
                "allAttemptsRecorded": True,
                "percentileMethod": "nearest-rank",
                "targetMs": 900_000,
                "coldRuns": [
                    _benchmark_run(f"cold-{index}", duration, "cold")
                    for index, duration in enumerate(cold, start=1)
                ],
                "warmRuns": [
                    _benchmark_run(f"warm-{index}", duration, "warm")
                    for index, duration in enumerate(warm, start=1)
                ],
                "failures": [],
                "coldP50Ms": _nearest_rank(cold, 50),
                "coldP95Ms": _nearest_rank(cold, 95),
                "warmP50Ms": _nearest_rank(warm, 50),
                "warmP95Ms": _nearest_rank(warm, 95),
            }
        if criterion_id == "runtime-usage-observability":
            def usage_record(run_id: str, agent_id: str) -> dict[str, object]:
                return {
                    "agentRunId": run_id,
                    "agentId": agent_id,
                    "runtime": "codex",
                    "model": "recorded-model",
                    "provider": _observation("OpenAI"),
                    "wallTimeMs": _metric(456_000),
                    "inputTokens": _metric(12_345),
                    "outputTokens": _metric(2_345),
                    "cacheTokens": _metric(
                        None, "Runtime did not expose cache tokens."
                    ),
                    "providerCostMicros": _metric(
                        None, "Runtime did not expose provider cost."
                    ),
                    "currency": None,
                    "pricingDate": _observation(
                        None, "Provider cost and pricing were not exposed."
                    ),
                    "costCalculation": _observation(
                        None, "No calculation was made without provider cost."
                    ),
                }

            return {
                "releaseSet": _release_set(),
                "coverage": {
                    "allAgentRunsRecorded": True,
                    "fixtureCommit": FIXTURE_COMMIT,
                    "taskId": FIXTURE_TASK,
                    "packId": FIXTURE_PACK,
                    "packSha256": FIXTURE_PACK_DIGEST,
                    "environmentManifestSha256": FIXTURE_ENVIRONMENT_DIGEST,
                    "expectedAgentRunIds": [
                        "implementation-run-1",
                        "review-run-1",
                    ],
                },
                "records": [
                    usage_record(
                        "implementation-run-1", "implementation-agent@example"
                    ),
                    usage_record("review-run-1", "review-agent@example"),
                ],
            }
        raise AssertionError(criterion_id)

    def write_pass_evidence(
        self,
        *,
        observed_at: str = OBSERVED,
        generated_at: str = OBSERVED,
    ) -> Path:
        evidence_dir = self.root / ".startup-factory"
        artifacts = evidence_dir / "beta-evidence"
        artifacts.mkdir(parents=True, exist_ok=True)
        candidate = self.git("rev-parse", "HEAD")
        entries: list[dict[str, object]] = []
        for index, criterion_id in enumerate(EVIDENCE_IDS, start=1):
            relative = f".startup-factory/beta-evidence/{criterion_id}.json"
            artifact = {
                "schemaVersion": 1,
                "artifactId": f"artifact-{index}-{criterion_id}",
                "criterionId": criterion_id,
                "candidateCommit": candidate,
                "observedAt": observed_at,
                "producer": {
                    "identity": f"producer-{index}@example",
                    "role": PRODUCER_ROLES[criterion_id],
                },
                "payload": self._payload(criterion_id, observed_at),
            }
            raw = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            (self.root / relative).write_bytes(raw)
            entries.append(
                {
                    "id": criterion_id,
                    "status": "pass",
                    "observedAt": observed_at,
                    "evidencePath": relative,
                    "evidenceSha256": hashlib.sha256(raw).hexdigest(),
                    "detail": f"Validated {criterion_id} evidence record.",
                }
            )
        value = {
            "schemaVersion": 1,
            "candidateCommit": candidate,
            "generatedAt": generated_at,
            "criteria": entries,
        }
        path = evidence_dir / "beta-readiness-evidence.json"
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        return path

    def mutate_artifact(self, evidence_path: Path, criterion_id: str, mutation) -> None:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        entry = next(
            item for item in evidence["criteria"] if item["id"] == criterion_id
        )
        artifact_path = self.root / entry["evidencePath"]
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        mutation(artifact)
        raw = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        artifact_path.write_bytes(raw)
        entry["evidenceSha256"] = hashlib.sha256(raw).hexdigest()
        evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")


class BetaReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def run_checker(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(CHECKER),
                "--project",
                str(self.fixture.root),
                "--at",
                NOW,
                "--json",
                *extra,
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_documented_repository_is_not_ready_without_external_evidence(self) -> None:
        result = self.run_checker()
        self.assertEqual(1, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["ready"])
        self.assertIsNone(report["releaseSetSha256"])
        documents = [item for item in report["criteria"] if item["kind"] == "document"]
        evidence = [item for item in report["criteria"] if item["kind"] == "evidence"]
        self.assertTrue(all(item["status"] == "pass" for item in documents))
        self.assertTrue(all(item["status"] == "unknown" for item in evidence))

    def test_reference_docs_pin_prerequisites_and_two_root_boundaries(self) -> None:
        quickstart = (ROOT / "reference/quickstart.md").read_text(encoding="utf-8")
        walkthrough = (ROOT / "reference/governed-delivery-example.md").read_text(
            encoding="utf-8"
        )
        benchmarks = (ROOT / "reference/benchmarks.md").read_text(encoding="utf-8")
        compatibility = (ROOT / "reference/compatibility.md").read_text(
            encoding="utf-8"
        )
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        quickstart_words = " ".join(quickstart.split())
        walkthrough_words = " ".join(walkthrough.split())
        self.assertIn("uvx --version", quickstart)
        self.assertIn(
            ".agents/skills/startup-factory/config/project-management.config.md",
            quickstart,
        )
        self.assertIn("never writes the host", quickstart)
        self.assertIn("does not ship an OS sandbox runner", quickstart_words)
        self.assertIn("unproven beta criterion", quickstart_words)
        for boundary_key in (
            "TRACKER_WRITERS=broker",
            "AGENT_SANDBOX_RUNNER=",
            "AGENT_SANDBOX_ENFORCED=true",
            "BROKER_LIFECYCLE_ROOT=",
        ):
            self.assertIn(boundary_key, quickstart)
            self.assertIn(boundary_key, walkthrough)
        self.assertIn(
            "manual/unauthenticated launch cannot produce the authenticated review",
            walkthrough_words,
        )
        for pin in (
            "build==1.3.0",
            "packaging==26.2",
            "pyproject-hooks==1.2.0",
            "setuptools==83.0.0",
            "wheel==0.47.0",
        ):
            self.assertIn(pin, walkthrough)
        self.assertIn("SOURCE_DATE_EPOCH", walkthrough)
        self.assertIn("never\nwrites a host-repository `config/` path", walkthrough)
        self.assertIn("contains no execution result", walkthrough)
        self.assertIn("authenticated review", walkthrough)
        self.assertIn("contains no benchmark result", benchmarks)
        for phase in (
            "`setup`",
            "`implementation-rework`",
            "`review`",
            "`integration`",
            "`total`",
        ):
            self.assertIn(phase, benchmarks)
        self.assertIn("contains no exact-candidate run result", compatibility)
        for classification in ("Claimed", "Tested", "Experimental", "Untested"):
            self.assertIn(classification, compatibility)
        self.assertIn("| Ubuntu Linux | Claimed | Untested |", compatibility)
        self.assertNotIn("| Ubuntu Linux | Tested |", compatibility)
        self.assertIn(
            "| Windows Subsystem for Linux (WSL) | Experimental | Untested |",
            compatibility,
        )
        self.assertIn("required typed Linux evidence excludes WSL", compatibility)
        self.assertIn(
            "3.15 and newer are unclaimed, Untested, and outside beta support",
            compatibility,
        )
        self.assertNotIn("Python 3.10 or newer", quickstart)
        self.assertNotIn("Python 3.10 or newer", walkthrough)
        self.assertIn(
            "Published-beta channel contract: available only after "
            "exact-candidate protected verification",
            security,
        )
        self.assertIn("available for a published beta only", security)
        self.assertIn(
            "Unreleased-candidate status: current channel availability is not "
            "asserted",
            security,
        )
        self.assertNotIn(
            "Current channel status: unavailable until verified", security
        )
        self.assertIn("## Safe harbor", security)

    def test_complete_strict_exact_commit_evidence_is_ready_and_deterministic(
        self,
    ) -> None:
        self.fixture.write_pass_evidence()
        first = self.run_checker()
        second = self.run_checker()
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        self.assertTrue(report["ready"])
        self.assertEqual("0.2.0", report["candidateVersion"])
        self.assertEqual(_release_set()["sha256"], report["releaseSetSha256"])
        self.assertTrue(all(item["status"] == "pass" for item in report["criteria"]))
        statuses = {
            (item["kind"], item["id"]): item["status"]
            for item in report["criteria"]
        }
        self.assertEqual("pass", statuses[("document", "security-policy")])
        self.assertEqual(
            "pass", statuses[("evidence", "private-disclosure-channel")]
        )

    def test_stale_permanent_unavailable_policy_blocks_complete_evidence(
        self,
    ) -> None:
        security = self.fixture.root / "SECURITY.md"
        security.write_text(
            security.read_text(encoding="utf-8")
            + "\n**Current channel status: unavailable until verified.**\n",
            encoding="utf-8",
        )
        self.fixture.commit("restore stale permanent-unavailable disclosure status")
        self.fixture.write_pass_evidence()

        result = self.run_checker()
        self.assertEqual(1, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["ready"])
        criteria = {
            (item["kind"], item["id"]): item for item in report["criteria"]
        }
        self.assertEqual(
            "fail", criteria[("document", "security-policy")]["status"]
        )
        self.assertIn(
            "obsolete or missing required content",
            criteria[("document", "security-policy")]["message"],
        )
        self.assertEqual(
            "pass", criteria[("evidence", "private-disclosure-channel")]["status"]
        )

    def test_arbitrary_assertion_and_artifact_reuse_cannot_make_ready(self) -> None:
        path = self.fixture.write_pass_evidence()
        evidence = json.loads(path.read_text(encoding="utf-8"))
        first = evidence["criteria"][0]
        assertion = self.fixture.root / first["evidencePath"]
        assertion.write_text("I assert everything passed.\n", encoding="utf-8")
        first["evidenceSha256"] = hashlib.sha256(assertion.read_bytes()).hexdigest()
        path.write_text(json.dumps(evidence), encoding="utf-8")
        arbitrary = self.run_checker()
        self.assertEqual(2, arbitrary.returncode)
        self.assertIn("strict bounded", arbitrary.stderr)

        other = Fixture()
        try:
            other_path = other.write_pass_evidence()
            reused = json.loads(other_path.read_text(encoding="utf-8"))
            reused["criteria"][1]["evidencePath"] = reused["criteria"][0][
                "evidencePath"
            ]
            reused["criteria"][1]["evidenceSha256"] = reused["criteria"][0][
                "evidenceSha256"
            ]
            other_path.write_text(json.dumps(reused), encoding="utf-8")
            result = subprocess.run(
                [
                    "python3",
                    str(CHECKER),
                    "--project",
                    str(other.root),
                    "--at",
                    NOW,
                    "--json",
                ],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("reuse an artifact path", result.stderr)
        finally:
            other.close()

    def test_documents_are_read_from_exact_git_blobs_not_worktree(self) -> None:
        quickstart = self.fixture.root / "reference" / "quickstart.md"
        quickstart.write_text("mutable worktree replacement\n", encoding="utf-8")
        unchanged = self.run_checker()
        report = json.loads(unchanged.stdout)
        status = {item["id"]: item["status"] for item in report["criteria"]}
        self.assertEqual("pass", status["quickstart"])

        self.fixture.git("rm", "-f", "reference/quickstart.md")
        self.fixture.commit("remove committed quickstart")
        quickstart.parent.mkdir(exist_ok=True)
        quickstart.write_bytes((ROOT / "reference/quickstart.md").read_bytes())
        absent_from_head = self.run_checker()
        report = json.loads(absent_from_head.stdout)
        status = {item["id"]: item["status"] for item in report["criteria"]}
        self.assertEqual("fail", status["quickstart"])

    def test_committed_document_symlink_is_not_a_document(self) -> None:
        quickstart = self.fixture.root / "reference" / "quickstart.md"
        quickstart.unlink()
        quickstart.symlink_to("# Quickstart\n15 minutes\ndoctor")
        self.fixture.commit("replace quickstart with a marker-bearing symlink")

        result = self.run_checker()
        self.assertEqual(1, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        quickstart_result = next(
            item for item in report["criteria"] if item["id"] == "quickstart"
        )
        self.assertEqual("fail", quickstart_result["status"])
        self.assertIn("regular Git file", quickstart_result["message"])

    def test_commit_mismatch_and_head_change_fail_closed(self) -> None:
        path = self.fixture.write_pass_evidence()
        value = json.loads(path.read_text(encoding="utf-8"))
        value["candidateCommit"] = "0" * 40
        path.write_text(json.dumps(value), encoding="utf-8")
        mismatch = self.run_checker()
        self.assertEqual(2, mismatch.returncode)
        self.assertIn("does not match", mismatch.stderr)

        path.unlink()
        now = CHECKER_MODULE._parse_timestamp(NOW, label="now")
        actual = self.fixture.git("rev-parse", "HEAD")
        with mock.patch.object(
            CHECKER_MODULE, "_head_commit", side_effect=[actual, "f" * 40]
        ):
            with self.assertRaisesRegex(
                CHECKER_MODULE.BetaReadinessError, "HEAD changed"
            ):
                CHECKER_MODULE.evaluate(self.fixture.root, now=now)

    def test_stale_future_and_incoherent_timestamps_fail_closed(self) -> None:
        old = Fixture()
        try:
            old.write_pass_evidence(
                observed_at="2026-08-01T12:00:00Z",
                generated_at="2026-08-01T12:00:00Z",
            )
            result = subprocess.run(
                [
                    "python3",
                    str(CHECKER),
                    "--project",
                    str(old.root),
                    "--at",
                    NOW,
                    "--json",
                ],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertIn("generatedAt is older", result.stderr)
        finally:
            old.close()

        path = self.fixture.write_pass_evidence(
            observed_at="2026-09-18T12:00:01Z", generated_at="2026-09-18T12:00:00Z"
        )
        incoherent = self.run_checker()
        self.assertEqual(2, incoherent.returncode)
        self.assertIn("later than evidence generatedAt", incoherent.stderr)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["generatedAt"] = "2026-09-20T12:00:00Z"
        path.write_text(json.dumps(value), encoding="utf-8")
        future = self.run_checker()
        self.assertEqual(2, future.returncode)
        self.assertIn("future", future.stderr)

    def test_strict_json_types_constants_depth_and_paths(self) -> None:
        path = self.fixture.root / ".startup-factory" / "beta-readiness-evidence.json"
        path.parent.mkdir()
        candidate = self.fixture.git("rev-parse", "HEAD")
        base = {
            "schemaVersion": 1.0,
            "candidateCommit": candidate,
            "generatedAt": OBSERVED,
            "criteria": [],
        }
        path.write_text(json.dumps(base), encoding="utf-8")
        floating = self.run_checker()
        self.assertEqual(2, floating.returncode)
        self.assertIn("unsupported JSON value", floating.stderr)

        path.write_text(
            '{"schemaVersion":NaN,"candidateCommit":"'
            + candidate
            + '","generatedAt":"'
            + OBSERVED
            + '","criteria":[]}',
            encoding="utf-8",
        )
        non_finite = self.run_checker()
        self.assertEqual(2, non_finite.returncode)
        self.assertIn("non-finite", non_finite.stderr)

        secret_like = {
            "schemaVersion": 1,
            "candidateCommit": candidate,
            "generatedAt": OBSERVED,
            "criteria": [
                {
                    "id": "private-disclosure-channel",
                    "status": "unknown",
                    "observedAt": OBSERVED,
                    "evidencePath": None,
                    "evidenceSha256": None,
                    "detail": _synthetic_provider_value(
                        "token=gh", "p_", "abcdefghijklmnopqrstuvwxyz123456"
                    ),
                }
            ],
        }
        path.write_text(json.dumps(secret_like), encoding="utf-8")
        leaked = self.run_checker()
        self.assertEqual(2, leaked.returncode)
        self.assertIn("secret-like material", leaked.stderr)

        nested: dict[str, object] = {}
        cursor = nested
        for index in range(15):
            child: dict[str, object] = {}
            cursor[f"level{index}"] = child
            cursor = child
        deep = {
            "schemaVersion": 1,
            "candidateCommit": candidate,
            "generatedAt": OBSERVED,
            "criteria": [],
            "extra": nested,
        }
        path.write_text(json.dumps(deep), encoding="utf-8")
        depth = self.run_checker()
        self.assertEqual(2, depth.returncode)
        self.assertIn("nesting", depth.stderr)

        invalid_path = self.run_checker(
            "--evidence", ".startup-factory//beta-readiness-evidence.json"
        )
        self.assertEqual(2, invalid_path.returncode)
        self.assertIn("normalized", invalid_path.stderr)

        bad_type = {
            "schemaVersion": 1,
            "candidateCommit": candidate,
            "generatedAt": OBSERVED,
            "criteria": [
                {
                    "id": [],
                    "status": "unknown",
                    "observedAt": OBSERVED,
                    "evidencePath": None,
                    "evidenceSha256": None,
                    "detail": "Invalid ID type.",
                }
            ],
        }
        path.write_text(json.dumps(bad_type), encoding="utf-8")
        malformed = self.run_checker()
        self.assertEqual(2, malformed.returncode)
        self.assertNotIn("Traceback", malformed.stderr)
        self.assertIn("invalid id", malformed.stderr)

    def test_provider_tokens_in_evidence_detail_are_rejected_without_echo(self) -> None:
        path = self.fixture.root / ".startup-factory" / "beta-readiness-evidence.json"
        path.parent.mkdir()
        candidate = self.fixture.git("rev-parse", "HEAD")
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
            "shopify": _synthetic_provider_value("sh", "pca_", "a" * 32),
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
                evidence = {
                    "schemaVersion": 1,
                    "candidateCommit": candidate,
                    "generatedAt": OBSERVED,
                    "criteria": [
                        {
                            "id": "private-disclosure-channel",
                            "status": "unknown",
                            "observedAt": OBSERVED,
                            "evidencePath": None,
                            "evidenceSha256": None,
                            "detail": token,
                        }
                    ],
                }
                path.write_text(json.dumps(evidence), encoding="utf-8")
                result = self.run_checker()
                self.assertEqual(2, result.returncode)
                self.assertIn("secret-like material", result.stderr)
                self.assertNotIn(token, result.stderr)
                self.assertNotIn(token, result.stdout)

    def test_evidence_detail_is_validated_but_never_reflected_to_output(self) -> None:
        path = self.fixture.write_pass_evidence()
        evidence = json.loads(path.read_text(encoding="utf-8"))
        detail = (
            "operator-private-narrative-should-not-be-reflected; "
            "glpat-rotation-check; npm_publish_validation; sk_live_contract; "
            "Authorization: required; token: required; "
            "connection_string: documented; api_key: configured"
        )
        evidence["criteria"][0]["detail"] = detail
        path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")

        result = self.run_checker()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(detail, result.stdout)
        self.assertNotIn("operator-private-narrative", result.stdout)
        report = json.loads(result.stdout)
        criterion = next(
            item
            for item in report["criteria"]
            if item["id"] == "private-disclosure-channel"
        )
        self.assertEqual(
            "External evidence reported pass for this criterion.",
            criterion["message"],
        )

    def test_duplicate_keys_oversize_and_symlinks_are_rejected(self) -> None:
        evidence_dir = self.fixture.root / ".startup-factory"
        evidence_dir.mkdir()
        candidate = self.fixture.git("rev-parse", "HEAD")
        default = evidence_dir / "beta-readiness-evidence.json"
        default.write_text(
            '{"schemaVersion":1,"schemaVersion":1,"candidateCommit":"'
            + candidate
            + '","generatedAt":"'
            + OBSERVED
            + '","criteria":[]}',
            encoding="utf-8",
        )
        duplicate = self.run_checker()
        self.assertEqual(2, duplicate.returncode)
        self.assertIn("duplicate JSON key", duplicate.stderr)

        large = evidence_dir / "large.json"
        large.write_bytes(b" " * (128 * 1024 + 1))
        oversized = self.run_checker("--evidence", ".startup-factory/large.json")
        self.assertEqual(2, oversized.returncode)
        self.assertIn("exceeds", oversized.stderr)

        link = evidence_dir / "link.json"
        link.symlink_to(large.name)
        symlinked = self.run_checker("--evidence", ".startup-factory/link.json")
        self.assertEqual(2, symlinked.returncode)
        self.assertIn("cannot open evidence file", symlinked.stderr)

        outside = self.fixture.root / "outside"
        outside.mkdir()
        (outside / "evidence.json").write_text("{}", encoding="utf-8")
        parent_link = self.fixture.root / "linked-parent"
        parent_link.symlink_to(outside, target_is_directory=True)
        parent = self.run_checker("--evidence", "linked-parent/evidence.json")
        self.assertEqual(2, parent.returncode)
        self.assertIn("unsafe component", parent.stderr)

    def test_fifo_evidence_is_rejected_without_blocking(self) -> None:
        if not hasattr(os, "mkfifo") or not getattr(os, "O_NONBLOCK", 0):
            self.skipTest("secure FIFO regression requires POSIX nonblocking opens")
        evidence_dir = self.fixture.root / ".startup-factory"
        evidence_dir.mkdir()
        fifo = evidence_dir / "evidence.fifo"
        os.mkfifo(fifo)
        result = subprocess.run(
            [
                "python3",
                str(CHECKER),
                "--project",
                str(self.fixture.root),
                "--at",
                NOW,
                "--json",
                "--evidence",
                ".startup-factory/evidence.fifo",
            ],
            check=False,
            text=True,
            capture_output=True,
            timeout=2,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("not a stable regular file", result.stderr)

    def test_exact_candidate_reads_ignore_git_replacement_refs(self) -> None:
        original = self.fixture.git("rev-parse", "HEAD")
        quickstart = self.fixture.root / "reference" / "quickstart.md"
        quickstart.write_text(
            "replacement commit without required markers\n", encoding="utf-8"
        )
        self.fixture.git("add", "reference/quickstart.md")
        self.fixture.commit("replacement candidate")
        replacement = self.fixture.git("rev-parse", "HEAD")
        self.fixture.git("update-ref", "HEAD", original)
        self.fixture.git("replace", original, replacement)

        result = self.run_checker()
        self.assertEqual(1, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        statuses = {item["id"]: item["status"] for item in report["criteria"]}
        self.assertEqual("pass", statuses["quickstart"])

    def test_git_subprocess_isolated_bounded_and_deadline_limited(self) -> None:
        hostile_directory = self.fixture.root / "hostile-path"
        hostile_directory.mkdir()
        hostile_git = hostile_directory / "git"
        hostile_git.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        hostile_git.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(hostile_directory)}):
            resolved = CHECKER_MODULE._resolved_git_executable()
        self.assertNotEqual(
            None if resolved is None else Path(resolved).resolve(),
            hostile_git.resolve(),
        )

        environment_git = self.fixture.root / "environment-git"
        environment_git.write_text(
            "#!/bin/sh\n"
            "printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\\n' "
            '"$GIT_CONFIG_NOSYSTEM" "$GIT_NO_LAZY_FETCH" '
            '"$GIT_TERMINAL_PROMPT" "$GIT_NO_REPLACE_OBJECTS" '
            '"$GCM_INTERACTIVE" "$GIT_CONFIG_VALUE_0" '
            '"$GIT_PROTOCOL_FROM_USER" "${GIT_ALLOW_PROTOCOL+set}" '
            '"${BETA_PARENT_SECRET-unset}"\n',
            encoding="utf-8",
        )
        environment_git.chmod(0o755)
        with mock.patch.object(
            CHECKER_MODULE, "GIT_EXECUTABLE", str(environment_git)
        ), mock.patch.dict(os.environ, {"BETA_PARENT_SECRET": "must-not-leak"}):
            output = CHECKER_MODULE._git(
                self.fixture.root,
                ["ignored"],
                label="environment probe",
                stdout_limit=256,
            )
        self.assertEqual(b"1|1|0|1|Never|never|0|set|unset\n", output)

        provider_token = _synthetic_provider_value(
            "gl", "pat-", "0123456789abcdefghij"
        )
        failing_git = self.fixture.root / "failing-git"
        failing_git.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' {shlex.quote(provider_token)} >&2\n"
            "exit 9\n",
            encoding="utf-8",
        )
        failing_git.chmod(0o755)
        with mock.patch.object(CHECKER_MODULE, "GIT_EXECUTABLE", str(failing_git)):
            with self.assertRaisesRegex(
                CHECKER_MODULE.BetaReadinessError,
                "cannot read failing Git probe from exact candidate",
            ) as raised:
                CHECKER_MODULE._git(
                    self.fixture.root,
                    ["ignored"],
                    label="failing Git probe",
                    stdout_limit=128,
                )
        self.assertNotIn(provider_token, str(raised.exception))

        noisy_git = self.fixture.root / "noisy-git"
        noisy_git.write_text(
            "#!/bin/sh\nwhile :; do printf '0123456789abcdef'; done\n",
            encoding="utf-8",
        )
        noisy_git.chmod(0o755)
        started = time.monotonic()
        with mock.patch.object(CHECKER_MODULE, "GIT_EXECUTABLE", str(noisy_git)):
            with self.assertRaisesRegex(
                CHECKER_MODULE.BetaReadinessError, "stdout exceeds 1024 bytes"
            ):
                CHECKER_MODULE._git(
                    self.fixture.root,
                    ["ignored"],
                    label="bounded probe",
                    timeout=2,
                    stdout_limit=1024,
                )
        self.assertLess(time.monotonic() - started, 2)

        hanging_git = self.fixture.root / "hanging-git"
        child_pid_file = self.fixture.root / "hanging-child.pid"
        hanging_git.write_text(
            "#!/bin/sh\n"
            "sleep 30 &\n"
            f"printf '%s\\n' \"$!\" > {shlex.quote(str(child_pid_file))}\n"
            "wait\n",
            encoding="utf-8",
        )
        hanging_git.chmod(0o755)
        started = time.monotonic()
        with mock.patch.object(CHECKER_MODULE, "GIT_EXECUTABLE", str(hanging_git)):
            with self.assertRaisesRegex(
                CHECKER_MODULE.BetaReadinessError, "timed out"
            ):
                CHECKER_MODULE._git(
                    self.fixture.root,
                    ["ignored"],
                    label="deadline probe",
                    timeout=1,
                    stdout_limit=64,
                )
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(child_pid_file.is_file(), "deadline probe did not start")
        self.assertRegex(
            child_pid_file.read_text(encoding="ascii").strip(), r"^[1-9][0-9]*$"
        )

    def test_reader_detects_concurrent_file_mutation(self) -> None:
        target = self.fixture.root / "race.bin"
        target.write_bytes(b"a" * 100_000)
        original_read = CHECKER_MODULE.os.read
        changed = False

        def racing_read(descriptor: int, count: int) -> bytes:
            nonlocal changed
            result = original_read(descriptor, count)
            if result and not changed:
                changed = True
                with target.open("ab") as stream:
                    stream.write(b"x")
            return result

        with CHECKER_MODULE.SafeRepositoryReader(self.fixture.root) as reader:
            with mock.patch.object(CHECKER_MODULE.os, "read", side_effect=racing_read):
                with self.assertRaisesRegex(
                    CHECKER_MODULE.BetaReadinessError, "changed while it was read"
                ):
                    reader.read_regular("race.bin", limit=200_000, label="race")

    def test_validation_reproducibility_reviews_and_package_binding_are_mechanical(
        self,
    ) -> None:
        cases = (
            (
                "full-validation",
                lambda artifact: artifact["payload"]["checks"][0].__setitem__(
                    "exitCode", 1
                ),
                "exitCode",
            ),
            (
                "reproducible-package",
                lambda artifact: artifact["payload"]["builds"][1].__setitem__(
                    "releaseSet", _release_set(wheel_digest="d" * 64)
                ),
                "release sets differ between clean builds",
            ),
            (
                "independent-exact-package-review",
                lambda artifact: artifact["payload"]["reviews"][1].__setitem__(
                    "identity", artifact["payload"]["reviews"][0]["identity"]
                ),
                "distinct identities",
            ),
            (
                "runtime-usage-observability",
                lambda artifact: artifact["payload"].__setitem__(
                    "releaseSet", _release_set(wheel_digest="d" * 64)
                ),
                "does not bind the reproducible exact release set",
            ),
        )
        for criterion_id, mutation, expected in cases:
            with self.subTest(criterion=criterion_id):
                fixture = Fixture()
                try:
                    path = fixture.write_pass_evidence()
                    fixture.mutate_artifact(path, criterion_id, mutation)
                    result = subprocess.run(
                        [
                            "python3",
                            str(CHECKER),
                            "--project",
                            str(fixture.root),
                            "--at",
                            NOW,
                            "--json",
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn(expected, result.stderr)
                finally:
                    fixture.close()

    def test_release_set_and_complete_validation_contract_fail_closed(self) -> None:
        def replace_both_build_sets(artifact: dict[str, object]) -> None:
            changed = _release_set(
                wheel_digest="d" * 64,
                sdist_digest="e" * 64,
            )
            for build in artifact["payload"]["builds"]:  # type: ignore[index]
                build["releaseSet"] = changed

        cases = (
            (
                "reproducible-package",
                replace_both_build_sets,
                "does not bind the reproducible exact release set",
            ),
            (
                "full-validation",
                lambda artifact: artifact["payload"]["releaseSet"].__setitem__(
                    "sha256", "f" * 64
                ),
                "does not match its canonical manifest",
            ),
            (
                "full-validation",
                lambda artifact: artifact["payload"]["releaseSet"]["artifacts"][
                    1
                ].__setitem__(
                    "name", "startup_factory-0.3.0-py3-none-any.whl"
                ),
                "artifact versions must match",
            ),
            (
                "full-validation",
                lambda artifact: artifact["payload"].__setitem__(
                    "releaseSet", _release_set(version="0.3.0")
                ),
                "does not match exact candidate project.version 0.2.0",
            ),
            (
                "full-validation",
                lambda artifact: artifact["payload"].__setitem__(
                    "checks", artifact["payload"]["checks"][:2]
                ),
                "requires the runtime, packaging-source, and built-distribution checks",
            ),
            (
                "full-validation",
                lambda artifact: artifact["payload"]["checks"][2].__setitem__(
                    "requiredEnvironment", []
                ),
                "requiredEnvironment does not match",
            ),
        )
        for criterion_id, mutation, expected in cases:
            with self.subTest(expected=expected):
                fixture = Fixture()
                try:
                    path = fixture.write_pass_evidence()
                    fixture.mutate_artifact(path, criterion_id, mutation)
                    result = subprocess.run(
                        [
                            "python3",
                            str(CHECKER),
                            "--project",
                            str(fixture.root),
                            "--at",
                            NOW,
                            "--json",
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn(expected, result.stderr)
                finally:
                    fixture.close()

    def test_compatibility_evidence_is_typed_and_exact_candidate_bound(self) -> None:
        cases = (
            (
                lambda artifact: artifact["payload"]["results"][0].__setitem__(
                    "candidateCommit", "0" * 40
                ),
                "does not bind exact HEAD",
            ),
            (
                lambda artifact: artifact["payload"]["results"][0].__setitem__(
                    "releaseSetSha256", "0" * 64
                ),
                "does not bind the exact release set",
            ),
            (
                lambda artifact: artifact["payload"]["results"][0].__setitem__(
                    "classification", "experimental"
                ),
                "classification must be exactly tested",
            ),
            (
                lambda artifact: artifact["payload"]["results"][0].__setitem__(
                    "operatingSystem",
                    "Ubuntu 24.04 LTS kernel 5.15.0-MiCrOsOfT-standard",
                ),
                "operatingSystem identifies WSL",
            ),
            (
                lambda artifact: artifact["payload"]["results"][0].__setitem__(
                    "operatingSystem", "Ubuntu 24.04 LTS on wSl2"
                ),
                "operatingSystem identifies WSL",
            ),
            (
                lambda artifact: artifact["payload"]["results"][0].__setitem__(
                    "operatingSystem", "Ubuntu windows-subsystem-for-linux"
                ),
                "operatingSystem identifies WSL",
            ),
            (
                lambda artifact: artifact["payload"]["results"][0].__setitem__(
                    "environmentId", "ubuntu-wsl1-python-310"
                ),
                "environmentId identifies WSL",
            ),
            (
                lambda artifact: artifact["payload"]["results"][0].__setitem__(
                    "pythonVersion", "3.11.9"
                ),
                "stable Python 3.10.x or 3.14.x",
            ),
            (
                lambda artifact: artifact["payload"]["results"][1].__setitem__(
                    "environmentManifestSha256",
                    artifact["payload"]["results"][0][
                        "environmentManifestSha256"
                    ],
                ),
                "environment manifests must be distinct",
            ),
        )
        for mutation, expected in cases:
            with self.subTest(expected=expected):
                fixture = Fixture()
                try:
                    path = fixture.write_pass_evidence()
                    fixture.mutate_artifact(
                        path, "exact-candidate-compatibility", mutation
                    )
                    result = subprocess.run(
                        [
                            "python3",
                            str(CHECKER),
                            "--project",
                            str(fixture.root),
                            "--at",
                            NOW,
                            "--json",
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn(expected, result.stderr)
                finally:
                    fixture.close()

    def test_wsl_cannot_satisfy_required_linux_compatibility_evidence(self) -> None:
        path = self.fixture.write_pass_evidence()
        ordinary_ubuntu = self.run_checker()
        self.assertEqual(0, ordinary_ubuntu.returncode, ordinary_ubuntu.stderr)
        self.assertTrue(json.loads(ordinary_ubuntu.stdout)["ready"])

        def describe_wsl(artifact: dict[str, object]) -> None:
            results = artifact["payload"]["results"]  # type: ignore[index]
            for result in results:
                result["operatingSystem"] = "Ubuntu 24.04 LTS on Microsoft WSL2"

        self.fixture.mutate_artifact(
            path, "exact-candidate-compatibility", describe_wsl
        )
        rejected = self.run_checker()
        self.assertEqual(2, rejected.returncode)
        self.assertEqual("", rejected.stdout)
        error = json.loads(rejected.stderr)
        self.assertFalse(error["ok"])
        self.assertIn("identifies WSL", error["error"])
        self.assertIn("excludes experimental WSL environments", error["error"])

    def test_walkthrough_binds_governance_and_benchmark_fixture(self) -> None:
        def duplicate_receipt(artifact: dict[str, object]) -> None:
            receipts = artifact["payload"]["reviewOutcome"][  # type: ignore[index]
                "publicationReceipts"
            ]
            receipts["architecture-approval"] = receipts["review-request"]

        cases = (
            (
                lambda artifact: artifact["payload"]["authority"].__setitem__(
                    "releaseAttempted", True
                ),
                "release and deployment must remain disabled and unattempted",
            ),
            (
                lambda artifact: artifact["payload"]["reviewOutcome"].__setitem__(
                    "reviewReceiptSchemaVersion", 1
                ),
                "reviewReceiptSchemaVersion must equal 2",
            ),
            (duplicate_receipt, "publication receipt digests must be distinct"),
            (
                lambda artifact: artifact["payload"][
                    "integrationOutcome"
                ].__setitem__("approvalEvidenceSha256", "0" * 64),
                "does not bind the authenticated approval evidence",
            ),
            (
                lambda artifact: artifact["payload"]["selectedPack"].__setitem__(
                    "packSha256", "0" * 64
                ),
                "walkthrough and benchmark fixture bindings differ",
            ),
        )
        for mutation, expected in cases:
            with self.subTest(expected=expected):
                fixture = Fixture()
                try:
                    path = fixture.write_pass_evidence()
                    fixture.mutate_artifact(
                        path, "governed-walkthrough-execution", mutation
                    )
                    result = subprocess.run(
                        [
                            "python3",
                            str(CHECKER),
                            "--project",
                            str(fixture.root),
                            "--at",
                            NOW,
                            "--json",
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn(expected, result.stderr)
                finally:
                    fixture.close()

    def test_benchmark_phase_timings_are_ordered_exact_and_bounded(self) -> None:
        def introduce_gap(artifact: dict[str, object]) -> None:
            phase = artifact["payload"]["coldRuns"][0]["phaseTimings"][1]
            started = CHECKER_MODULE._parse_timestamp(
                phase["startedAt"], label="test phase start"
            )
            phase["startedAt"] = _format_timestamp(
                started + dt.timedelta(milliseconds=1)
            )
            phase["durationMs"] -= 1

        def exceed_bound(artifact: dict[str, object]) -> None:
            run = artifact["payload"]["coldRuns"][0]
            run.update(_benchmark_run(run["runId"], 86_400_001, "cold"))

        cases = (
            (
                lambda artifact: artifact["payload"]["coldRuns"][0][
                    "phaseTimings"
                ][1].__setitem__("phase", "review"),
                "objective phase order",
            ),
            (
                lambda artifact: artifact["payload"]["coldRuns"][0][
                    "phaseTimings"
                ][0].__setitem__(
                    "durationMs",
                    artifact["payload"]["coldRuns"][0]["phaseTimings"][0][
                        "durationMs"
                    ]
                    + 1,
                ),
                "durationMs does not match its timestamps",
            ),
            (introduce_gap, "phaseTimings must be contiguous and ordered"),
            (
                lambda artifact: artifact["payload"]["coldRuns"][0][
                    "phaseTimings"
                ].pop(3),
                "objective phase order",
            ),
            (exceed_bound, "exceeds the permitted maximum 86400000"),
        )
        for mutation, expected in cases:
            with self.subTest(expected=expected):
                fixture = Fixture()
                try:
                    path = fixture.write_pass_evidence()
                    fixture.mutate_artifact(
                        path, "first-governed-delivery-under-15m", mutation
                    )
                    result = subprocess.run(
                        [
                            "python3",
                            str(CHECKER),
                            "--project",
                            str(fixture.root),
                            "--at",
                            NOW,
                            "--json",
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn(expected, result.stderr)
                finally:
                    fixture.close()

    def test_benchmark_count_math_success_and_target_are_enforced(self) -> None:
        def exceed_target(artifact: dict[str, object]) -> None:
            payload = artifact["payload"]
            for run in payload["coldRuns"]:  # type: ignore[index]
                run.update(_benchmark_run(run["runId"], 950_000, "cold"))
            payload["coldP50Ms"] = 950_000  # type: ignore[index]
            payload["coldP95Ms"] = 950_000  # type: ignore[index]

        mutations = (
            (
                lambda artifact: artifact["payload"].__setitem__("coldP50Ms", 1),
                "raw-run calculation",
            ),
            (
                lambda artifact: artifact["payload"].__setitem__(
                    "coldRuns", artifact["payload"]["coldRuns"][:4]
                ),
                "5 to 100 runs",
            ),
            (exceed_target, "below-15-minute target"),
            (
                lambda artifact: artifact["payload"]["warmRuns"][0].__setitem__(
                    "status", "fail"
                ),
                "status must be exactly pass",
            ),
            (
                lambda artifact: artifact["payload"].__setitem__(
                    "allAttemptsRecorded", False
                ),
                "allAttemptsRecorded must be true",
            ),
            (
                lambda artifact: artifact["payload"]["coldRuns"][0].__setitem__(
                    "rawEvidenceSha256",
                    artifact["payload"]["coldRuns"][1]["rawEvidenceSha256"],
                ),
                "distinct raw evidence digests",
            ),
            (
                lambda artifact: artifact["payload"]["fixture"].pop("packSha256"),
                "missing packSha256",
            ),
        )
        for mutation, expected in mutations:
            with self.subTest(expected=expected):
                fixture = Fixture()
                try:
                    path = fixture.write_pass_evidence()
                    fixture.mutate_artifact(
                        path, "first-governed-delivery-under-15m", mutation
                    )
                    result = subprocess.run(
                        [
                            "python3",
                            str(CHECKER),
                            "--project",
                            str(fixture.root),
                            "--at",
                            NOW,
                            "--json",
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn(expected, result.stderr)
                finally:
                    fixture.close()

    def test_benchmark_duration_supports_exact_millisecond_timestamps(self) -> None:
        path = self.fixture.write_pass_evidence()

        def use_millisecond_precision(artifact: dict[str, object]) -> None:
            run = artifact["payload"]["coldRuns"][0]  # type: ignore[index]
            run.update(_benchmark_run(run["runId"], 600_001, "cold"))

        self.fixture.mutate_artifact(
            path,
            "first-governed-delivery-under-15m",
            use_millisecond_precision,
        )
        result = self.run_checker()
        self.assertEqual(0, result.returncode, result.stderr)

        self.assertEqual(
            999_000,
            CHECKER_MODULE._parse_timestamp(
                "2026-09-18T11:49:59.999Z", label="millisecond timestamp"
            ).microsecond,
        )
        with self.assertRaisesRegex(
            CHECKER_MODULE.BetaReadinessError, r"\[\.mmm\]"
        ):
            CHECKER_MODULE._parse_timestamp(
                "2026-09-18T11:49:59.9999Z", label="over-precise timestamp"
            )

    def test_usage_requires_values_or_explicit_unavailability_reason(self) -> None:
        path = self.fixture.write_pass_evidence()

        def remove_reason(artifact: dict[str, object]) -> None:
            artifact["payload"]["records"][0]["cacheTokens"] = {  # type: ignore[index]
                "value": None,
                "unavailableReason": None,
            }

        self.fixture.mutate_artifact(path, "runtime-usage-observability", remove_reason)
        result = self.run_checker()
        self.assertEqual(2, result.returncode)
        self.assertIn("unavailableReason", result.stderr)

    def test_usage_coverage_is_complete_and_fixture_bound(self) -> None:
        cases = (
            (
                lambda artifact: artifact["payload"]["coverage"].__setitem__(
                    "allAgentRunsRecorded", False
                ),
                "allAgentRunsRecorded must be true",
            ),
            (
                lambda artifact: artifact["payload"]["records"].pop(),
                "exactly cover expectedAgentRunIds",
            ),
            (
                lambda artifact: artifact["payload"]["coverage"].__setitem__(
                    "expectedAgentRunIds", ["implementation-run-1"]
                ),
                "exactly cover expectedAgentRunIds",
            ),
            (
                lambda artifact: artifact["payload"]["coverage"].__setitem__(
                    "environmentManifestSha256", "e" * 64
                ),
                "runtime usage and walkthrough fixture bindings differ",
            ),
        )
        for mutation, expected in cases:
            with self.subTest(expected=expected):
                fixture = Fixture()
                try:
                    path = fixture.write_pass_evidence()
                    fixture.mutate_artifact(
                        path, "runtime-usage-observability", mutation
                    )
                    result = subprocess.run(
                        [
                            "python3",
                            str(CHECKER),
                            "--project",
                            str(fixture.root),
                            "--at",
                            NOW,
                            "--json",
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn(expected, result.stderr)
                finally:
                    fixture.close()

    def test_usage_provenance_fields_are_objective_and_bounded(self) -> None:
        cases = (
            (
                lambda artifact: artifact["payload"]["records"][0].pop("provider"),
                "missing provider",
            ),
            (
                lambda artifact: artifact["payload"]["records"][0].__setitem__(
                    "wallTimeMs", _metric(0)
                ),
                "wallTimeMs value must be a positive integer",
            ),
            (
                lambda artifact: artifact["payload"]["records"][0].__setitem__(
                    "pricingDate", _observation("2026-09-19")
                ),
                "cannot postdate the usage record",
            ),
            (
                lambda artifact: artifact["payload"]["records"][0].__setitem__(
                    "costCalculation", _observation(None)
                ),
                "costCalculation unavailableReason",
            ),
        )
        for mutation, expected in cases:
            with self.subTest(expected=expected):
                fixture = Fixture()
                try:
                    path = fixture.write_pass_evidence()
                    fixture.mutate_artifact(
                        path, "runtime-usage-observability", mutation
                    )
                    result = subprocess.run(
                        [
                            "python3",
                            str(CHECKER),
                            "--project",
                            str(fixture.root),
                            "--at",
                            NOW,
                            "--json",
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn(expected, result.stderr)
                finally:
                    fixture.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
