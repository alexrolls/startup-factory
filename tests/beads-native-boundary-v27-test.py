#!/usr/bin/env python3
"""Offline contract tests for the internal protected Beads V27 boundary."""

from __future__ import annotations

import importlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

boundary = importlib.import_module("startup_factory_cli.beads_native_boundary_v27")
controller = importlib.import_module("startup_factory_cli.beads_boundary_controller")
runtime = importlib.import_module("startup_factory_cli.beads_protected_runtime")


def digest(label: str) -> str:
    return "sha256:" + __import__("hashlib").sha256(label.encode()).hexdigest()


class NativeBoundaryV27Test(unittest.TestCase):
    def manifest(self) -> dict:
        return {
            "schemaVersion": 27,
            "profile": "startup-factory/beads-native-boundary/v27",
            "systemdVersion": "254",
            "podmanVersion": "5.4.1",
            "conmonVersion": "2.1.12",
            "selinuxMode": "enforcing",
            "supervisorPath": "/usr/local/libexec/startup-factory-beads-supervisor-v27",
            "supervisorSha256": digest("supervisor"),
            "podmanPath": "/usr/bin/podman",
            "podmanSha256": digest("podman"),
            "conmonPath": "/usr/bin/conmon",
            "conmonSha256": digest("conmon"),
            "selinuxPolicySha256": digest("policy"),
            "imageDigest": digest("beads-v27-image"),
            "imageReference": "localhost/startup-factory/beads-v27@"
            + digest("beads-v27-image"),
            "selinuxContexts": {
                "proc-current-preexec": self.context("system_u:system_r:beads_controller_t:s0", "none"),
                "proc-exec-preexec": self.context("", "empty"),
                "file-xattr-supervisor-exec": self.context(
                    "system_u:object_r:beads_supervisor_exec_t:s0\0", "one-trailing-nul"
                ),
                "proc-current-setupready": self.context(
                    "system_u:system_r:beads_native_supervisor_t:s0", "none"
                ),
            },
        }

    @staticmethod
    def context(text: str, terminator: str) -> dict:
        raw = text.encode()
        import base64
        import hashlib

        return {
            "rawBytesBase64": base64.b64encode(raw).decode("ascii"),
            "byteLength": len(raw),
            "terminatorKind": terminator,
            "rawBytesSha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        }

    def test_public_surface_remains_frozen_and_v27_is_internal(self) -> None:
        self.assertEqual(92, len(runtime._TYPE_NAMES))
        self.assertEqual(33, len(runtime._FUNCTION_EXPORTS))
        self.assertEqual(30, len(controller.ALLOWED_OPERATIONS))
        self.assertTrue(set(boundary.INTERNAL_SCHEMA_NAMES).isdisjoint(runtime._TYPE_NAMES))
        self.assertTrue(set(boundary.INTERNAL_SCHEMA_NAMES).isdisjoint(runtime.__all__))
        schema = json.loads(boundary.internal_schema_fixture_v27())
        self.assertEqual(27, schema["schemaVersion"])
        self.assertEqual(sorted(boundary.INTERNAL_SCHEMA_NAMES), schema["internalSchemas"])

    def test_exact_profile_and_full_raw_selinux_contexts(self) -> None:
        parsed = boundary.parse_native_boundary_manifest_v27(self.manifest())
        self.assertEqual("5.4.1", parsed.podman_version)
        for interface, expectation in parsed.selinux_contexts.items():
            boundary.verify_selinux_raw_context_v27(interface, expectation.raw_bytes, parsed)

        mutations = (
            ("podmanVersion", "5.4.2"),
            ("systemdVersion", "255"),
            ("conmonVersion", "2.1.13"),
            ("selinuxMode", "permissive"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                candidate = {**self.manifest(), field: value}
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.parse_native_boundary_manifest_v27(candidate)

        candidate = self.manifest()
        candidate["selinuxContexts"] = dict(candidate["selinuxContexts"])
        candidate["selinuxContexts"]["proc-current-preexec"] = self.context(
            "system_u:system_r:beads_controller_t:s0\0", "one-trailing-nul"
        )
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.parse_native_boundary_manifest_v27(candidate)

    def test_socket_fd_key_and_creator_custody_are_closed(self) -> None:
        plan = boundary.validate_launch_plan_v27(boundary.reference_launch_plan_v27())
        self.assertEqual((70, 71, 6), (plan.controller_source_fd, plan.child_source_fd, plan.child_socket_fd))
        self.assertEqual(tuple(range(14)), tuple(sorted(plan.fixed_fd_roles)))
        self.assertEqual("controller-pidfd", plan.fixed_fd_roles[7])
        self.assertEqual("launcher-tid-stat", plan.fixed_fd_roles[11])
        self.assertEqual("supervisor-executable", plan.fixed_fd_roles[13])

        for mutation in (
            {"childSocketFd": 7},
            {"controllerSourceFd": 71},
            {"parentClosesChildSourceBeforeRelease": False},
            {"childCloseRangeStartsAt": 15},
            {"retainedThroughCreate": [7]},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.validate_launch_plan_v27(
                        {**boundary.reference_launch_plan_v27(), **mutation}
                    )

        key = b"k" * 32
        with tempfile.TemporaryFile() as handle:
            handle.write(key)
            handle.flush()
            handle.seek(0)
            before = handle.tell()
            boundary.verify_sealed_key_material_v27(
                handle.fileno(),
                expected_sha256=boundary.sha256(key),
                seals_verified=True,
            )
            self.assertEqual(before, handle.tell())
        with tempfile.TemporaryFile() as handle:
            handle.write(key + b"x")
            handle.flush()
            with self.assertRaises(boundary.NativeBoundaryV27Error):
                boundary.verify_sealed_key_material_v27(
                    handle.fileno(), expected_sha256=boundary.sha256(key), seals_verified=True
                )

    def test_result_terminal_and_round49_recovery_xors(self) -> None:
        success = boundary.validate_result_envelope_v4(
            {
                "resultKind": "success",
                "predecessorKind": "creator-lifetime-closed-positive",
                "failureEvidenceSha256": None,
            }
        )
        self.assertEqual("success", success["resultKind"])
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_result_envelope_v4(
                {
                    "resultKind": "success",
                    "predecessorKind": "revoke-verified-no-effect",
                    "failureEvidenceSha256": None,
                }
            )
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_result_envelope_v4(
                {
                    "resultKind": "unresolved",
                    "predecessorKind": "creator-lifetime-closed-positive",
                    "failureEvidenceSha256": None,
                }
            )

        terminal = boundary.validate_supervisor_terminal_current_v3(
            {
                "terminalBranch": "result-handoff-terminal",
                "resultEnvelopeSha256": digest("result"),
                "launchPreEffectFailedSha256": None,
            }
        )
        self.assertEqual("result-handoff-terminal", terminal["terminalBranch"])
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_supervisor_terminal_current_v3(
                {
                    "terminalBranch": "result-handoff-terminal",
                    "resultEnvelopeSha256": digest("result"),
                    "launchPreEffectFailedSha256": digest("impossible-second-branch"),
                }
            )

        base = boundary.reference_prior_recovery_attempt_result_v3(
            "acquired-holder-lost", "acquisition-receipt"
        )
        boundary.validate_prior_recovery_attempt_result_v3(base)
        self.assertEqual("not-reached", base["dispositionState"])
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_prior_recovery_attempt_result_v3(
                {**base, "dispositionState": "reached", "dispositionPair": boundary.digest_pair("d")}
            )

        disposed = boundary.reference_prior_recovery_attempt_result_v3(
            "acquired-holder-lost", "disposition-receipt"
        )
        boundary.validate_prior_recovery_attempt_result_v3(disposed)
        self.assertEqual("reached", disposed["dispositionState"])
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_prior_recovery_attempt_result_v3(
                {**disposed, "dispositionState": "not-reached", "dispositionPair": None}
            )

        for prefix in ("release-durable-close-unreceipted", "close-receipt"):
            for state in ("not-reached", "reached"):
                value = boundary.reference_prior_recovery_attempt_result_v3(
                    "acquired-holder-lost", prefix, disposition_state=state
                )
                boundary.validate_prior_recovery_attempt_result_v3(value)
                self.assertEqual(state == "reached", value["dispositionPair"] is not None)

    def test_operation_lock_and_platform_observation_are_exact(self) -> None:
        self.assertEqual(
            {
                "openFlags": ["O_RDWR", "O_CLOEXEC", "O_NOFOLLOW"],
                "lockCommand": "F_OFD_SETLK",
                "l_type": "F_WRLCK",
                "l_whence": "SEEK_SET",
                "l_start": 0,
                "l_len": 0,
                "l_pid": 0,
            },
            boundary.operation_lock_contract_v27(),
        )
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        observation = {
            "platform": "linux",
            "systemdVersion": "254",
            "podmanVersion": "5.4.1",
            "podmanRootless": True,
            "conmonVersion": "2.1.12",
            "selinuxMode": "enforcing",
            "supervisorSha256": digest("supervisor"),
            "podmanSha256": digest("podman"),
            "conmonSha256": digest("conmon"),
            "selinuxPolicySha256": digest("policy"),
            "podmanSocketMounted": False,
            "sudoAvailableToWorker": False,
            "agentRunsAsRoot": False,
        }
        boundary.validate_platform_observation_v27(observation, manifest)
        for field, bad in (
            ("podmanRootless", False),
            ("selinuxMode", "permissive"),
            ("podmanSocketMounted", True),
            ("sudoAvailableToWorker", True),
            ("agentRunsAsRoot", True),
        ):
            with self.subTest(field=field), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.validate_platform_observation_v27(
                    {**observation, field: bad}, manifest
                )

    def test_internal_hmac_current_and_recovery_stage_contracts_are_closed(self) -> None:
        self.assertEqual(
            b"startup-factory/beads/prior-recovery-attempt-result/v3\0",
            boundary.HMAC_DOMAINS_V27["PriorRecoveryAttemptResultV3"],
        )
        self.assertEqual(42, len(boundary.CURRENT_UNION_V27))
        self.assertEqual(
            {
                "claim-cas": 76,
                "ordinary": 76,
                "receipt-comment": 77,
                "create-preparation": 63,
                "reattest-preparation": 24,
            },
            boundary.DONE_LOCATIONS_V27,
        )
        self.assertEqual(
            tuple(range(70, 76)), boundary.INCOMPLETE_TAILS_V27["claim-cas"]
        )
        evidence = boundary.reference_recovery_suffix_v27(
            "ordinary", 72, "object-before-current"
        )
        boundary.validate_recovery_suffix_v27(evidence)
        for mutation in (
            {"targetLocation": 69},
            {"targetLocation": 73},
            {"candidateCurrentPair": boundary.digest_pair("future")},
            {"receiptPair": boundary.digest_pair("fabricated")},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.validate_recovery_suffix_v27({**evidence, **mutation})

        sequence = boundary.OneUseSequenceV27()
        self.assertEqual(1, sequence.consume("one-use-token-0001", "claim-cas", 0))
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            sequence.consume("one-use-token-0001", "claim-cas", 1)
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            sequence.consume("another-one-use-token", "claim-cas", 76)

    def test_seqpacket_creator_and_all_recovery_result_branches_fail_closed(self) -> None:
        packet = {
            "packetLength": 128,
            "msgTrunc": False,
            "msgCtrunc": False,
            "zeroLengthRecord": False,
            "credentialsCount": 1,
            "rightsCount": 0,
            "extraQueuedRecord": False,
            "peerEof": False,
        }
        boundary.validate_seqpacket_observation_v27(packet, expected_length=128)
        for field, value in (
            ("msgTrunc", True),
            ("credentialsCount", 2),
            ("rightsCount", 1),
            ("extraQueuedRecord", True),
            ("peerEof", True),
        ):
            with self.subTest(field=field), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.validate_seqpacket_observation_v27(
                    {**packet, field: value}, expected_length=128
                )

        gate = boundary.reference_creator_gate_observation_v27()
        boundary.validate_creator_gate_observation_v27(gate)
        for field, value in (
            ("controllerPidfdReadable", True),
            ("launcherTidIdentityMatches", False),
            ("childSocketPeek", "eof"),
            ("pthreadCreateAdjacent", False),
            ("runAuthorizationUseCount", 2),
            ("podmanSocketMounted", True),
            ("agentRunsAsRoot", True),
        ):
            with self.subTest(field=field), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.validate_creator_gate_observation_v27(
                    {**gate, field: value}
                )

        cases = (
            ("nonacquired-clean-closed", "nonacquired-closed-current"),
            ("acquired-clean-closed", "acquired-closed-before-disposition"),
            ("acquired-clean-closed", "acquired-closed-after-disposition"),
            ("lost-before-call-result", "intent-current-no-call-consume"),
            ("lost-before-call-result", "call-consumed-no-result"),
            ("lost-after-nonacquired-result", "nonacquired-result-close-unreceipted"),
            ("lost-after-nonacquired-result", "nonacquired-close-receipt"),
            (
                "lost-after-acquired-result-before-acquisition",
                "acquired-result-no-acquisition-receipt",
            ),
        )
        for kind, prefix in cases:
            with self.subTest(kind=kind, prefix=prefix):
                value = boundary.reference_prior_recovery_attempt_result_v3(
                    kind, prefix
                )
                boundary.validate_prior_recovery_attempt_result_v3(value)
                forbidden_field = (
                    "releasePair"
                    if kind == "nonacquired-clean-closed"
                    else "holderAbsencePair"
                    if kind == "acquired-clean-closed"
                    else "closedCurrentPair"
                )
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.validate_prior_recovery_attempt_result_v3(
                        {**value, forbidden_field: boundary.digest_pair("smuggled")}
                    )

    def test_native_supervisor_probe_binds_full_gate_and_fixed_local_commands(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        probe = boundary.reference_native_supervisor_probe_v27(manifest)
        boundary.validate_native_supervisor_probe_v27(probe, manifest)
        tampered = json.loads(json.dumps(probe))
        tampered["agentBoundary"]["task2CanMintAuthority"] = True
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_native_supervisor_probe_v27(tampered, manifest)

        commands = []

        def runner(argv):
            commands.append(tuple(argv))
            if argv == ["/usr/bin/systemd", "--version"]:
                return b"systemd 254 (254.26-1)\n"
            if argv == [str(manifest.podman_path), "--version"]:
                return b"podman version 5.4.1\n"
            if argv == [str(manifest.podman_path), "info", "--format", "json"]:
                return boundary.canonical_bytes(
                    {
                        "host": {
                            "cgroupManager": "systemd",
                            "cgroupVersion": "v2",
                            "idMappings": {
                                "gidmap": [
                                    {"container_id": 0, "host_id": 81003, "size": 1}
                                ],
                                "uidmap": [
                                    {"container_id": 0, "host_id": 81003, "size": 1}
                                ],
                            },
                            "security": {"rootless": True},
                        }
                    }
                ) + b"\n"
            if argv == [
                str(manifest.podman_path),
                "image",
                "inspect",
                "--format",
                "json",
                manifest.image_reference,
            ]:
                return boundary.canonical_bytes(
                    [
                        {
                            "Id": manifest.image_digest,
                            "RepoDigests": [manifest.image_reference],
                        }
                    ]
                ) + b"\n"
            if argv == [str(manifest.conmon_path), "--version"]:
                return b"conmon version 2.1.12\n"
            if argv == [str(manifest.supervisor_path), "--startup-factory-probe-v27"]:
                return boundary.canonical_bytes(probe) + b"\n"
            self.fail(f"unexpected argv: {argv!r}")

        observed = boundary.verify_local_platform_gate_v27(
            manifest,
            runner=runner,
            selinux_enforce_reader=lambda: b"1\n",
            platform_name="linux",
        )
        self.assertEqual(probe, observed)
        self.assertEqual(
            [
                ("/usr/bin/systemd", "--version"),
                (str(manifest.podman_path), "--version"),
                (str(manifest.podman_path), "info", "--format", "json"),
                (
                    str(manifest.podman_path),
                    "image",
                    "inspect",
                    "--format",
                    "json",
                    manifest.image_reference,
                ),
                (str(manifest.conmon_path), "--version"),
                (str(manifest.supervisor_path), "--startup-factory-probe-v27"),
            ],
            commands,
        )
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_local_platform_gate_v27(
                manifest, runner=runner, selinux_enforce_reader=lambda: b"0\n"
                , platform_name="linux"
            )

        def hostile_systemd(argv):
            if argv == ["/usr/bin/systemd", "--version"]:
                return b"systemd 254 attacker-controlled-suffix\n"
            return runner(argv)

        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=hostile_systemd,
                selinux_enforce_reader=lambda: b"1\n",
                platform_name="linux",
            )

        for hostile in (
            b'{"host":{"cgroupManager":"systemd","cgroupVersion":"v2","idMappings":{"gidmap":[],"uidmap":[]},"security":{"rootless":true}}}\n',
            b'{"host":{"cgroupManager":"systemd","cgroupVersion":"v2","idMappings":{"gidmap":[{"container_id":0,"host_id":81003,"size":1}],"uidmap":[{"container_id":0,"host_id":81003,"size":1}]},"security":{"rootless":true,"rootless":true}}}\n',
        ):
            with self.subTest(hostile_podman_info=hostile), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.verify_local_platform_gate_v27(
                    manifest,
                    runner=lambda argv, hostile=hostile: (
                        hostile
                        if argv
                        == [str(manifest.podman_path), "info", "--format", "json"]
                        else runner(argv)
                    ),
                    selinux_enforce_reader=lambda: b"1\n",
                    platform_name="linux",
                )

        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=lambda argv: (
                    boundary.canonical_bytes(
                        [
                            {
                                "Id": manifest.image_digest,
                                "RepoDigests": [manifest.image_reference],
                            },
                            {
                                "Id": manifest.image_digest,
                                "RepoDigests": [manifest.image_reference],
                            },
                        ]
                    )
                    + b"\n"
                    if argv[:3]
                    == [str(manifest.podman_path), "image", "inspect"]
                    else runner(argv)
                ),
                selinux_enforce_reader=lambda: b"1\n",
                platform_name="linux",
            )

        def hostile_conmon(argv):
            if argv == [str(manifest.conmon_path), "--version"]:
                return b"not-conmon 2.1.12-malicious\n"
            return runner(argv)

        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=hostile_conmon,
                selinux_enforce_reader=lambda: b"1\n",
                platform_name="linux",
            )

    def test_production_effect_is_durable_hmac_cas_and_never_replays_consumed_launch(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        plan = boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="a" * 64,
            operation_class="ordinary",
            argv=["/usr/local/bin/bd", "update", "task-1", "--status", "active", "--json"],
            repository_path="/srv/startup-factory/repositories/repository-1",
        )
        calls = []

        def runner(_manifest, observed_plan):
            calls.append(observed_plan)
            return {
                "exitCode": 0,
                "stdout": b'{"id":"task-1","status":"active"}\n',
                "stderr": b"",
                "readBack": b'{"id":"task-1","status":"active"}\n',
                "lifecycle": ["create", "init", "start-attach", "terminal", "cleanup", "rm"],
            }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = boundary.execute_supervised_effect_v27(
                root,
                b"v27-test-stage-hmac-key-material-32-bytes",
                manifest,
                plan,
                runner=runner,
            )
            self.assertEqual(0, result["exitCode"])
            self.assertEqual(1, len(calls))
            current = boundary.inspect_supervised_effect_v27(
                root,
                b"v27-test-stage-hmac-key-material-32-bytes",
                plan["operationId"],
            )
            self.assertEqual(boundary.DONE_LOCATIONS_V27["ordinary"], current["payload"]["location"])
            self.assertEqual("completion", current["payload"]["state"])
            self.assertTrue(current["auth"].startswith("hmac-sha256:"))

            repeated = boundary.execute_supervised_effect_v27(
                root,
                b"v27-test-stage-hmac-key-material-32-bytes",
                manifest,
                plan,
                runner=runner,
            )
            self.assertEqual(result, repeated)
            self.assertEqual(1, len(calls), "a Done current must return without replay")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27("launch-consumed-current"):
                    boundary.execute_supervised_effect_v27(
                        root,
                        b"v27-test-stage-hmac-key-material-32-bytes",
                        manifest,
                        plan,
                        runner=runner,
                    )
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "possible effect"
            ):
                boundary.execute_supervised_effect_v27(
                    root,
                    b"v27-test-stage-hmac-key-material-32-bytes",
                    manifest,
                    plan,
                    runner=runner,
                )
            self.assertEqual(1, len(calls), "a consumed launch is never replayed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = len(calls)
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27("result-object-written"):
                    boundary.execute_supervised_effect_v27(
                        root,
                        b"v27-test-stage-hmac-key-material-32-bytes",
                        manifest,
                        plan,
                        runner=runner,
                    )
            recovered = boundary.execute_supervised_effect_v27(
                root,
                b"v27-test-stage-hmac-key-material-32-bytes",
                manifest,
                plan,
                runner=runner,
            )
            self.assertEqual(0, recovered["exitCode"])
            self.assertEqual(before + 1, len(calls), "stored result recovery never replays")

    def test_native_runner_uses_pinned_supervisor_and_closed_podman_lifecycle(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        plan = boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="b" * 64,
            operation_class="create-preparation",
            argv=["/usr/local/bin/bd", "init", "--json"],
            repository_path="/srv/startup-factory/repositories/repository-2",
        )
        captured = {}

        def process_runner(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return boundary.subprocess.CompletedProcess(
                argv,
                0,
                boundary.canonical_bytes(
                    {
                        "exitCode": 0,
                        "lifecycle": ["create", "init", "start-attach", "terminal", "cleanup", "rm"],
                        "readBackBase64": "e30K",
                        "stderrBase64": "",
                        "stdoutBase64": "e30K",
                    }
                )
                + b"\n",
                b"",
            )

        result = boundary.run_native_supervisor_v27(
            manifest, plan, process_runner=process_runner
        )
        self.assertEqual(0, result["exitCode"])
        self.assertEqual(
            [str(manifest.supervisor_path), "--startup-factory-execute-v27"],
            captured["argv"],
        )
        self.assertEqual(
            boundary._fixed_worker_environment_v27(),
            captured["kwargs"]["env"],
        )
        self.assertFalse(captured["kwargs"]["shell"])
        self.assertEqual("/", captured["kwargs"]["cwd"])

    def test_shipped_native_assets_bind_reproducible_closed_profile(self) -> None:
        source = (ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c").read_text()
        containerfile = (ROOT / "runtime/beads-v27/Containerfile").read_text()
        policy = (ROOT / "runtime/beads-v27/startup_factory_beads_v27.te").read_text()
        build = (ROOT / "runtime/beads-v27/build.sh").read_text()
        service = (ROOT / "runtime/startup-factory-beads-controller.service.example").read_text()
        protected_runtime_source = (ROOT / "src/startup_factory_cli/beads_protected_runtime.py").read_text()

        self.assertIn("--startup-factory-execute-v27", source)
        for stage in ("create", "init", "start", "wait", "cleanup", "rm"):
            self.assertIn(f'\"{stage}\"', source)
        self.assertIn("--pull", source)
        self.assertIn("never", source)
        self.assertIn("--network", source)
        self.assertIn("none", source)
        self.assertIn("--cgroups", source)
        self.assertIn("verify_selinux_transition", source)
        self.assertIn("security.selinux", source)
        self.assertIn("FROM scratch", containerfile)
        self.assertIn("beads_native_supervisor_t", policy)
        self.assertIn("-Werror", build)
        self.assertIn("Delegate=yes", service)
        self.assertIn("DelegateSubgroup=supervisor", service)
        self.assertIn("ProtectControlGroups=false", service)
        self.assertIn("KillMode=control-group", service)
        self.assertIn(
            "SELinuxContext=system_u:system_r:beads_controller_t:s0", service
        )
        self.assertNotIn("def _spawn_verified_executable_v1", protected_runtime_source)
        self.assertNotIn("subprocess.run(", protected_runtime_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
