from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import cli, runtime_kit  # noqa: E402
from tests.packaging.test_cli_installer import base_payload, write_bundle  # noqa: E402


IMAGE = "registry.example.invalid/startup-factory@sha256:" + "a" * 64


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


class GovernedRuntimeLauncherTest(unittest.TestCase):
    def test_gate_role_receives_only_isolated_clone_tools_and_scoped_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            project = root / "project"
            project.mkdir(mode=0o700)
            subprocess.run(["git", "-C", str(project), "init", "-q", "-b", "main"], check=True)
            subprocess.run(["git", "-C", str(project), "config", "user.name", "Fixture"], check=True)
            subprocess.run(["git", "-C", str(project), "config", "user.email", "fixture@example.invalid"], check=True)
            probe = project / "agent-probe.sh"
            probe.write_text(
                "#!/bin/sh\nset -eu\nmkdir -p .startup-factory-output\n"
                "printf '%s\\n' \"$PWD\" \"$1\" \"${STARTUP_FACTORY_AGENT_WORKTREE:-missing}\" "
                "\"${STARTUP_FACTORY_CANONICAL_REPO:-unset}\" \"${STARTUP_FACTORY_CANONICAL_WORKSPACE:-unset}\" "
                "\"${STARTUP_FACTORY_OUTBOX_INGRESS:-missing}\" > .startup-factory-output/agent-result.txt\n"
                "printf '[design-note]\\nisolated gate submission\\n' > .startup-factory-output/body.md\n"
                "\"$STARTUP_FACTORY_SKILL_ROOT/bin/submit-artifact.sh\" feature-runtime F-1 T-1 1 backend design-note "
                ".startup-factory-output/body.md - > .startup-factory-output/entry-path.txt\n"
            )
            probe.chmod(0o755)
            sentinel = root / "host-sentinel"
            sentinel.write_text("host-only\n")
            validator = project / "validator.sh"
            validator.write_text(
                "#!/bin/sh\nset -eu\n"
                f"test ! -e '{sentinel}'\n"
                f"test ! -e '{project}'\n"
                f"test ! -e '{root / 'protected-runtime/lifecycle'}'\n"
                "test -z \"${STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET:-}\"\n"
                "test -z \"${AWS_SECRET_ACCESS_KEY:-}\"\n"
                "python3 -c 'import socket; s=socket.socket(); s.settimeout(.1); "
                "assert s.connect_ex((\"127.0.0.1\", 9)) != 0'\n"
            )
            validator.chmod(0o755)
            (project / ".gitignore").write_text(".teamwork/\n")
            (project / "base.txt").write_text("base\n")
            subprocess.run(["git", "-C", str(project), "add", "."], check=True)
            subprocess.run(["git", "-C", str(project), "commit", "-qm", "base"], check=True)
            subprocess.run(["git", "-C", str(project), "branch", "feature-runtime"], check=True)

            engine_log = root / "engine.log"
            validation_started = root / "validation-started"
            validation_continue = root / "validation-continue"
            reject_merged = root / "reject-merged-validation"
            authoritative_snapshot = root / "authoritative-tracker-snapshot.json"
            engine = root / "podman"
            engine.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = info ]; then printf '%s\\n' '"
                '{"version":{"Version":"5.4.2"},"host":{"security":{"rootless":true},"idMappings":{"uidmap":[{"container_id":0,"host_id":1000,"size":1}],"gidmap":[{"container_id":0,"host_id":1000,"size":1}]}}}'
                "'; elif [ \"$1\" = image ]; then printf '%s\\n' '"
                f'[{{"RepoDigests":["{IMAGE}"],"Id":"sha256:{"b" * 64}"}}]'
                "'; elif [ \"$1\" = run ]; then printf '%s\\n' \"$@\" >> '"
                + str(engine_log)
                + "'; case \" $* \" in *validator.sh*) "
                + "case \" $* \" in *'--network=none'*) ;; *) exit 70;; esac; "
                + "case \" $* \" in *'"
                + str(project)
                + "'*) exit 71;; esac; "
                + "case \" $* \" in *'"
                + str(root / "protected-runtime/lifecycle")
                + "'*) exit 72;; esac; "
                + "case \" $* \" in *STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET*|*AWS_SECRET_ACCESS_KEY*) exit 73;; esac; "
                + "case \" $* \" in *merged-feature-validation*) [ ! -e '"
                + str(reject_merged)
                + "' ] || exit 75;; esac; "
                + "touch '"
                + str(validation_started)
                + "'; i=0; while [ ! -e '"
                + str(validation_continue)
                + "' ]; do i=$((i+1)); [ \"$i\" -lt 500 ] || exit 74; sleep .01; done; exit 0;; esac; "
                + "while [ \"$#\" -gt 0 ]; do if [ \"$1\" = '"
                + IMAGE
                + "' ]; then shift; exec \"$@\"; fi; shift; done; exit 65; else exit 64; fi\n"
            )
            engine.chmod(0o700)

            payload = base_payload()
            for root_name in ("bin", "config", "reference", "roles", "teams", "runtime", "adapters", "extensions"):
                for source in (ROOT / root_name).rglob("*"):
                    if source.is_file() and not source.is_symlink():
                        relative = source.relative_to(ROOT).as_posix()
                        payload[relative] = (source.read_bytes(), stat.S_IMODE(source.stat().st_mode))
            team_config = payload["config/team.config.md"][0].decode()
            replacements = {
                "BACKEND_CMD": '"./agent-probe.sh {prompt_file}"',
                "TEAM_DEFAULT_CMD": '"./agent-probe.sh {prompt_file}"',
                "AGENT_ENV_ALLOWLIST": '"PATH TMPDIR LANG LC_ALL TERM"',
                "TRACKER_WRITERS": "broker",
                "VALIDATE_SCRIPT": "validator.sh",
            }
            for key, value in replacements.items():
                team_config, count = re.subn(rf"(?m)^{key}=.*$", f"{key}={value}", team_config)
                self.assertEqual(count, 1, key)
            payload["config/team.config.md"] = (team_config.encode(), 0o640)
            payload["bin/tracker-ops.sh"] = (
                (
                    "#!/bin/sh\nset -eu\n"
                    "if [ \"${1:-}\" = export ] && [ \"$#\" -eq 3 ]; then "
                    f"/bin/cp '{authoritative_snapshot}' \"$3\"; exit 0; fi\n"
                    "exit 0\n"
                ).encode(),
                0o755,
            )
            bundle = write_bundle(root / "bundle.tar.gz", payload=payload)
            target = root / "installed" / "startup-factory"
            code, output, error = invoke(
                "install", "--project", str(project), "--install-dir", str(target),
                "--bundle", str(bundle), "--json",
            )
            self.assertEqual((code, error), (0, ""), output + error)
            runtime_root = root / "protected-runtime"
            code, output, error = invoke(
                "runtime-kit", "--project", str(project), "--install-dir", str(target),
                "--runtime-root", str(runtime_root), "--engine", str(engine), "--image", IMAGE,
                "--host-platform", "linux", "--json",
            )
            self.assertEqual((code, error), (0, ""), output + error)
            plan_digest = json.loads(output)["planDigest"]
            with mock.patch.object(runtime_kit.sys, "platform", "linux"):
                code, output, error = invoke(
                    "runtime-kit", "--project", str(project), "--install-dir", str(target),
                    "--runtime-root", str(runtime_root), "--engine", str(engine), "--image", IMAGE,
                    "--host-platform", "linux", "--apply", "--plan-digest", plan_digest, "--json",
                )
            self.assertEqual((code, error), (0, ""), output + error)

            launch = target / "bin/launch-team.sh"
            result = subprocess.run(
                [str(launch), "start", "feature-runtime", "F-1", "backend"],
                cwd=project,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": str(root), "TEAM_RUNNER": "background"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            clone = runtime_root / "attempt-clones/feature-runtime/backend#1-gate-backend"
            agent_result = clone / ".startup-factory-output/agent-result.txt"
            for _ in range(100):
                if agent_result.exists():
                    break
                time.sleep(0.02)
            role_log = project / ".teamwork/feature-runtime/pids/backend.log"
            self.assertTrue(
                agent_result.is_file(),
                result.stdout + result.stderr + (role_log.read_text() if role_log.exists() else "<no role log>"),
            )
            lines = agent_result.read_text().splitlines()
            self.assertEqual(lines[0], str(clone))
            prompt_path = Path(lines[1])
            self.assertEqual(prompt_path.parent, clone / ".startup-factory-input")
            self.assertRegex(prompt_path.name, r"^role-prompt-[0-9a-f]{16}\.md$")
            self.assertEqual(lines[2], str(clone))
            self.assertEqual(lines[3:5], ["unset", "unset"])
            self.assertRegex(lines[5], rf"^{re.escape(str(runtime_root / 'outbox-ingress'))}/cap-[0-9a-f]{{32}}$")
            entry_receipt = clone / ".startup-factory-output/entry-path.txt"
            for _ in range(100):
                if entry_receipt.exists() and entry_receipt.stat().st_size:
                    break
                time.sleep(0.02)
            self.assertTrue(entry_receipt.exists() and entry_receipt.stat().st_size, role_log.read_text() if role_log.exists() else "<no role log>")
            entry_path = Path(entry_receipt.read_text().strip())
            self.assertEqual(entry_path.parent, Path(lines[5]))
            entry = json.loads(entry_path.read_text())
            self.assertEqual(entry["producerCapability"]["id"], entry_path.parent.name)
            self.assertEqual(Path(entry["bodyPath"]).parent, entry_path.parent)
            self.assertFalse((project / ".teamwork/feature-runtime/outbox/pending").exists())
            rendered_prompt = prompt_path.read_text()
            self.assertNotIn(str(project), rendered_prompt)
            self.assertNotIn(str(project / ".teamwork"), rendered_prompt)
            invocation = engine_log.read_text()
            self.assertIn(f"type=bind,src={clone},dst={clone},rw", invocation)
            self.assertIn(f"type=bind,src={target},dst={target},ro", invocation)
            self.assertNotIn(str(project), invocation)
            self.assertNotIn(str(project / ".git"), invocation)
            self.assertNotIn(str(project / ".teamwork"), invocation)
            self.assertNotIn(str(runtime_root / "lifecycle"), invocation)
            self.assertEqual(subprocess.check_output(["git", "-C", str(clone), "status", "--porcelain=v1", "-uall"], text=True), "")

            # The integration entry path must freeze one imported head before
            # validation and never return to the producer-controlled clone.
            subprocess.run(["git", "-C", str(project), "checkout", "-q", "feature-runtime"], check=True)
            task = "F-1#validation"
            key = subprocess.check_output(
                ["python3", str(target / "bin/runtime-state.py"), "key", task], text=True
            ).strip()
            branch = f"agent-task/feature-runtime/{key}"
            base = subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"], text=True).strip()
            created = subprocess.check_output(
                [
                    "python3", str(target / "bin/standalone_workspace.py"), "create",
                    "--repo", str(project), "--root", str(runtime_root / "attempt-clones"),
                    "--team", "feature-runtime", "--role", "backend", "--attempt", "1",
                    "--task-key", key, "--branch", branch, "--base-ref", base,
                ],
                text=True,
            )
            producer = Path(json.loads(created)["path"])
            (producer / "task.txt").write_text("reviewed\n")
            subprocess.run(["git", "-C", str(producer), "add", "task.txt"], check=True)
            subprocess.run(["git", "-C", str(producer), "commit", "-qm", "reviewed task"], check=True)
            imported_head = subprocess.check_output(["git", "-C", str(producer), "rev-parse", "HEAD"], text=True).strip()
            workspace = project / ".teamwork/feature-runtime"
            execution_path = workspace / f"executions/{key}.json"
            execution_path.parent.mkdir(parents=True)
            artifact_root = workspace / f"artifacts/{key}/attempt-1"
            artifact_root.mkdir(parents=True)
            manifest_digest = json.loads(
                subprocess.check_output(
                    ["python3", str(target / "bin/runtime-static-verify.py"), "--target", str(target)], text=True
                )
            )["manifestDigest"]
            execution_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "featureId": "F-1",
                        "taskId": task,
                        "taskKey": key,
                        "attempt": 1,
                        "role": "backend",
                        "branch": branch,
                        "worktree": str(producer),
                        "worktreeMode": "standalone-clone",
                        "baseCommit": base,
                        "runtimeManifestDigest": manifest_digest,
                        "packetPath": str(artifact_root / "task-packet.md"),
                        "packetJsonPath": str(artifact_root / "task-packet.json"),
                        "reportPath": str(artifact_root / "task-report.md"),
                    }
                )
            )
            # Discard the earlier gate-role invocation. The remainder of the
            # log is the exact governed validation boundary under test.
            engine_log.write_text("")
            integration = subprocess.Popen(
                [str(target / "bin/integrate-task.sh"), "feature-runtime", "F-1", task, "backend", "1"],
                cwd=project,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": str(root)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(500):
                if validation_started.exists():
                    break
                time.sleep(0.01)
            if not validation_started.exists():
                validation_continue.touch()
                stdout, stderr = integration.communicate(timeout=30)
                self.fail(
                    "governed validator did not reach the protected runner\n"
                    + stdout + stderr
                    + ("\nengine:\n" + engine_log.read_text() if engine_log.exists() else "\n<no engine log>")
                )
            (producer / "task.txt").write_text("attacker moved producer after quarantine\n")
            subprocess.run(["git", "-C", str(producer), "add", "task.txt"], check=True)
            subprocess.run(["git", "-C", str(producer), "commit", "-qm", "post quarantine mutation"], check=True)
            moved_head = subprocess.check_output(["git", "-C", str(producer), "rev-parse", "HEAD"], text=True).strip()
            validation_continue.touch()
            stdout, stderr = integration.communicate(timeout=30)
            self.assertNotEqual(integration.returncode, 0, stdout + stderr)
            self.assertIn("missing safe tracker snapshot", stderr)
            package = next((workspace / f"artifacts/{key}").glob("review-*.diff"))
            package_text = package.read_text()
            self.assertIn(f"Head: {imported_head}", package_text)
            self.assertNotIn(moved_head, package_text)
            evidence_line = package_text.split("## Governed validation evidence\n", 1)[1].splitlines()[0]
            evidence = json.loads(evidence_line)
            self.assertEqual(evidence["importedCommit"], imported_head)
            self.assertEqual(
                evidence["importedTree"],
                subprocess.check_output(["git", "-C", str(project), "rev-parse", f"{imported_head}^{{tree}}"], text=True).strip(),
            )
            self.assertEqual(evidence["runtimeManifestSha256"], manifest_digest)
            self.assertFalse(evidence["canonicalRepositoryMounted"])
            self.assertFalse(evidence["producerCloneMounted"])
            self.assertEqual(evidence["network"], "none")
            full_log = engine_log.read_text()
            validation_clone = runtime_root / "attempt-clones" / "feature-runtime" / (
                f"integration-validator#1-{key[:64]}-task-head-validation-{imported_head[:16]}"
            )
            self.assertIn("--network=none", full_log)
            self.assertIn(
                f"type=bind,src={validation_clone},dst={validation_clone},rw",
                full_log,
            )
            self.assertNotIn(f"type=bind,src={project},", full_log)
            self.assertNotIn(f"type=bind,src={producer},", full_log)
            self.assertNotIn(str(runtime_root / "lifecycle"), full_log)
            self.assertNotIn("STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET", full_log)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", full_log)
            self.assertNotEqual(imported_head, moved_head)
            self.assertFalse(validation_clone.exists(), "verified disposable clone was not retired")

            # A second task exercises the protected merged-feature tree, broker
            # authorization, actual after-commit process death, and recovery.
            task2 = "F-1#combined-validation"
            key2 = subprocess.check_output(
                ["python3", str(target / "bin/runtime-state.py"), "key", task2], text=True
            ).strip()
            branch2 = f"agent-task/feature-runtime/{key2}"
            base2 = subprocess.check_output(
                ["git", "-C", str(project), "rev-parse", "feature-runtime"], text=True
            ).strip()
            created2 = subprocess.check_output(
                [
                    "python3", str(target / "bin/standalone_workspace.py"), "create",
                    "--repo", str(project), "--root", str(runtime_root / "attempt-clones"),
                    "--team", "feature-runtime", "--role", "backend", "--attempt", "1",
                    "--task-key", key2, "--branch", branch2, "--base-ref", base2,
                ],
                text=True,
            )
            producer2 = Path(json.loads(created2)["path"])
            (producer2 / "combined.txt").write_text("task side\n")
            subprocess.run(["git", "-C", str(producer2), "add", "combined.txt"], check=True)
            subprocess.run(["git", "-C", str(producer2), "commit", "-qm", "combined task"], check=True)
            head2 = subprocess.check_output(["git", "-C", str(producer2), "rev-parse", "HEAD"], text=True).strip()
            artifact2 = workspace / f"artifacts/{key2}/attempt-1"
            artifact2.mkdir(parents=True)
            execution2 = workspace / f"executions/{key2}.json"
            execution2.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "featureId": "F-1",
                        "taskId": task2,
                        "taskKey": key2,
                        "attempt": 1,
                        "role": "backend",
                        "branch": branch2,
                        "worktree": str(producer2),
                        "worktreeMode": "standalone-clone",
                        "baseCommit": base2,
                        "runtimeManifestDigest": manifest_digest,
                        "packetPath": str(artifact2 / "task-packet.md"),
                        "packetJsonPath": str(artifact2 / "task-packet.json"),
                        "reportPath": str(artifact2 / "task-report.md"),
                    }
                )
            )
            package2 = Path(
                subprocess.check_output(
                    [str(target / "bin/review-package.sh"), "feature-runtime", task2],
                    cwd=project,
                    env={"PATH": "/usr/bin:/bin", "TMPDIR": str(root)},
                    text=True,
                ).strip()
            )
            package_digest2 = "sha256:" + hashlib.sha256(package2.read_bytes()).hexdigest()
            package_text2 = package2.read_text()
            review_base2 = re.search(r"(?m)^Base: ([0-9a-f]+)$", package_text2).group(1)
            request_raw = root / "request-raw.md"
            request_bound = root / "request-bound.md"
            request_raw.write_text("[review-request]\nFiles: combined.txt\n\n- backend\n")
            preset = workspace / "preset.env"
            preset_text = preset.read_text() if preset.exists() else ""
            gate_match = re.search(r"(?m)^REQUIRED_REVIEW_GATES=([^\n]+)$", preset_text)
            gates = "" if not gate_match or gate_match.group(1).strip() in {"", "null"} else gate_match.group(1).strip()
            bind_request = [
                "python3", str(target / "bin/review_evidence.py"), "bind-request",
                str(request_raw), review_base2, head2, package_digest2, str(request_bound),
            ]
            if gates:
                bind_request += ["--review-gates", gates]
            subprocess.run(bind_request, check=True)
            request_only = root / "request-only.json"
            request_only.write_text(
                json.dumps(
                    {
                        "featureId": "F-1",
                        "tasks": [
                            {
                                "taskId": task2,
                                "title": "Combined validation",
                                "description": "",
                                "status": "Review",
                                "labels": [],
                                "comments": [{"body": request_bound.read_text()}],
                            }
                        ],
                    }
                )
            )
            approvals: list[str] = []
            approval_specs = [
                ("architecture-approval", "principal-architect", "gate:architect"),
                ("sceptical-architecture-approval", "sceptical-architect", "gate:sceptical"),
            ]
            if "security" in {part.strip() for part in gates.split(",") if part.strip()}:
                approval_specs.append(("security-approval", "security-reviewer", "gate:security"))
            approval_specs.append(("team-lead-approval", "team-lead", "gate:team-lead"))
            for index, (marker, role, context) in enumerate(approval_specs):
                raw = root / f"approval-{index}-raw.md"
                bound = root / f"approval-{index}-bound.md"
                raw.write_text(f"[{marker}]\nFiles: combined.txt\n\n- {role}\n")
                subprocess.run(
                    [
                        "python3", str(target / "bin/review_evidence.py"), "bind-approval",
                        str(raw), str(request_only), task2, str(bound), role, context,
                    ],
                    check=True,
                )
                approvals.append(bound.read_text())
            snapshot = {
                "featureId": "F-1",
                "tasks": [
                    {
                        "taskId": task2,
                        "title": "Combined validation",
                        "description": "",
                        "status": "Review",
                        "labels": [],
                        "comments": [{"body": request_bound.read_text()}]
                        + [{"body": body} for body in approvals],
                    }
                ],
            }
            authoritative_snapshot.write_text(json.dumps(snapshot))
            (workspace / "tasks.json").write_text(json.dumps(snapshot))
            integration2 = [
                str(target / "bin/integrate-task.sh"), "feature-runtime", "F-1", task2, "backend", "1",
            ]
            environment = {"PATH": "/usr/bin:/bin", "TMPDIR": str(root)}
            prepared = subprocess.run(
                integration2, cwd=project, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False, timeout=30,
            )
            project_status = subprocess.check_output(
                ["git", "-C", str(project), "status", "--porcelain=v1", "-uall"], text=True
            )
            self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr + project_status)
            self.assertIn("awaiting fresh credentialed broker authorization", prepared.stdout)
            preparation = workspace / f"integrations/.prepared/{key2}.json"
            authorized = subprocess.run(
                [str(target / "bin/finalize-integrations.sh"), "--authorize-prepared", "feature-runtime", "F-1", str(preparation)],
                cwd=project, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, check=False, timeout=30,
            )
            self.assertEqual(authorized.returncode, 0, authorized.stdout + authorized.stderr)

            reject_merged.touch()
            rejected = subprocess.run(
                integration2, cwd=project, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False, timeout=30,
            )
            self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
            self.assertIn("exact merged feature tree failed", rejected.stderr)
            self.assertEqual(
                subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"], text=True).strip(),
                base2,
            )
            self.assertEqual(
                subprocess.check_output(["git", "-C", str(project), "status", "--porcelain=v1", "-uall"], text=True),
                "",
            )
            reject_merged.unlink()

            crash_environment = {**environment, "INTEGRATION_TEST_CRASH_AT": "after-commit"}
            crashed = subprocess.run(
                integration2, cwd=project, env=crash_environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False, timeout=30,
            )
            self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stdout + crashed.stderr)
            integration_head = subprocess.check_output(
                ["git", "-C", str(project), "rev-parse", "HEAD"], text=True
            ).strip()
            merge_evidence = next((workspace / f"artifacts/{key2}").glob("governed-validation-merged-feature-*.json"))
            merge_evidence_before = merge_evidence.read_bytes()
            merge_record = json.loads(merge_evidence_before)

            merge_evidence.write_bytes(merge_evidence_before + b"tamper")
            tampered = subprocess.run(
                integration2, cwd=project, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False, timeout=30,
            )
            self.assertNotEqual(tampered.returncode, 0)
            merge_evidence.write_bytes(merge_evidence_before)

            merge_ref2 = merge_record["quarantineRef"]
            subprocess.run(["git", "-C", str(project), "update-ref", merge_ref2, base2, merge_record["importedCommit"]], check=True)
            moved_ref = subprocess.run(
                integration2, cwd=project, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False, timeout=30,
            )
            self.assertNotEqual(moved_ref.returncode, 0)
            subprocess.run(["git", "-C", str(project), "update-ref", merge_ref2, merge_record["importedCommit"], base2], check=True)

            original_message = subprocess.check_output(
                ["git", "-C", str(project), "show", "-s", "--format=%B", integration_head], text=True
            )
            missing_message = "\n".join(
                line for line in original_message.splitlines() if not line.startswith("Merge-Validation-SHA256:")
            )
            subprocess.run(["git", "-C", str(project), "commit", "--amend", "-qm", missing_message], check=True)
            amended = subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"], text=True).strip()
            missing_trailer = subprocess.run(
                integration2, cwd=project, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False, timeout=30,
            )
            self.assertNotEqual(missing_trailer.returncode, 0)
            self.assertIn("lacks its protected validation evidence binding", missing_trailer.stderr)
            subprocess.run(
                ["git", "-C", str(project), "update-ref", "refs/heads/feature-runtime", integration_head, amended],
                check=True,
            )

            merge_evidence.unlink()
            reject_merged.touch()
            missing_evidence = subprocess.run(
                integration2, cwd=project, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False, timeout=30,
            )
            self.assertNotEqual(missing_evidence.returncode, 0)
            self.assertFalse(merge_evidence.exists())
            reject_merged.unlink()
            recovered = subprocess.run(
                integration2, cwd=project, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False, timeout=30,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
            self.assertIn("awaiting credentialed tracker broker", recovered.stdout)
            transaction2 = json.loads((workspace / f"integrations/{key2}.json").read_text())
            self.assertEqual(transaction2["commit"], integration_head)
            self.assertEqual(transaction2["mergeValidationTree"], merge_record["importedTree"])
            self.assertRegex(transaction2["mergeValidationSha256"], r"^sha256:[0-9a-f]{64}$")
            validated_transaction = subprocess.run(
                [
                    str(target / "bin/finalize-integrations.sh"), "--validate-only",
                    "feature-runtime", "F-1", str(workspace / f"integrations/{key2}.json"),
                ],
                cwd=project,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(
                validated_transaction.returncode,
                0,
                validated_transaction.stdout + validated_transaction.stderr,
            )


if __name__ == "__main__":
    unittest.main()
