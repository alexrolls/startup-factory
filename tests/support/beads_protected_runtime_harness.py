"""Non-production logic harness for protected Beads runtime tests.

This module is deliberately outside ``src/`` and is not part of the wheel or
runtime installation.  It supplies only deterministic test provenance.  The
production module has no offline bypass and rejects records written under this
domain when its production provenance requirement is restored.
"""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterator


TEST_PROVENANCE = "startup-factory/beads-boundary-controller/test-harness/v1"


class LogicHarness:
    def __init__(
        self,
        runtime: Any,
        protected_root: Path,
        hmac_key_path: Path,
        repository_locator_sha256: str,
    ) -> None:
        self.runtime = runtime
        self.protected_root = protected_root
        self.hmac_key_path = hmac_key_path
        self.repository = repository_locator_sha256
        self._saved: dict[str, Any] = {}
        self._tokens: tuple[Any, Any] | None = None

    def _config(self) -> Any:
        digest = self.runtime.sha256
        controller = self.runtime._boundary_controller
        return controller.ControllerConfig(
            beads_enabled=True,
            protected_root=self.protected_root,
            record_hmac_key_path=self.hmac_key_path,
            controller_uid=91_001,
            broker_uid=91_002,
            worker_uid=91_003,
            transport_gid=91_004,
            runtime_manifest_path=Path(
                "/usr/lib/startup-factory/test-runtime-manifest.json"
            ),
            module_path=Path(
                "/usr/lib/startup-factory/test-controller-module.py"
            ),
            schema_path=Path(
                "/usr/lib/startup-factory/test-runtime-schema.json"
            ),
            runtime_manifest_sha256=digest(b"test-runtime-manifest"),
            module_sha256=digest(b"test-module"),
            schema_sha256=digest(b"test-schema"),
            config_epoch=1,
            key_epoch=1,
            native_boundary_manifest_path=Path(
                "/usr/lib/startup-factory/test-native-boundary-v27.json"
            ),
            native_boundary_manifest_sha256=digest(b"test-native-boundary-v27"),
            native_module_path=Path(controller.native_boundary_v27.__file__),
            native_module_sha256=digest(b"test-native-module-v27"),
        )

    def _session_and_operation(
        self, operation: str, repository: str, request_sha256: str
    ) -> tuple[Any, MappingProxyType]:
        config = self._config()
        operation_id = self.runtime.sha256(
            self.runtime.canonical_bytes(
                {
                    "harness": TEST_PROVENANCE,
                    "operation": operation,
                    "repository": repository,
                    "requestSha256": request_sha256,
                }
            )
        ).removeprefix("sha256:")
        receipt = self.runtime.sha256(
            self.runtime.canonical_bytes(
                {"operationId": operation_id, "state": "effect-authorized"}
            )
        )
        response = {
            "operationId": operation_id,
            "sessionNonce": "test-harness-session-nonce-0001",
            "receiptSha256": receipt,
            "state": "effect-authorized",
            "resultSha256": None,
        }
        session = self.runtime._ControllerBoundarySessionV1(
            config=config,
            response=response,
            operation=operation,
            request_sha256=request_sha256,
            repository_locator_sha256=repository,
            effect_authorization_receipt_sha256=receipt,
        )
        operation_record = MappingProxyType(
            {
                "schemaVersion": 1,
                "operation": operation,
                "requestSha256": request_sha256,
                "repositoryLocatorSha256": repository,
                "rootSetSha256": config.root_set_sha256,
                "sessionReceiptSha256": receipt,
                "runtimeManifestSha256": config.runtime_manifest_sha256,
                "moduleSha256": config.module_sha256,
                "verifierIdentitySha256": self.runtime.sha256(
                    TEST_PROVENANCE.encode("utf-8")
                ),
                "expiresAtUnix": int(time.time()) + 86_400,
                "controllerOperationId": operation_id,
                "controllerProvenanceDomain": TEST_PROVENANCE,
            }
        )
        return session, operation_record

    def __enter__(self) -> "LogicHarness":
        runtime = self.runtime
        for name in (
            "_controller_operation",
            "_validate_live_boundary_session",
            "_complete_controller_operation",
            "_execute_supervised_beads_effect_v27",
            "_REQUIRED_PROVENANCE_DOMAIN",
        ):
            self._saved[name] = getattr(runtime, name)

        @contextlib.contextmanager
        def controller_operation(
            operation: str,
            repository: str,
            request_sha256: str,
            requested_paths: tuple[str, str],
        ) -> Iterator[Any]:
            if requested_paths != (
                str(self.protected_root),
                str(self.hmac_key_path),
            ):
                raise runtime.BeadsProtectedRuntimeError(
                    "test harness request paths differ from its isolated root"
                )
            session, operation_record = self._session_and_operation(
                operation, repository, request_sha256
            )
            session_token = runtime._BOUNDARY_SESSION_CONTEXT.set(session)
            operation_token = runtime._BOUNDARY_OPERATION_CONTEXT.set(operation_record)
            try:
                yield session
            finally:
                runtime._BOUNDARY_OPERATION_CONTEXT.reset(operation_token)
                runtime._BOUNDARY_SESSION_CONTEXT.reset(session_token)

        def validate(session: Any = None) -> Any:
            candidate = (
                runtime._BOUNDARY_SESSION_CONTEXT.get()
                if session is None
                else session
            )
            if not isinstance(candidate, runtime._ControllerBoundarySessionV1):
                raise runtime.BeadsProtectedRuntimeError(
                    "test harness has no bound logic session"
                )
            return candidate

        def complete(session: Any, result: Any) -> None:
            session.completed = True

        def execute_supervised_effect(
            *, authorization_record_sha256: str
        ) -> MappingProxyType:
            if not isinstance(authorization_record_sha256, str):
                raise runtime.BeadsProtectedRuntimeError(
                    "test harness received an invalid protected authorization"
                )
            records = []
            for path in self.protected_root.rglob("*.json"):
                try:
                    candidate = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                payload = candidate.get("payload")
                if (
                    isinstance(payload, dict)
                    and runtime.sha256(runtime.canonical_bytes(payload))
                    == authorization_record_sha256
                ):
                    records.append(payload)
            if len(records) != 1:
                raise runtime.BeadsProtectedRuntimeError(
                    "test harness cannot resolve one protected authorization record"
                )
            authority = records[0]
            session = runtime._BOUNDARY_SESSION_CONTEXT.get()
            if (
                isinstance(session, runtime._ControllerBoundarySessionV1)
                and session.operation == "finish_beads_preparation_v1"
            ):
                mode = authority.get("preparationMode")
                stages = (
                    [
                        "binary-proof-payload-terminal",
                        "initialize-payload-terminal",
                        "status-write-payload-terminal",
                        "status-read-payload-terminal",
                    ]
                    if mode == "create"
                    else ["status-read-payload-terminal"]
                )
                return MappingProxyType(
                    {
                        "schemaVersion": 27,
                        "profile": "startup-factory/beads-native-boundary/v27",
                        "preparationState": "sequence-completed",
                        "operationClass": (
                            "create-preparation"
                            if mode == "create"
                            else "reattest-preparation"
                        ),
                        "commandCount": len(stages),
                        "commandStages": stages,
                        "commandResultsSha256": [
                            runtime.sha256(stage.encode("utf-8")) for stage in stages
                        ],
                        "observedByNativeSupervisor": True,
                    }
                )
            argv = authority.get("argv", ["fixture-native-effect"])
            if "init" in argv and "--db" in argv:
                database_path = Path(argv[argv.index("--db") + 1])
                database_path.mkdir(mode=0o700, parents=False, exist_ok=False)
                (database_path / ".dolt").mkdir(mode=0o700)
                manifest = database_path / "manifest.json"
                manifest.write_bytes(b'{"database":"dolt","schemaVersion":1}\n')
                manifest.chmod(0o600)
            task_id = authority.get("taskId", "fixture-task")
            revision = authority.get("observedRevision")
            if revision is None:
                expected = authority.get("expectedRevision")
                revision = "r2" if expected == "r1" else "fixture-revision"
            projection = {
                "comments": [],
                "dependencies": [],
                "id": task_id,
                "labels": [],
                "revision": revision,
                "status": authority.get("observedStatus") or "active",
            }
            observation = runtime.canonical_bytes(
                {
                    "authorizationRecordSha256": authorization_record_sha256,
                    "projection": projection,
                }
            )
            read_back_digest = runtime.sha256(runtime.canonical_bytes(projection))
            return MappingProxyType(
                {
                    "exitCode": 0,
                    "stdoutSha256": runtime.sha256(observation),
                    "stderrSha256": runtime.sha256(b""),
                    "readBackSha256": read_back_digest,
                    "readBackProjection": projection,
                    "readBacksSha256": [read_back_digest] * 4,
                    "physicalEqualityPasses": [True, True],
                    "repeatabilityPasses": [True] * 6,
                    "repeatabilityEvidenceSha256": runtime.sha256(
                        b"harness-repeatability"
                    ),
                    "rollingJoinPasses": [True] * 5,
                    "rollingJoinEvidenceSha256": runtime.sha256(
                        b"harness-rolling-joins"
                    ),
                    "crossWindowNoEffect": True,
                    "crossWindowNoEffectEvidenceSha256": runtime.sha256(
                        b"harness-cross-window"
                    ),
                    "independentReadCount": 4,
                    "lifecycle": [
                        "create",
                        "init",
                        "start-attach",
                        "terminal",
                        "cleanup",
                        "rm",
                    ],
                    "observedByNativeSupervisor": True,
                }
            )

        runtime._controller_operation = controller_operation
        runtime._validate_live_boundary_session = validate
        runtime._complete_controller_operation = complete
        runtime._execute_supervised_beads_effect_v27 = execute_supervised_effect
        runtime._REQUIRED_PROVENANCE_DOMAIN = TEST_PROVENANCE
        session, operation = self._session_and_operation(
            "test-harness-lexical-context",
            self.repository,
            self.runtime.sha256(b"test-harness-lexical-request"),
        )
        self._tokens = (
            runtime._BOUNDARY_SESSION_CONTEXT.set(session),
            runtime._BOUNDARY_OPERATION_CONTEXT.set(operation),
        )
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        runtime = self.runtime
        if self._tokens is not None:
            session_token, operation_token = self._tokens
            runtime._BOUNDARY_OPERATION_CONTEXT.reset(operation_token)
            runtime._BOUNDARY_SESSION_CONTEXT.reset(session_token)
            self._tokens = None
        for name, value in self._saved.items():
            setattr(runtime, name, value)
        self._saved.clear()

    def bind_repository(self, repository_locator_sha256: str) -> None:
        """Rebind the lexical direct-store context used by one test case."""

        if self._tokens is None:
            raise RuntimeError("logic harness is not active")
        runtime = self.runtime
        session_token, operation_token = self._tokens
        runtime._BOUNDARY_OPERATION_CONTEXT.reset(operation_token)
        runtime._BOUNDARY_SESSION_CONTEXT.reset(session_token)
        self.repository = repository_locator_sha256
        session, operation = self._session_and_operation(
            "test-harness-lexical-context",
            self.repository,
            self.runtime.sha256(b"test-harness-lexical-request"),
        )
        self._tokens = (
            runtime._BOUNDARY_SESSION_CONTEXT.set(session),
            runtime._BOUNDARY_OPERATION_CONTEXT.set(operation),
        )


def logic_harness(
    runtime: Any,
    protected_root: Path,
    hmac_key_path: Path,
    repository_locator_sha256: str,
) -> LogicHarness:
    return LogicHarness(
        runtime,
        protected_root,
        hmac_key_path,
        repository_locator_sha256,
    )
