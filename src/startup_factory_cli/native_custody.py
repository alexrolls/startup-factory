"""Native custody inside the independently installed persistent job service.

This object is not an independent service by itself. The protected service
hosts the controller, job runner, adapter and this manager in the same process;
launcher clients receive job frames, never these Python objects or raw Popen
handles. No method below issues enrollment, reconciliation or a daemon queue
barrier. A service crash leaves durable uncertainty and requires requalification.
"""
from __future__ import annotations

import contextlib
import hashlib
import math
import os
import secrets
import selectors
import subprocess
import threading
import time
from typing import Any, Sequence

from .execution_backend import DockerProfile, canonical_digest
from .native_clients import GatedClient, NativeClientError, NativeClientJournal, NativeIntent
from .sandbox_exec_probe import CommandResult


class CustodyError(NativeClientError):
    """Dispatch or native delivery is refused or uncertain."""


def _budget(value: Any, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise CustodyError("native byte budget is invalid")
    return value


class CustodiedProcess:
    """Private adapter handle; all numeric-PID authority stays with the journal."""
    def __init__(self, manager: JournalCustody, handle: GatedClient, timeout: float, intent: NativeIntent) -> None:
        self._manager, self._handle = manager, handle
        self._intent = intent
        self.pid = handle.process.pid
        self.stdin, self.stdout, self.stderr = handle.stdin, handle.stdout, handle.stderr
        self._timer = threading.Timer(timeout, self._expire)
        self._timer.daemon = True
        self._timer.start()

    @property
    def returncode(self) -> int | None:
        return self._handle.process.returncode

    def poll(self) -> int | None:
        raise CustodyError("native polling belongs to the persistent custody owner")

    def wait(self, timeout: float | None = None) -> int:
        raise CustodyError("native reaping belongs to the persistent custody owner")

    def _expire(self) -> None:
        with contextlib.suppress(Exception):
            self._cancel_owned()

    def _reap_owned(self, *, timeout: float) -> int:
        self._manager._owner()
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("owned native client", timeout)
                # Serialize each waitpid attempt against group cancellation so
                # a reaped PID can never be signaled. Short waits let the
                # independent service timer/disconnect path acquire custody.
                with self._handle._lock:
                    try:
                        return self._handle.process._reap_owned(timeout=min(.05, remaining))
                    except subprocess.TimeoutExpired:
                        pass
                time.sleep(0)
        except subprocess.TimeoutExpired:
            raise
        except Exception as exc:
            self._manager._uncertain(self, "native exit durability is uncertain")
            raise CustodyError("native exit durability is uncertain") from exc

    def _acknowledge(self, response_digest: str) -> None:
        self._manager._owner()
        try:
            self._handle.acknowledge(response_digest)
        except Exception as exc:
            self._manager._uncertain(self, "native response acknowledgment failed")
            raise CustodyError("native response acknowledgment failed") from exc
        self._timer.cancel()
        self._manager._retire(self)

    def _cancel_owned(self) -> None:
        # Journal/profile health must never block same-owner child cleanup.
        self._manager._custody_owner()
        self._timer.cancel()
        self._manager._uncertain(self, "native request cancelled or launcher disconnected")
        try:
            self._handle.cancel()
        finally:
            if self.returncode is not None:
                self._manager._retire(self)

    def _mark_uncertain(self) -> None:
        self._manager._custody_owner()
        self._manager._uncertain(self, "native lifecycle authority became uncertain")


class JournalCustody:
    """Finite native ownership in one persistent service PID, never readiness.

    Registry/task leases and enrollment remain external mandatory authorities.
    Clean journal history does not prove daemon or namespace quiescence. After
    ambiguous delivery, allocation/exec remain blocked for this journal history;
    there is deliberately no reset/unfence API.
    """
    def __init__(self, journal: NativeClientJournal) -> None:
        if type(journal) is not NativeClientJournal:
            raise CustodyError("a protected pre-exec journal is required")
        self.journal = journal
        self._pid = os.getpid()
        self._lock = threading.RLock()
        self._closed = False
        self._authority: Any = None
        self._active: dict[str, CustodiedProcess] = {}
        self._blocked = any(record["state"] not in {"completed-acknowledged", "aborted-before-release"}
                            for record in journal.records())

    def _custody_owner(self) -> None:
        if os.getpid() != self._pid:
            raise CustodyError("native custody cannot be inherited")

    def _owner(self) -> None:
        self._custody_owner()
        if self._closed:
            raise CustodyError("native custody is closed")
        self.journal._check()
        records = self.journal.records()
        if any(record["state"] == "delivery-uncertain" or
               record["controllerPid"] != self._pid and record["state"] not in
               {"completed-acknowledged", "aborted-before-release"} for record in records):
            self._blocked = True

    def bind_reconciler(self, authority: Any) -> None:
        self._owner()
        with self._lock:
            if authority is None or self._authority is not None and authority is not self._authority:
                raise CustodyError("native reconciliation authority cannot be replaced")
            self._authority = authority

    def is_bound_to(self, backend: Any, profile: DockerProfile) -> bool:
        self._owner()
        return (profile == self.journal.profile and getattr(backend, "custody", None) is self
                and self._authority is not None
                and getattr(backend, "native_client_reconciler", None) is self._authority)

    @property
    def pool_blocked(self) -> bool:
        self._custody_owner()
        try:
            self._owner()
        except Exception:
            self._blocked = True
        return self._blocked

    def _retire(self, process: CustodiedProcess) -> None:
        with self._lock:
            self._active.pop(process._handle.client_id, None)

    def _uncertain(self, process: CustodiedProcess, reason: str) -> None:
        self._custody_owner()
        with self._lock:
            self._blocked = True
        # The pre-release record is already durable if this save fails. A
        # poisoned/incomplete history also blocks the next service instance.
        with contextlib.suppress(Exception):
            self.journal._update(process._handle.client_id, state="delivery-uncertain",
                                 responseDigest=None, reason=reason)

    def _intent(self, profile: DockerProfile, permit: Any, argv: Sequence[str], operation: str | None) -> NativeIntent:
        # Import lazily to keep the adapter/manager dependency one-way at load.
        from .docker_backend import OperationPermit
        if type(profile) is not DockerProfile or profile != self.journal.profile or type(permit) is not OperationPermit:
            raise CustodyError("native request differs from its protected service profile")
        if self._authority is None:
            raise CustodyError("native custody has no bound controller authority")
        prefix = (profile.sbx_path, "--app-name", profile.namespace, "--no-input")
        argv = tuple(argv)
        if len(argv) < 5 or argv[:4] != prefix:
            raise CustodyError("native command has an unsafe namespace prefix")
        op = {"create": "create", "inspect": "inspect", "ls": "list", "stop": "stop", "rm": "destroy", "exec": operation or "open-session", "secret": operation, "policy": operation}.get(argv[4])
        if op is None or op not in {"create", "inspect", "list", "stop", "destroy", "open-session", "provision", "collect", "credential-set", "credential-remove", "policy-inspect", "policy-allow", "policy-remove-lock"}:
            raise CustodyError("native command is outside the fixed adapter command tree")
        if self._blocked and op not in {"inspect", "list", "stop", "destroy", "credential-remove"}:
            raise CustodyError("native delivery is uncertain; new workload dispatch is blocked")
        name = permit.reserved_name
        if name is None and op == "list":
            name = "sf-" + secrets.token_hex(16)  # journal identity only; never a VM allocation
        return NativeIntent(profile.namespace, name, permit.generation, permit.epoch, permit.request_digest, op)

    def open_process(self, profile: DockerProfile, permit: Any, argv: Sequence[str], *, timeout_seconds: float,
                     operation: str | None = None) -> CustodiedProcess:
        self._owner()
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= profile.limits.wall_seconds:
            raise CustodyError("native wall deadline is invalid")
        with self._lock:
            intent = self._intent(profile, permit, argv, operation)
            if len(self._active) >= 128:
                raise CustodyError("active native client quota exhausted")
            handle = None
            try:
                authorize = getattr(self._authority, "authorize_native", None)
                if callable(authorize) and authorize(profile, permit, intent) is not True:
                    raise CustodyError("current native authority refused dispatch")
                handle = self.journal.prepare(intent, tuple(argv))
                if callable(authorize) and authorize(profile, permit, intent) is not True:
                    raise CustodyError("native authority expired before gated release")
                handle.release()
                process = CustodiedProcess(self, handle, float(timeout_seconds), intent)
                self._active[handle.client_id] = process
                return process
            except Exception:
                # A failed spawn can have crossed release. Retain history and
                # refuse new jobs even when same-owner cleanup succeeded.
                self._blocked = True
                if handle is not None:
                    with contextlib.suppress(Exception):
                        handle.cancel()
                raise

    def run_control(self, profile: DockerProfile, permit: Any, argv: Sequence[str], *, timeout_seconds: float,
                    max_stdout_bytes: int, max_stderr_bytes: int, operation: str | None = None) -> CommandResult:
        return self._capture(profile, permit, argv, timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes, max_stderr_bytes=max_stderr_bytes, operation=operation)

    def _capture(self, profile: DockerProfile, permit: Any, argv: Sequence[str], *, timeout_seconds: float,
                 max_stdout_bytes: int, max_stderr_bytes: int, secret: bytes | bytearray | None = None,
                 operation: str | None = None) -> CommandResult:
        out_limit = _budget(max_stdout_bytes, maximum=256 * 1024)
        err_limit = _budget(max_stderr_bytes, maximum=256 * 1024)
        deadline = time.monotonic() + timeout_seconds
        process = self.open_process(profile, permit, argv, timeout_seconds=timeout_seconds, operation=operation)
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {"stdout": out_limit, "stderr": err_limit}
        counts = {"stdout": 0, "stderr": 0}
        view = memoryview(secret) if secret is not None else None
        offset = 0
        try:
            with selectors.DefaultSelector() as selector:
                if view is None:
                    process.stdin.close()
                else:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "input")
                for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise CustodyError("native control deadline exceeded")
                    for key, _event in selector.select(min(remaining, .1)):
                        if key.data == "input":
                            try:
                                offset += os.write(key.fileobj.fileno(), view[offset:offset + 16384])
                            except (BlockingIOError, InterruptedError):
                                continue
                            if offset == len(view):
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                            continue
                        try:
                            chunk = os.read(key.fileobj.fileno(), 8192)
                        except (BlockingIOError, InterruptedError):
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                        elif counts[key.data] + len(chunk) > limits[key.data]:
                            raise CustodyError("native control output limit exceeded")
                        else:
                            counts[key.data] += len(chunk)
                            if operation not in {"credential-set", "credential-remove"}:
                                captured[key.data].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CustodyError("native control completion deadline exceeded")
            code = process._reap_owned(timeout=remaining)
            output, errors = bytes(captured["stdout"]), bytes(captured["stderr"])
            if operation in {"credential-set", "credential-remove"}:
                # Even a vendor diagnostic echo of input must never become a
                # persisted secret hash. Bind only nonsensitive operation data.
                response = {"returncode": code, "operation": operation, "requestDigest": permit.request_digest}
            else:
                response = {"returncode": code, "stdout": "sha256:" + hashlib.sha256(output).hexdigest(),
                            "stderr": "sha256:" + hashlib.sha256(errors).hexdigest()}
            process._acknowledge(canonical_digest(response))
            return CommandResult(code, output, errors)
        except BaseException:
            with contextlib.suppress(Exception):
                process._cancel_owned()
            raise
        finally:
            if view is not None:
                view.release()
            process._handle._close_io()

    def run_credential(self, profile: DockerProfile, permit: Any, *, operation: str,
                       service: str = "openai", secret: bytes | bytearray | None = None) -> str:
        if operation not in {"credential-set", "credential-remove"} or service != "openai":
            raise CustodyError("only the qualified OpenAI scoped credential command is supported")
        if (operation == "credential-set" and (type(secret) not in {bytes, bytearray} or not 1 <= len(secret) <= 16384)
            or operation == "credential-remove" and secret is not None):
            raise CustodyError("credential input must be bounded stdin only")
        argv = (profile.sbx_path, "--app-name", profile.namespace, "--no-input", "secret",
                "set" if operation == "credential-set" else "rm", service, "--sandbox", permit.reserved_name, "--force")
        result = self._capture(profile, permit, argv, timeout_seconds=min(30, profile.limits.wall_seconds),
                               max_stdout_bytes=16384, max_stderr_bytes=16384, secret=secret, operation=operation)
        if result.returncode != 0:
            raise CustodyError("scoped credential command did not acknowledge completion")
        return canonical_digest({"operation": operation, "requestDigest": permit.request_digest,
            "profileDigest": profile.digest, "namespace": profile.namespace, "name": permit.reserved_name,
            "generation": permit.generation, "epoch": permit.epoch, "provider": service})

    def cancel_generation(self, name: str, generation: str, epoch: int) -> None:
        self._custody_owner()
        failure = None
        with self._lock:
            matches = [process for process in self._active.values()
                       if self._matches(process, name, generation, epoch)]
        for process in matches:
            try:
                process._cancel_owned()
            except Exception as exc:
                failure = failure or exc
        if failure is not None:
            raise CustodyError("native cancellation remains uncertain") from failure

    @staticmethod
    def _matches(process: CustodiedProcess, name: str, generation: str, epoch: int) -> bool:
        intent = process._intent
        return (intent.name, intent.generation, intent.epoch) == (name, generation, epoch)

    def diagnostics(self) -> dict[str, Any]:
        self._custody_owner()
        blocked = self.pool_blocked
        with self._lock:
            return {"schemaVersion": 1, "scope": "native-service-custody-only", "ownerPid": self._pid,
                    "activeClients": len(self._active), "poolBlocked": blocked,
                    "lateCommandsQuiescent": False, "qualified": False, "autonomousReady": False}

    def close(self) -> None:
        self._custody_owner()
        failure = None
        with self._lock:
            self._closed = True
            active = tuple(self._active.values())
        for process in active:
            try:
                process._cancel_owned()
            except Exception as exc:
                failure = failure or exc
        try:
            self.journal.close()
        except Exception as exc:
            failure = failure or exc
        if failure is not None:
            raise CustodyError("native service shutdown remains uncertain") from failure
