"""Pinned sbx v0.54.0 adapter behind an external authorization boundary.

This module cannot enroll, qualify, or resume a controller on its own. The
permit provider must authenticate current profile/policy/qualification evidence,
exclusive access to every namespace endpoint, a lifecycle lease, and independent
orphan reconciliation. A digest or an inspect result is not that authorization.

sbx addresses names, not immutable IDs. Repeated checks do not close that race:
the external exclusive-controller invariant and permanent name reservations are
mandatory. A session lease must allow independent epoch fencing/revocation; it
must not block the authority responsible for stopping a compromised generation.

Native client children have one wait/reap owner. Foreign waitpid/SIGCHLD reapers
are unsupported. Cancelling a native client never establishes that its VM
stopped. Controller death/orphan takeover requires an external reconciler.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import pwd
import re
import selectors
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, ContextManager, Mapping, Sequence

from .execution_backend import (
    ArtifactReference, BackendContractError, BackendIdentity, BackendObservation,
    BackendProbe, DockerProfile, GuestCommand, LaunchSpec, canonical_digest, load_profile,
)
from .sandbox_exec_probe import CommandResult, ExecProbeError, INSPECT_FIELDS, _json_object
from .native_clients import NativeClientError
from .native_custody import JournalCustody
from .sandbox_network_policy import ModelNetworkPolicy, verify_effective_policy


VERSION = "v0.54.0"
MAX_METADATA_BYTES = 64 * 1024
MAX_LIST_BYTES = 256 * 1024
MAX_LIST_ROWS = 128
MAX_TRACKED_NAMES = 1024
CONTROL_TIMEOUT_SECONDS = 30.0
_NAME = re.compile(r"sf-[0-9a-f]{32}\Z")
_GENERATION = re.compile(r"gen-[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INSPECT_REQUIRED = frozenset({
    "name", "id", "created_at", "created_version", "daemon_version", "state", "cpus",
    "memory", "image_digest", "kits", "host_mounts", "runtime_mounts", "working_dir",
    "mcp_mode", "mcp_servers", "network", "network_policy",
})
_LIST_FIELDS = frozenset({
    "name", "id", "agent", "status", "last_used_at", "cpus", "memory", "memory_mib", "created_at",
})
_OPERATIONS = frozenset({"probe", "create", "inspect", "open-session", "provision", "collect", "stop", "destroy", "credential-set", "credential-remove", "policy-activate"})
MAX_TRANSFER_BYTES = 44 * 1024 * 1024


class DockerBackendError(BackendContractError):
    """An operation was refused, failed, or left externally reconcilable uncertainty."""


class DockerBackendUnsupported(DockerBackendError):
    """The adapter intentionally has no safe implementation for this operation."""


@dataclasses.dataclass(frozen=True)
class OperationRequest:
    operation: str
    profile_digest: str
    namespace: str
    controller_pid: int
    identity: BackendIdentity | None = None
    launch_spec: LaunchSpec | None = None
    guest_command: GuestCommand | None = None

    def as_dict(self) -> dict[str, Any]:
        launch = None if self.launch_spec is None else {
            "scope": self.launch_spec.scope.as_dict(),
            "profileDigest": self.launch_spec.profile_digest,
            "command": self.launch_spec.command.as_dict(),
        }
        return {"operation": self.operation, "profileDigest": self.profile_digest,
                "namespace": self.namespace, "controllerPid": self.controller_pid,
                "identity": None if self.identity is None else self.identity.as_dict(),
                "launchSpec": launch,
                "guestCommand": None if self.guest_command is None else self.guest_command.as_dict()}

    @property
    def digest(self) -> str:
        return canonical_digest(self.as_dict())


@dataclasses.dataclass(frozen=True)
class OperationPermit:
    """Issued only by trusted host code after validating external authority.

    The callback context must keep its lifecycle lease valid until exit. These
    fields bind its decision, but this object itself is not a signed attestation
    or a substitute for the provider's checks. No guest JSON creates permits.
    """
    request_digest: str
    reserved_name: str | None
    generation: str
    epoch: int
    reconciliation_digest: str


PermitProvider = Callable[[DockerProfile, OperationRequest], ContextManager[OperationPermit]]
CommandRunner = Callable[..., CommandResult]


def _child_owner() -> None:
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise DockerBackendError("native client ownership requires default SIGCHLD handling and no foreign child reaper")


class _OwnedProcess(subprocess.Popen[bytes]):
    """The session alone may consume the child's reserved PID by waiting."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._owner_active = False
        super().__init__(*args, **kwargs)
        self._owner_active = True

    def poll(self) -> int | None:
        if not self._owner_active:
            return super().poll()
        raise DockerBackendError("native client polling belongs to its session owner")

    def wait(self, timeout: float | None = None) -> int:
        if not getattr(self, "_owner_active", False):
            return super().wait(timeout=timeout)
        raise DockerBackendError("native client reaping belongs to its session owner")

    def _reap_owned(self, *, timeout: float) -> int:
        return super().wait(timeout=timeout)


class _Pipe(io.RawIOBase):
    def __init__(self, session: NativeSession, stream: Any, *, writing: bool, label: str) -> None:
        super().__init__()
        self._session = session
        self._stream = stream
        self._writing = writing
        self._label = label
        os.set_blocking(stream.fileno(), False)

    def fileno(self) -> int:
        return self._stream.fileno()

    def readable(self) -> bool:
        return not self._writing

    def writable(self) -> bool:
        return self._writing

    def _wait(self, event: int) -> None:
        with selectors.DefaultSelector() as selector:
            selector.register(self._stream, event)
            while True:
                remaining = self._session._remaining()
                # Closing an fd from another thread is not a portable selector
                # wakeup. Poll cancellation at a small bounded interval too.
                if selector.select(min(remaining, 0.05)):
                    self._session._remaining()
                    return

    def read(self, size: int = -1) -> bytes:
        if self._writing:
            raise io.UnsupportedOperation("write-only native client pipe")
        if self.closed:
            raise ValueError("native client pipe is closed")
        if size == 0:
            return b""
        if size < 0:
            chunks = []
            while True:
                chunk = self.read(8192)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        while True:
            self._wait(selectors.EVENT_READ)
            try:
                chunk = os.read(self.fileno(), min(size, 65536))
            except (BlockingIOError, InterruptedError):
                continue
            self._session._charge_output(len(chunk))
            self._session._record_output(self._label, chunk)
            return chunk

    def readinto(self, target: Any) -> int:
        chunk = self.read(len(target))
        target[:len(chunk)] = chunk
        return len(chunk)

    def write(self, data: Any) -> int:
        if not self._writing:
            raise io.UnsupportedOperation("read-only native client pipe")
        if self.closed:
            raise ValueError("native client pipe is closed")
        view = memoryview(data).cast("B")
        self._session._charge_input(len(view))
        offset = 0
        while offset < len(view):
            self._wait(selectors.EVENT_WRITE)
            try:
                written = os.write(self.fileno(), view[offset:offset + 65536])
            except (BlockingIOError, InterruptedError):
                continue
            if written <= 0:
                raise DockerBackendError("native client input pipe closed")
            offset += written
        return offset

    def close(self) -> None:
        if not self.closed:
            self._stream.close()
            super().close()


class NativeSession:
    """Live bounded pipes. Call close/cancel; never reap the exposed Popen.

    The timeout watchdog only signals the native client group. The owning
    controller must still close/reap it and perform identity-bound VM cleanup.
    Raw process pipes/filenos are exposed for trusted controller integration;
    bypassing these bounded wrappers is outside this contract.
    """

    def __init__(self, process: Any, *, timeout: float, output_limit: int,
                 lease: contextlib.ExitStack, on_close: Callable[[], None] | None = None,
                 input_limit: int | None = None) -> None:
        self.process = process
        self._owner_pid = os.getpid()
        self._deadline = time.monotonic() + timeout
        self._limit = output_limit
        self._input_limit = output_limit if input_limit is None else input_limit
        self._hashes = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
        self._eof: set[str] = set()
        self._output = self._input = 0
        self._lease = lease
        self._on_close = on_close
        self._lock = threading.RLock()
        self._failure: str | None = None
        self._cleanup_error: str | None = None
        self._closed = False
        self._finished = False
        if any(stream is None for stream in (process.stdin, process.stdout, process.stderr)):
            raise DockerBackendError("native session requires three binary pipes")
        self.stdin = _Pipe(self, process.stdin, writing=True, label="stdin")
        self.stdout = _Pipe(self, process.stdout, writing=False, label="stdout")
        self.stderr = _Pipe(self, process.stderr, writing=False, label="stderr")
        self._timer = threading.Timer(timeout, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _signal(self) -> None:
        if os.getpid() != self._owner_pid:
            raise DockerBackendError("native session custody cannot be inherited across fork")
        if self.process.returncode is None:
            cancel = getattr(self.process, "_cancel_owned", None)
            if callable(cancel):
                try:
                    cancel()
                except NativeClientError as exc:
                    raise DockerBackendError("persistent native custody cancellation is uncertain") from exc
                return
            _child_owner()
            # Neither this watchdog nor the public handle polls/waits first.
            # Even an exited leader reserves its PID until our owning wait.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _expire(self) -> None:
        with self._lock:
            if os.getpid() != self._owner_pid:
                raise DockerBackendError("native session custody cannot be inherited across fork")
            if not self._closed:
                self._failure = "native client deadline exceeded"
                try:
                    self._signal()
                except (OSError, DockerBackendError):
                    self._cleanup_error = "native client ownership or cancellation is uncertain"

    def _remaining(self) -> float:
        with self._lock:
            if os.getpid() != self._owner_pid:
                raise DockerBackendError("native session custody cannot be inherited across fork")
            if self._closed or self._cleanup_error is not None:
                raise DockerBackendError("native session is closed or cleanup is uncertain")
            if self._failure is not None:
                raise DockerBackendError(self._failure)
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                self._expire()
                raise DockerBackendError("native client deadline exceeded")
            return remaining

    def _charge_output(self, count: int) -> None:
        with self._lock:
            self._output += count
            if self._output > self._limit:
                self._failure = "native client output byte limit exceeded"
                self._signal()
                raise DockerBackendError(self._failure)

    def _record_output(self, label: str, chunk: bytes) -> None:
        with self._lock:
            if chunk:
                self._hashes[label].update(chunk)
            else:
                self._eof.add(label)

    def _charge_input(self, count: int) -> None:
        with self._lock:
            self._input += count
            if self._input > self._input_limit:
                self._failure = "native client input byte limit exceeded"
                self._signal()
                raise DockerBackendError(self._failure)

    def cancel(self) -> None:
        self.close()

    def finish(self, *, timeout: float | None = None) -> int:
        """Acknowledge a normally exited native channel after draining both pipes.

        This is a native response receipt only; it never certifies VM state or
        queued daemon command quiescence. Cancellation uses close(), not finish.
        """
        with self._lock:
            if self._closed:
                if not self._finished or self.process.returncode is None or self._cleanup_error is not None:
                    raise DockerBackendError("native completion is uncertain")
                return self.process.returncode
            remaining = self._remaining()
            if self._eof != {"stdout", "stderr"}:
                raise DockerBackendError("drain both native output pipes before acknowledging completion")
            if timeout is not None:
                if type(timeout) not in (int, float) or not 0 < timeout <= remaining:
                    raise DockerBackendError("native finish timeout exceeds its remaining deadline")
                remaining = timeout
            try:
                code = self.process._reap_owned(timeout=remaining)
                acknowledge = getattr(self.process, "_acknowledge", None)
                if callable(acknowledge):
                    acknowledge(canonical_digest({"returncode": code,
                        "stdout": "sha256:" + self._hashes["stdout"].hexdigest(),
                        "stderr": "sha256:" + self._hashes["stderr"].hexdigest()}))
                self._timer.cancel()
                for stream in (self.stdin, self.stdout, self.stderr):
                    stream.close()
                self._lease.close()
                self._finished = True
                self._closed = True
                if self._on_close is not None:
                    self._on_close()
                return code
            except Exception as exc:
                self._finished = False
                uncertain = getattr(self.process, "_mark_uncertain", None)
                if callable(uncertain):
                    uncertain()
                raise DockerBackendError("normal native completion could not be established") from exc

    def close(self) -> None:
        with self._lock:
            if os.getpid() != self._owner_pid:
                raise DockerBackendError("native session custody cannot be inherited across fork")
            if self._cleanup_error is not None:
                for stream in (self.stdin, self.stdout, self.stderr):
                    stream.close()
                raise DockerBackendError(self._cleanup_error)
            if self._closed:
                return
            self._timer.cancel()
            try:
                self._signal()
                if self.process.returncode is None:
                    self.process._reap_owned(timeout=1.0)
                if self.process.returncode is None:
                    raise DockerBackendError("native client did not terminate")
            except (OSError, subprocess.TimeoutExpired, DockerBackendError) as exc:
                self._cleanup_error = "native client cleanup is uncertain; external reconciliation required"
                raise DockerBackendError(self._cleanup_error) from exc
            finally:
                for stream in (self.stdin, self.stdout, self.stderr):
                    stream.close()
            try:
                self._lease.close()
            except Exception as exc:
                uncertain = getattr(self.process, "_mark_uncertain", None)
                if callable(uncertain):
                    uncertain()
                self._cleanup_error = "native client lease release is uncertain"
                raise DockerBackendError(self._cleanup_error) from exc
            self._closed = True
            if self._on_close is not None:
                self._on_close()


def _spawn(argv: Sequence[str], *, env: Mapping[str, str]) -> _OwnedProcess:
    _child_owner()
    return _OwnedProcess(list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=dict(env), cwd="/", shell=False,
                         close_fds=True, start_new_session=True)


def _cleanup_spawn(process: Any) -> None:
    """Handle partial session construction without losing native child custody."""
    try:
        if process.returncode is None:
            cancel = getattr(process, "_cancel_owned", None)
            if callable(cancel):
                cancel()
            else:
                _child_owner()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process._reap_owned(timeout=1.0)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def _run_control(argv: Sequence[str], *, env: Mapping[str, str], timeout_seconds: float,
                 max_stdout_bytes: int, max_stderr_bytes: int) -> CommandResult:
    # Total output is capped by the stricter aggregate of both declared limits;
    # each stream is also checked before a returned captured result is accepted.
    process = _spawn(argv, env=env)
    try:
        session = NativeSession(process, timeout=timeout_seconds,
                                output_limit=max_stdout_bytes + max_stderr_bytes,
                                lease=contextlib.ExitStack())
    except BaseException:
        _cleanup_spawn(process)
        raise
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max_stdout_bytes, "stderr": max_stderr_bytes}
    try:
        session.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(session.stdout, selectors.EVENT_READ, "stdout")
            selector.register(session.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                for key, _ in selector.select(session._remaining()):
                    chunk = key.fileobj.read(8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        if len(captured[key.data]) + len(chunk) > limits[key.data]:
                            raise DockerBackendError("native command output byte limit exceeded")
                        captured[key.data].extend(chunk)
        session.finish()
        return CommandResult(session.process.returncode, bytes(captured["stdout"]), bytes(captured["stderr"]))
    finally:
        session.close()


class DockerBackend:
    """Implementation is inert until a trusted external permit provider is set."""

    def __init__(self, profile_path: Path, *, permit: PermitProvider | None = None,
                 runner: CommandRunner | None = None, popen_factory: Callable[..., Any] | None = None,
                 custody: JournalCustody | None = None, native_client_reconciler: Any = None) -> None:
        self._path = profile_path
        self._owner_pid = os.getpid()
        self._permit = permit
        self._runner = runner if runner is not None else _run_control
        self._popen = popen_factory if popen_factory is not None else _spawn
        self._test_transport = runner is not None and popen_factory is not None
        if custody is not None and type(custody) is not JournalCustody:
            raise DockerBackendError("a protected journal custody manager is required")
        if custody is not None and (runner is not None or popen_factory is not None):
            raise DockerBackendError("custody cannot be bypassed with alternate native transports")
        self.custody = custody
        self.native_client_reconciler = native_client_reconciler
        if custody is not None:
            custody.bind_reconciler(native_client_reconciler)
        self._profile_digest: str | None = None
        self._seen_names: set[str] = set()
        self._clients: dict[BackendIdentity, list[NativeSession]] = {}
        self._receipts: dict[str, bytes] = {}
        self._uncertain = False

    def _profile(self) -> DockerProfile:
        if os.getpid() != self._owner_pid:
            raise DockerBackendError("adapter and namespace leases cannot be inherited across fork")
        profile = load_profile(self._path)
        if type(profile) is not DockerProfile or os.geteuid() == 0 or os.geteuid() != profile.controller_uid:
            raise DockerBackendError("adapter requires the profile's current nonroot controller UID")
        if self._profile_digest is None:
            self._profile_digest = profile.digest
        elif self._profile_digest != profile.digest:
            raise DockerBackendError("profile changed; a newly enrolled controller instance is required")
        return profile

    def _lease(self, operation: str, *, identity: BackendIdentity | None = None,
               launch_spec: LaunchSpec | None = None,
               guest_command: GuestCommand | None = None) -> tuple[DockerProfile, OperationPermit, contextlib.ExitStack]:
        if self._permit is None:
            raise DockerBackendError("no external enrollment, namespace lease, and reconciler permit provider")
        if operation not in _OPERATIONS:
            raise DockerBackendError("unsupported adapter operation")
        if identity is not None and type(identity) is not BackendIdentity:
            raise DockerBackendError("operation requires a validated exact backend identity")
        if launch_spec is not None and type(launch_spec) is not LaunchSpec:
            raise DockerBackendError("create requires a validated launch specification")
        profile = self._profile()
        if self.custody is None and not self._test_transport:
            raise DockerBackendError("native dispatch requires the persistent service's pre-exec journal custody")
        if self.custody is not None and not self.custody.is_bound_to(self, profile):
            raise DockerBackendError("native custody is bound to another controller authority")
        if launch_spec is not None and launch_spec.profile_digest != profile.digest:
            raise DockerBackendError("launch specification is bound to another profile")
        request = OperationRequest(operation, profile.digest, profile.namespace, self._owner_pid,
                                   identity, launch_spec, guest_command)
        lease = contextlib.ExitStack()
        try:
            issued = lease.enter_context(self._permit(profile, request))
            if (
                type(issued) is not OperationPermit or issued.request_digest != request.digest
                or type(issued.epoch) is not int or not 1 <= issued.epoch <= 2**63 - 1
                or type(issued.generation) is not str or not _GENERATION.fullmatch(issued.generation)
                or type(issued.reconciliation_digest) is not str or not _DIGEST.fullmatch(issued.reconciliation_digest)
            ):
                raise DockerBackendError("external permit is missing or bound to another operation")
            expected_name = None if identity is None else identity.name
            if operation == "create":
                if type(issued.reserved_name) is not str or not _NAME.fullmatch(issued.reserved_name):
                    raise DockerBackendError("create needs an externally and permanently reserved random name")
            elif issued.reserved_name != expected_name:
                raise DockerBackendError("external permit targets another sandbox")
            return profile, issued, lease
        except BaseException:
            lease.close()
            raise

    @staticmethod
    def _environment(profile: DockerProfile) -> dict[str, str]:
        account = pwd.getpwuid(profile.controller_uid)
        return {"PATH": "/usr/bin:/bin", "HOME": account.pw_dir, "USER": account.pw_name,
                "LOGNAME": account.pw_name, "LANG": "C", "LC_ALL": "C", "NO_COLOR": "1",
                "DOCKER_SANDBOXES_ROOT_SIZE": f"{profile.limits.root_disk_mib}m",
                "DOCKER_SANDBOXES_DOCKER_SIZE": f"{profile.limits.docker_disk_mib}m"}

    @staticmethod
    def _prefix(profile: DockerProfile) -> list[str]:
        return [profile.sbx_path, "--app-name", profile.namespace, "--no-input"]

    def _command(self, profile: DockerProfile, args: list[str], *, maximum: int = MAX_METADATA_BYTES,
                 permit: OperationPermit | None = None, operation: str | None = None) -> CommandResult:
        if self._profile().digest != profile.digest:
            raise DockerBackendError("profile drift before native command")
        timeout = min(CONTROL_TIMEOUT_SECONDS, float(profile.limits.wall_seconds))
        started = time.monotonic()
        try:
            if self.custody is not None:
                result = self.custody.run_control(profile, permit, [*self._prefix(profile), *args],
                                  timeout_seconds=timeout, max_stdout_bytes=maximum,
                                  max_stderr_bytes=MAX_METADATA_BYTES, operation=operation)
            else:
                result = self._runner([*self._prefix(profile), *args], env=self._environment(profile),
                                  timeout_seconds=timeout, max_stdout_bytes=maximum,
                                  max_stderr_bytes=MAX_METADATA_BYTES)
        except (OSError, TimeoutError, subprocess.TimeoutExpired, ExecProbeError, NativeClientError) as exc:
            self._uncertain = True
            raise DockerBackendError("bounded native command failed") from exc
        if time.monotonic() - started >= timeout:
            raise DockerBackendError("native command exceeded its deadline")
        if (type(result) is not CommandResult or type(result.returncode) is not int
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or len(result.stdout) > maximum or len(result.stderr) > MAX_METADATA_BYTES):
            raise DockerBackendError("invalid or oversized native command result")
        return result

    def _inspect(self, profile: DockerProfile, name: str, expected: BackendIdentity | None,
                 permit: OperationPermit | None = None) -> BackendObservation:
        result = self._command(profile, ["inspect", name, "--format", "json"], permit=permit)
        if result.returncode != 0:
            raise DockerBackendError("sandbox inspection failed; absence is not established")
        try:
            data = _json_object(result.stdout)
            if not _INSPECT_REQUIRED <= data.keys() or data.keys() - INSPECT_FIELDS:
                raise DockerBackendError("unknown or incomplete inspect schema")
            identity = BackendIdentity(name=data["name"], sandbox_id=data["id"], created_at=data["created_at"])
            if identity.name != name or (expected is not None and identity != expected):
                raise DockerBackendError("sandbox name, ID, or creation generation mismatch")
            if data["created_version"] != VERSION or data["daemon_version"] != VERSION:
                raise DockerBackendError("unsupported daemon or sandbox version")
            if any(type(data[key]) is not list or data[key] for key in ("host_mounts", "runtime_mounts", "mcp_servers")):
                raise DockerBackendError("sandbox exposes a mount or MCP server")
            if data["mcp_mode"] != "static" or data["working_dir"] != "":
                raise DockerBackendError("sandbox is not mountless with static empty MCP")
            if (type(data["cpus"]) is not int or data["cpus"] != profile.limits.cpus
                or data["memory"] != f"{profile.limits.memory_mib}m"
                or data["image_digest"] != profile.image.split("@", 1)[1]
                or data["kits"] != [profile.image]):
                raise DockerBackendError("sandbox image or observed resource request differs from profile")
            if data["network"] != name or data["network_policy"] != {"scope": "sandbox"}:
                raise DockerBackendError("unsupported sandbox network policy scope")
            if data["state"] not in {"running", "stopped"}:
                raise DockerBackendError("unsupported sandbox state")
            return BackendObservation(identity, data["state"])
        except (ExecProbeError, BackendContractError, KeyError, TypeError) as exc:
            self._uncertain = True
            raise DockerBackendError("sandbox inspection did not match its closed pinned contract") from exc

    def _rows(self, profile: DockerProfile, permit: OperationPermit | None = None) -> list[dict[str, Any]]:
        result = self._command(profile, ["ls", "--json"], maximum=MAX_LIST_BYTES, permit=permit)
        if result.returncode != 0:
            raise DockerBackendError("cannot establish namespace inventory")
        try:
            wrapped = _json_object(b'{"rows":' + result.stdout + b'}')
            rows = wrapped.get("rows")
            if set(wrapped) != {"rows"} or type(rows) is not list or len(rows) > MAX_LIST_ROWS:
                raise DockerBackendError("unknown sandbox list schema")
            names, identifiers = set(), set()
            for row in rows:
                if type(row) is not dict or set(row) != _LIST_FIELDS:
                    raise DockerBackendError("unknown sandbox list row schema")
                identity = BackendIdentity(row["name"], row["id"], row["created_at"])
                if identity.name in names or identity.sandbox_id in identifiers:
                    raise DockerBackendError("duplicate namespace object identity")
                names.add(identity.name)
                identifiers.add(identity.sandbox_id)
                if (row["status"] not in {"running", "stopped"} or type(row["cpus"]) is not int
                    or row["cpus"] < 1 or type(row["memory_mib"]) is not int or row["memory_mib"] < 1
                    or type(row["memory"]) is not str or type(row["agent"]) is not str
                    or type(row["last_used_at"]) is not str):
                    raise DockerBackendError("invalid sandbox list row values")
            return rows
        except (ExecProbeError, BackendContractError, KeyError, TypeError) as exc:
            self._uncertain = True
            raise DockerBackendError("namespace listing did not match its closed contract") from exc

    def probe(self, profile: DockerProfile) -> BackendProbe:
        loaded, _permit, lease = self._lease("probe")
        with lease:
            if type(profile) is not DockerProfile or loaded.digest != profile.digest:
                raise DockerBackendError("probe profile mismatch")
            return BackendProbe(1, ("Protected profile/runtime verified; external permit supplied.",
                                    "This adapter does not grant enrollment or qualification.",
                                    "Name targeting requires externally enforced exclusive namespace ownership.",
                                    "Storage, policy rules, integrations, and orphan cleanup need external attestation."))

    def create(self, launch_spec: LaunchSpec) -> BackendIdentity:
        if self._uncertain:
            raise DockerBackendError("adapter has unresolved uncertainty; external reconciliation required")
        profile, permit, lease = self._lease("create", launch_spec=launch_spec)
        with lease:
            name = permit.reserved_name
            assert name is not None
            if name in self._seen_names or len(self._seen_names) >= MAX_TRACKED_NAMES:
                raise DockerBackendError("name was already reserved or local permanent-name quota was reached")
            self._seen_names.add(name)
            if any(row["name"] == name for row in self._rows(profile, permit)):
                self._uncertain = True
                raise DockerBackendError("reserved sandbox name is already present")
            try:
                result = self._command(profile, [
                    "create", "--name", name, "--cpus", str(profile.limits.cpus),
                    "--memory", f"{profile.limits.memory_mib}m", "--skills", "off",
                    "--static-mcp", "none", "--deny-network", "**", "--pull", "missing", profile.image,
                ], permit=permit)
                if result.returncode != 0:
                    raise DockerBackendError("create failed; reserved name must be externally reconciled")
                return self._inspect(profile, name, None, permit).identity
            except BaseException:
                self._uncertain = True
                raise

    def configure_network(self, identity: BackendIdentity, policy: ModelNetworkPolicy) -> ArtifactReference:
        """Activate only pinned scoped HTTP rules before credentials/source.

        A failure leaves this adapter uncertain; the owner must fence and clean
        up. Repeated name checks rely on the enrolled exclusive namespace lease,
        not an atomic sbx identity-addressing primitive.
        """
        if self._uncertain or type(policy) is not ModelNetworkPolicy:
            raise DockerBackendError("network activation requires a reconciled pinned policy")
        profile, permit, lease = self._lease("policy-activate", identity=identity)
        with lease:
            if len(self._receipts) >= MAX_TRACKED_NAMES:
                raise DockerBackendError("policy receipt quota reached; permanent history retained")
            if policy.digest != profile.policy_digest or policy.namespace != profile.namespace:
                raise DockerBackendError("network policy differs from the protected profile")
            def observed(stage: str) -> dict:
                self._inspect(profile, identity.name, identity, permit)
                result = self._command(profile, ["policy", "ls", identity.name, "--json"],
                                       permit=permit, operation="policy-inspect")
                if result.returncode != 0:
                    raise DockerBackendError("cannot inspect exact effective policy")
                return verify_effective_policy(policy, result.stdout, sandbox_name=identity.name, stage=stage)
            try:
                locked = observed("locked")
                for rule in policy.rules:
                    self._inspect(profile, identity.name, identity, permit)
                    result = self._command(profile, ["policy", "allow", "network", "--sandbox", identity.name,
                        rule.host, "--method", rule.method, "--path", rule.path], permit=permit, operation="policy-allow")
                    if result.returncode != 0:
                        raise DockerBackendError("scoped model rule installation failed")
                staged = observed("staged")
                if staged["lockRuleId"] != locked["lockRuleId"]:
                    raise DockerBackendError("create-time deny lock changed during activation")
                self._inspect(profile, identity.name, identity, permit)
                result = self._command(profile, ["policy", "rm", "network", "--sandbox", identity.name,
                    "--id", staged["lockRuleId"], "--force"], permit=permit, operation="policy-remove-lock")
                if result.returncode != 0:
                    raise DockerBackendError("exact scoped deny lock removal failed")
                active = observed("active")
                payload = json.dumps({"schemaVersion": 1, "identity": identity.as_dict(),
                    "policyDigest": policy.digest, "effectiveRulesDigest": active["rulesDigest"],
                    "requestDigest": permit.request_digest}, sort_keys=True, separators=(",", ":")).encode()
                reference = ArtifactReference("sha256:" + hashlib.sha256(payload).hexdigest())
                self._receipts[reference.digest] = payload
                return reference
            except BaseException:
                self._uncertain = True
                raise

    def inspect(self, identity: BackendIdentity) -> BackendObservation:
        profile, permit, lease = self._lease("inspect", identity=identity)
        with lease:
            return self._inspect(profile, identity.name, identity, permit)

    def open_session(self, identity: BackendIdentity, guest_command: GuestCommand, *, operation: str = "open-session",
                     max_input_bytes: int | None = None, max_output_bytes: int | None = None) -> NativeSession:
        if self._uncertain or type(guest_command) is not GuestCommand or type(identity) is not BackendIdentity:
            raise DockerBackendError("session needs a validated guest command and reconciled adapter state")
        if self._clients.get(identity):
            raise DockerBackendError("sandbox already has an owned live native session")
        if sum(len(clients) for clients in self._clients.values()) >= MAX_TRACKED_NAMES:
            raise DockerBackendError("owned native client quota reached")
        if operation not in {"open-session", "provision", "collect"}:
            raise DockerBackendError("unsupported fixed guest session phase")
        profile, permit, lease = self._lease(operation, identity=identity, guest_command=guest_command)
        process = None
        try:
            input_cap = MAX_TRANSFER_BYTES if operation == "provision" else profile.limits.max_output_bytes
            output_cap = MAX_TRANSFER_BYTES if operation == "collect" else profile.limits.max_output_bytes
            input_limit = input_cap if max_input_bytes is None else max_input_bytes
            output_limit = output_cap if max_output_bytes is None else max_output_bytes
            if (type(input_limit) is not int or not 1 <= input_limit <= input_cap
                or type(output_limit) is not int or not 1 <= output_limit <= output_cap):
                raise DockerBackendError("guest stream byte budgets exceed their permitted phase")
            self._inspect(profile, identity.name, identity, permit)
            if self._profile().digest != profile.digest:
                raise DockerBackendError("profile drift before session launch")
            argv = [
                *self._prefix(profile), "exec", "-i", "--user", "root", "--workdir",
                "/" if operation == "provision" else profile.guest_workdir, "--", identity.name, *guest_command.argv,
            ]
            if self.custody is not None:
                process = self.custody.open_process(profile, permit, argv,
                            timeout_seconds=float(profile.limits.wall_seconds), operation=operation)
            else:
                process = self._popen(argv, env=self._environment(profile))
            session: NativeSession

            def retired() -> None:
                clients = self._clients.get(identity, [])
                if session in clients:
                    clients.remove(session)
                if not clients:
                    self._clients.pop(identity, None)

            session = NativeSession(process, timeout=float(profile.limits.wall_seconds),
                                    output_limit=output_limit, input_limit=input_limit, lease=lease,
                                    on_close=retired)
            self._clients.setdefault(identity, []).append(session)
            return session
        except BaseException:
            try:
                if process is not None:
                    _cleanup_spawn(process)
            finally:
                lease.close()
            raise

    def _close_clients(self, identity: BackendIdentity) -> None:
        if type(identity) is not BackendIdentity:
            raise DockerBackendError("native client cleanup requires an exact backend identity")
        for session in list(self._clients.get(identity, [])):
            try:
                session.close()
            except Exception:
                self._uncertain = True
                raise

    def stop(self, identity: BackendIdentity) -> BackendObservation:
        profile, permit, lease = self._lease("stop", identity=identity)
        with lease:
            self._close_clients(identity)
            self._inspect(profile, identity.name, identity, permit)
            result = self._command(profile, ["stop", identity.name], permit=permit)
            if result.returncode != 0:
                self._uncertain = True
                raise DockerBackendError("sandbox stop failed; external reconciliation required")
            observed = self._inspect(profile, identity.name, identity, permit)
            if observed.state != "stopped":
                self._uncertain = True
                raise DockerBackendError("sandbox is not confirmed stopped")
            return observed

    def destroy(self, identity: BackendIdentity) -> ArtifactReference:
        profile, permit, lease = self._lease("destroy", identity=identity)
        with lease:
            self._close_clients(identity)
            if self._inspect(profile, identity.name, identity, permit).state != "stopped":
                raise DockerBackendError("sandbox must be confirmed stopped before removal")
            result = self._command(profile, ["rm", "--force", identity.name], permit=permit)
            if result.returncode != 0:
                self._uncertain = True
                raise DockerBackendError("sandbox removal failed; absence is unproven")
            rows = self._rows(profile, permit)
            if any(row["name"] == identity.name or row["id"] == identity.sandbox_id for row in rows):
                self._uncertain = True
                raise DockerBackendError("sandbox name or UUID remains present after removal")
            receipt = {"schemaVersion": 1, "kind": "sandbox-removal-observation",
                       "profileDigest": profile.digest, "namespace": profile.namespace,
                       "identity": identity.as_dict(), "nameAndIdAbsent": True,
                       "generation": permit.generation, "epoch": permit.epoch,
                       "reconciliationDigest": permit.reconciliation_digest,
                       "storageCleanupVerified": False, "qualified": False}
            digest = canonical_digest(receipt)
            if len(self._receipts) >= MAX_TRACKED_NAMES:
                self._uncertain = True
                raise DockerBackendError("removal receipt quota reached")
            self._receipts[digest] = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            return ArtifactReference(digest)

    def read_receipt(self, reference: ArtifactReference) -> bytes:
        if type(reference) is not ArtifactReference or reference.digest not in self._receipts:
            raise DockerBackendError("unknown local observation receipt")
        return self._receipts[reference.digest]

    def stage_input(self, identity: BackendIdentity, approved_manifest: ArtifactReference) -> ArtifactReference:
        raise DockerBackendUnsupported("safe bounded digest blob provisioning is not implemented; arbitrary host paths are forbidden")

    def collect_output(self, identity: BackendIdentity, export_request: ArtifactReference) -> ArtifactReference:
        raise DockerBackendUnsupported("safe artifact collection/import is not implemented; arbitrary guest paths are forbidden")
