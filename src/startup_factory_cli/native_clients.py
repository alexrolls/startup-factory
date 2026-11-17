"""Durable pre-exec native client custody, not a server reconciler or permit.

Only trusted adapter code calls this API while holding its externally validated
namespace/lifecycle authority. Arguments are never accepted from a guest tool
or journal JSON. A root-protected fixed Python gate waits for an explicit byte;
the intent and exact process generation are durable before that byte is sent.

Native exit, an exec-status EOF, and an adapter acknowledgment are distinct.
None proves that queued daemon requests are drained or a VM stopped. Recovery
therefore always requires an independent server reconciler before dispatch.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import signal
import stat
import struct
import subprocess
import threading
import time
import types
from typing import Any

from .execution_backend import (
    DockerProfile, _absolute_path, _file_identity, _read_protected, canonical_digest, load_profile,
)
from .sandbox_registry import SandboxRegistry, RegistryError
from .sandbox_enrollment import profile_basis_digest


STATE_FILE = "native-clients.json"
PENDING_FILE = ".native-clients.pending"
MAX_RECORDS = 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_COMMAND_BYTES = 128 * 1024
HANDSHAKE_SECONDS = 5.0
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CLIENT = re.compile(r"native-[0-9a-f]{32}\Z")
_NAME = re.compile(r"sf-[0-9a-f]{32}\Z")
_GENERATION = re.compile(r"gen-[0-9a-f]{32}\Z")
_STATES = frozenset({"intent", "gated", "release-intent", "exec-channel-open", "client-exited",
                     "completed-acknowledged", "delivery-uncertain", "aborted-before-release"})
_RECORD_FIELDS = frozenset({"clientId", "intent", "profileDigest", "argvDigest", "environmentDigest",
    "controllerPid", "controllerStart", "native", "state", "returncode", "responseDigest", "reason"})
_NATIVE_FIELDS = frozenset({"pid", "processIdentity", "processGroupId", "sessionId"})


class NativeClientError(RuntimeError):
    """Native custody or journal durability could not be established."""


@dataclasses.dataclass(frozen=True)
class ProgramPin:
    path: Path
    sha256: str

    def __post_init__(self) -> None:
        _absolute_path(os.fspath(self.path), "pinned program")
        if type(self.sha256) is not str or not _HEX.fullmatch(self.sha256):
            raise NativeClientError("program pin requires a lowercase SHA-256")

    def as_dict(self) -> dict[str, str]:
        return {"path": str(self.path), "sha256": self.sha256}


@dataclasses.dataclass(frozen=True)
class GateTools:
    python: ProgramPin
    gate: ProgramPin
    lifecycle_helper: ProgramPin

    def __post_init__(self) -> None:
        if any(type(pin) is not ProgramPin for pin in (self.python, self.gate, self.lifecycle_helper)):
            raise NativeClientError("gate tools require explicit protected program pins")

    def as_dict(self) -> dict[str, Any]:
        return {"python": self.python.as_dict(), "gate": self.gate.as_dict(),
                "lifecycleHelper": self.lifecycle_helper.as_dict()}


@dataclasses.dataclass(frozen=True)
class NativeIntent:
    namespace: str
    name: str
    generation: str
    epoch: int
    request_digest: str
    operation: str

    def __post_init__(self) -> None:
        if (type(self.namespace) is not str or len(self.namespace) > 20
            or not re.fullmatch(r"sf-[a-z0-9]+(?:-[a-z0-9]+)*", self.namespace)
            or self.namespace == "sf-qualification" or type(self.name) is not str
            or not _NAME.fullmatch(self.name) or type(self.generation) is not str
            or not _GENERATION.fullmatch(self.generation) or type(self.epoch) is not int
            or not 1 <= self.epoch <= 2**63 - 1 or type(self.request_digest) is not str
            or not _DIGEST.fullmatch(self.request_digest)
            or self.operation not in {"create", "inspect", "open-session", "provision", "collect", "stop", "destroy", "probe", "list", "credential-set", "credential-remove", "policy-inspect", "policy-allow", "policy-remove-lock"}):
            raise NativeClientError("native intent has an invalid scope or request binding")

    def as_dict(self) -> dict[str, Any]:
        return {"namespace": self.namespace, "name": self.name, "generation": self.generation,
                "epoch": self.epoch, "requestDigest": self.request_digest, "operation": self.operation}

    @classmethod
    def from_dict(cls, value: Any) -> NativeIntent:
        if type(value) is not dict or set(value) != {"namespace", "name", "generation", "epoch", "requestDigest", "operation"}:
            raise NativeClientError("unknown native intent schema")
        return cls(value["namespace"], value["name"], value["generation"], value["epoch"],
                   value["requestDigest"], value["operation"])


def _verify_pin(pin: ProgramPin, *, executable: bool) -> bytes | None:
    content, digest = _read_protected(pin.path, maximum=256 * 1024 * 1024 if executable else 256 * 1024,
                                      capture=not executable, executable=executable)
    if digest != pin.sha256:
        raise NativeClientError("protected native tool differs from its pinned digest")
    return content


def _identity_helper(pin: ProgramPin) -> Any:
    raw = _verify_pin(pin, executable=False)
    if raw is None:
        raise NativeClientError("protected lifecycle helper is absent")
    module = types.ModuleType("_sf_pinned_native_lifecycle_" + pin.sha256[:16])
    module.__file__ = str(pin.path)
    # Execute only already verified, protected installation bytes. No loader
    # cache writes, sys.path changes, or project-controlled imports occur.
    exec(compile(raw, str(pin.path), "exec"), module.__dict__)
    if any(not callable(getattr(module, name, None)) for name in
           ("process_identity", "group_exists", "leader_matches_group")):
        raise NativeClientError("lifecycle helper lacks required stable identity operations")
    return module


def _owner_signals() -> None:
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise NativeClientError("native custody requires default SIGCHLD and no foreign waitpid reapers")


def _decode(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_STATE_BYTES:
        raise NativeClientError("native history byte quota exceeded")
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 12:
                raise NativeClientError("native history nesting quota exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise NativeClientError("invalid native history nesting")
    def unique(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise NativeClientError("duplicate native history field")
            result[key] = value
        return result
    def constant(_value: str) -> Any:
        raise NativeClientError("nonfinite native history value")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)
        pending, count = [result], 0
        while pending:
            child = pending.pop()
            count += 1
            if count > MAX_RECORDS * 100 + 32:
                raise NativeClientError("native history node quota exceeded")
            if type(child) is dict:
                pending.extend(child.keys())
                pending.extend(child.values())
            elif type(child) is list:
                pending.extend(child)
            elif type(child) is str:
                if len(child) > 4096 or any(0xD800 <= ord(c) <= 0xDFFF for c in child):
                    raise NativeClientError("native history string is invalid")
            elif type(child) is float and not math.isfinite(child):
                raise NativeClientError("nonfinite native history value")
        if type(result) is not dict:
            raise NativeClientError("native history must be an object")
        return result
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise NativeClientError("native history cannot be decoded") from exc


def validate_native_history(state: Any, *, profile_basis_digest: str, tools_digest: str,
                            journal_id: str, namespace: str) -> dict[str, Any]:
    """Pure strict schema2 validation for protected issuance/history readers.

    The caller separately establishes file ownership, marker/inode identity and
    absence of an interrupted pending write. This checks data only and conveys
    neither native custody nor server quiescence. Original record profileDigest
    values remain provenance across receipt renewal, never authorization.
    """
    try:
        # Apply the exact byte/depth/node/string bounds even to in-memory input;
        # serialization also refuses cycles/non-JSON objects and nonfinite data.
        state = _decode(json.dumps(state, allow_nan=False, separators=(",", ":")).encode())
        if (set(state) != {"schemaVersion", "journalId", "profileBasisDigest", "toolsDigest", "revision", "records"}
            or type(state["schemaVersion"]) is not int or state["schemaVersion"] != 2
            or state["journalId"] != journal_id or state["profileBasisDigest"] != profile_basis_digest
            or state["toolsDigest"] != tools_digest
            or type(state["revision"]) is not int or not 0 <= state["revision"] < 2**63
            or type(state["records"]) is not dict or len(state["records"]) > MAX_RECORDS):
            raise NativeClientError("native journal header or history is inconsistent")
        for client_id, record in state["records"].items():
            if (not _CLIENT.fullmatch(client_id) or type(record) is not dict or set(record) != _RECORD_FIELDS
                or record["clientId"] != client_id or type(record["profileDigest"]) is not str
                or not _DIGEST.fullmatch(record["profileDigest"])
                or record["state"] not in _STATES or type(record["controllerPid"]) is not int
                or record["controllerPid"] < 1 or type(record["controllerStart"]) is not str
                or not record["controllerStart"].startswith(("linux:", "darwin:"))
                or "unknown-boot" in record["controllerStart"]):
                raise NativeClientError("native journal record is invalid")
            if NativeIntent.from_dict(record["intent"]).namespace != namespace:
                raise NativeClientError("native intent namespace changed")
            for name in ("argvDigest", "environmentDigest"):
                if type(record[name]) is not str or not _DIGEST.fullmatch(record[name]):
                    raise NativeClientError("native journal command binding is invalid")
            if record["responseDigest"] is not None and (type(record["responseDigest"]) is not str or not _DIGEST.fullmatch(record["responseDigest"])):
                raise NativeClientError("native response binding is invalid")
            if record["returncode"] is not None and type(record["returncode"]) is not int:
                raise NativeClientError("native exit status is invalid")
            if record["reason"] is not None and (type(record["reason"]) is not str or len(record["reason"]) > 256):
                raise NativeClientError("native diagnostic is invalid")
            native = record["native"]
            if native is not None and (type(native) is not dict or set(native) != _NATIVE_FIELDS
                or type(native["pid"]) is not int or native["pid"] <= 1
                or type(native["processGroupId"]) is not int or type(native["sessionId"]) is not int
                or native["processGroupId"] != native["pid"] or native["sessionId"] != native["pid"]
                or type(native["processIdentity"]) is not str
                or not native["processIdentity"].startswith(("linux:", "darwin:"))
                or "unknown-boot" in native["processIdentity"]):
                raise NativeClientError("native process identity is invalid")
            if (record["state"] in {"gated", "release-intent", "exec-channel-open", "client-exited", "completed-acknowledged"} and native is None
                or record["state"] in {"intent", "gated", "release-intent", "exec-channel-open"} and record["returncode"] is not None
                or record["state"] in {"client-exited", "completed-acknowledged"} and (type(record["returncode"]) is not int or record["returncode"] < 0)
                or (record["state"] == "completed-acknowledged") != (record["responseDigest"] is not None)):
                raise NativeClientError("native state and exit/acknowledgment evidence disagree")
        return copy.deepcopy(state)
    except (TypeError, KeyError, ValueError, RecursionError) as exc:
        raise NativeClientError("native journal cannot be trusted") from exc


def _fd_read(fd: int, *, deadline: float) -> bytes:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise NativeClientError("native exec gate handshake exceeded its deadline")
        try:
            return os.read(fd, 1)
        except (BlockingIOError, InterruptedError):
            continue


def _fd_write(fd: int, raw: bytes, *, deadline: float) -> None:
    offset = 0
    os.set_blocking(fd, False)
    while offset < len(raw):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
            raise NativeClientError("native exec gate input exceeded its deadline")
        try:
            count = os.write(fd, raw[offset:offset + 65536])
        except (BlockingIOError, InterruptedError):
            continue
        if count <= 0:
            raise NativeClientError("native gate input closed")
        offset += count


class _JournalProcess(subprocess.Popen[bytes]):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._custody = False
        self._on_reap = None
        super().__init__(*args, **kwargs)
        self._custody = True

    def poll(self) -> int | None:
        if self._custody:
            raise NativeClientError("native client polling belongs to its journal owner")
        return super().poll()

    def wait(self, timeout: float | None = None) -> int:
        if self._custody:
            raise NativeClientError("native client reaping belongs to its journal owner")
        return super().wait(timeout)

    def _reap_owned(self, *, timeout: float) -> int:
        result = super().wait(timeout=timeout)
        callback, self._on_reap = self._on_reap, None
        if callback is not None:
            callback(result)
        return result


class NativeClientJournal:
    """Protected finite history; use a separate precreated private state root."""
    def __init__(self, root: Path, profile_path: Path, tools: GateTools) -> None:
        if type(tools) is not GateTools:
            raise NativeClientError("explicit gate tool pins are required")
        self.profile_path = Path(profile_path)
        self.profile = load_profile(self.profile_path)
        self.tools = tools
        self._pid = os.getpid()
        self._mutex = threading.RLock()
        self._poisoned = False
        self._closed = False
        self._needs_migration = False
        self._handles: dict[str, GatedClient] = {}
        self._verify_tools()
        self._identity = _identity_helper(tools.lifecycle_helper)
        self._storage = SandboxRegistry(root, self.profile.namespace)
        try:
            with self._storage.locked() as tx:
                try:
                    self._load(tx)
                except FileNotFoundError:
                    if tx.epoch != 0:
                        raise NativeClientError("native history is missing and cannot be reset")
                    initial = {"schemaVersion": 2, "journalId": tx.registry_id,
                               "profileBasisDigest": profile_basis_digest(self.profile), "toolsDigest": canonical_digest(tools.as_dict()),
                               "revision": 0, "records": {}}
                    self._storage._write_exclusive(STATE_FILE, self._encode(initial))
                    os.fsync(self._storage._root_fd)
                    tx.takeover()  # permanent initialization tombstone
                else:
                    if self._needs_migration:
                        self._persist(tx, self._load(tx))
                        self._needs_migration = False
                    if tx.epoch == 0:
                        tx.takeover()
        except BaseException:
            self._storage.close()
            raise

    def _check(self) -> None:
        if os.getpid() != self._pid or self._poisoned or self._closed:
            raise NativeClientError("native journal is inherited or durability is uncertain")
        if load_profile(self.profile_path) != self.profile:
            raise NativeClientError("native profile changed; independent reconciliation required")

    def _verify_tools(self) -> None:
        _verify_pin(self.tools.python, executable=True)
        _verify_pin(self.tools.gate, executable=False)
        _verify_pin(self.tools.lifecycle_helper, executable=False)

    @staticmethod
    def _encode(state: dict[str, Any]) -> bytes:
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > MAX_STATE_BYTES:
            raise NativeClientError("native journal byte quota exhausted; history is retained")
        return raw

    def _load(self, tx: Any) -> dict[str, Any]:
        tx.records()  # validates held namespace, marker, file and inode identities
        try:
            os.stat(PENDING_FILE, dir_fd=self._storage._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise NativeClientError("interrupted native history commit requires independent reconciliation")
        raw, _identity = self._storage._file(STATE_FILE, maximum=MAX_STATE_BYTES)
        try:
            state = _decode(raw)
            if type(state.get("schemaVersion")) is int and state["schemaVersion"] == 1:
                # V1 contained no stable basis. It can be migrated only while
                # the exact old profile is still available; never guess that
                # an arbitrary old digest had this policy/runtime basis.
                if (set(state) != {"schemaVersion", "journalId", "profileDigest", "toolsDigest", "revision", "records"}
                    or state["profileDigest"] != self.profile.digest):
                    raise NativeClientError("v1 native history requires its exact old profile for migration")
                state.pop("profileDigest")
                state.update(schemaVersion=2, profileBasisDigest=profile_basis_digest(self.profile))
                self._needs_migration = True
            return validate_native_history(state,
                profile_basis_digest=profile_basis_digest(self.profile),
                tools_digest=canonical_digest(self.tools.as_dict()), journal_id=tx.registry_id,
                namespace=self.profile.namespace)
        except (TypeError, KeyError, ValueError, RecursionError) as exc:
            raise NativeClientError("native journal cannot be trusted") from exc

    def _persist(self, tx: Any, state: dict[str, Any]) -> None:
        state = copy.deepcopy(state)
        state["revision"] += 1
        raw = self._encode(state)
        pending = PENDING_FILE
        old, old_identity = self._storage._file(STATE_FILE, maximum=MAX_STATE_BYTES)
        try:
            pending_identity = self._storage._write_exclusive(pending, raw)
            tx.records()
            current, current_identity = self._storage._file(STATE_FILE, maximum=MAX_STATE_BYTES)
            if current != old or current_identity != old_identity:
                raise NativeClientError("native journal changed before commit")
            if _file_identity(os.stat(pending, dir_fd=self._storage._root_fd, follow_symlinks=False)) != pending_identity:
                raise NativeClientError("pending native journal changed")
            os.replace(pending, STATE_FILE, src_dir_fd=self._storage._root_fd, dst_dir_fd=self._storage._root_fd)
            os.fsync(self._storage._root_fd)
            committed, _ = self._storage._file(STATE_FILE, maximum=MAX_STATE_BYTES)
            if committed != raw:
                raise NativeClientError("native journal commit differs")
        except BaseException:
            self._poisoned = True
            raise

    def _update(self, client_id: str, **changes: Any) -> dict[str, Any]:
        self._check()
        with self._mutex, self._storage.locked() as tx:
            state = self._load(tx)
            if client_id not in state["records"]:
                raise NativeClientError("unknown native client")
            state["records"][client_id].update(changes)
            self._persist(tx, state)
            return copy.deepcopy(state["records"][client_id])

    def records(self) -> tuple[dict[str, Any], ...]:
        self._check()
        with self._mutex, self._storage.locked() as tx:
            state = self._load(tx)
            return tuple(copy.deepcopy(state["records"][key]) for key in sorted(state["records"]))

    def _snapshot(self, pid: int) -> dict[str, Any]:
        identity = self._identity.process_identity(pid)
        if (type(identity) is not str or not identity.startswith(("linux:", "darwin:"))
            or "unknown-boot" in identity or os.getpgid(pid) != pid or os.getsid(pid) != pid):
            raise NativeClientError("native child lacks a stable dedicated process generation")
        return {"pid": pid, "processIdentity": identity, "processGroupId": pid, "sessionId": pid}

    def _environment(self) -> dict[str, str]:
        account = pwd.getpwuid(os.geteuid())
        return {"PATH": "/usr/bin:/bin", "HOME": account.pw_dir, "USER": account.pw_name,
                "LOGNAME": account.pw_name, "LANG": "C", "LC_ALL": "C", "NO_COLOR": "1",
                "DOCKER_SANDBOXES_ROOT_SIZE": f"{self.profile.limits.root_disk_mib}m",
                "DOCKER_SANDBOXES_DOCKER_SIZE": f"{self.profile.limits.docker_disk_mib}m"}

    def prepare(self, intent: NativeIntent, argv: tuple[str, ...]) -> GatedClient:
        """Trusted-adapter-only: persist intent, then bind a paused gate child."""
        self._check()
        _owner_signals()
        self._verify_tools()
        if type(intent) is not NativeIntent or intent.namespace != self.profile.namespace:
            raise NativeClientError("native intent targets another protected namespace")
        if (type(argv) is not tuple or not 1 <= len(argv) <= 256 or argv[0] != self.profile.sbx_path
            or any(type(arg) is not str or len(arg) > 4096 or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in arg) for arg in argv)):
            raise NativeClientError("native command must be a bounded literal tuple for the pinned binary")
        self._validate_command(intent, argv)
        _verify_pin(ProgramPin(Path(self.profile.sbx_path), self.profile.sbx_sha256), executable=True)
        environment = self._environment()
        raw = json.dumps({"schemaVersion": 1, "argv": list(argv)}, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > MAX_COMMAND_BYTES:
            raise NativeClientError("native command exceeds its byte limit")
        client_id = "native-" + secrets.token_hex(16)
        controller_start = self._identity.process_identity(self._pid)
        if type(controller_start) is not str or not controller_start.startswith(("linux:", "darwin:")) or "unknown-boot" in controller_start:
            raise NativeClientError("controller lacks a stable process generation")
        record = {"clientId": client_id, "intent": intent.as_dict(), "profileDigest": self.profile.digest,
                  "argvDigest": canonical_digest(list(argv)), "environmentDigest": canonical_digest(environment),
                  "controllerPid": self._pid, "controllerStart": controller_start,
                  "native": None, "state": "intent", "returncode": None, "responseDigest": None, "reason": None}
        with self._mutex, self._storage.locked() as tx:
            state = self._load(tx)
            if len(state["records"]) >= MAX_RECORDS or client_id in state["records"]:
                raise NativeClientError("permanent native history quota exhausted")
            state["records"][client_id] = record
            self._persist(tx, state)  # MUST precede Popen, including its failure path
        gate_read = gate_write = status_read = status_write = command_read = command_write = -1
        child = None
        handle = None
        deadline = time.monotonic() + HANDSHAKE_SECONDS
        try:
            gate_read, gate_write = os.pipe()
            status_read, status_write = os.pipe()
            command_read, command_write = os.pipe()
            child = _JournalProcess([
                str(self.tools.python.path), "-I", "-B", str(self.tools.gate.path),
                "--gate-fd", str(gate_read), "--status-fd", str(status_write), "--command-fd", str(command_read),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd="/", env=environment, close_fds=True, start_new_session=True,
                pass_fds=(gate_read, status_write, command_read), shell=False)
            for fd in (gate_read, status_write, command_read):
                os.close(fd)
            gate_read = status_write = command_read = -1
            _fd_write(command_write, struct.pack("!I", len(raw)) + raw, deadline=deadline)
            os.close(command_write)
            command_write = -1
            if _fd_read(status_read, deadline=deadline) != b"R":
                raise NativeClientError("protected native gate did not become ready")
            native = self._snapshot(child.pid)
            self._update(client_id, native=native, state="gated")
            handle = GatedClient(self, client_id, child, native, gate_write, status_read)
            gate_write = status_read = -1
            self._handles[client_id] = handle
            return handle
        except BaseException:
            if handle is not None:
                handle.abort_unreleased()
            elif child is not None:
                # Direct unreaped Popen custody reserves this PID even if the
                # fixed gate exited before it could be bound in the journal.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child._reap_owned(timeout=1)
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()
            if not self._poisoned:
                self._update(client_id, state="aborted-before-release", reason="gate setup failed")
            raise
        finally:
            for fd in (gate_read, gate_write, status_read, status_write, command_read, command_write):
                if fd >= 0:
                    os.close(fd)

    def spawn(self, intent: NativeIntent, argv: tuple[str, ...]) -> GatedClient:
        handle = self.prepare(intent, argv)
        try:
            handle.release()
            return handle
        except BaseException:
            with contextlib.suppress(Exception):
                handle.cancel()
            raise

    def _validate_command(self, intent: NativeIntent, argv: tuple[str, ...]) -> None:
        prefix = (self.profile.sbx_path, "--app-name", self.profile.namespace, "--no-input")
        commands = {"create": "create", "inspect": "inspect", "open-session": "exec", "provision": "exec", "collect": "exec", "stop": "stop",
                    "destroy": "rm", "probe": "ls", "list": "ls", "credential-set": "secret", "credential-remove": "secret",
                    "policy-inspect": "policy", "policy-allow": "policy", "policy-remove-lock": "policy"}
        if len(argv) < 5 or argv[:4] != prefix or argv[4] != commands[intent.operation]:
            raise NativeClientError("native command does not match its protected namespace and operation")
        args = argv[5:]
        if intent.operation == "create":
            valid = args == ("--name", intent.name, "--cpus", str(self.profile.limits.cpus),
                "--memory", f"{self.profile.limits.memory_mib}m", "--skills", "off", "--static-mcp", "none",
                "--deny-network", "**", "--pull", "missing", self.profile.image)
        elif intent.operation == "inspect":
            valid = args in {(intent.name, "--format", "json"), (intent.name, "--json")}
        elif intent.operation == "stop":
            valid = args == (intent.name,)
        elif intent.operation == "destroy":
            valid = args == ("--force", intent.name)
        elif intent.operation in {"open-session", "provision", "collect"}:
            workdir = "/" if intent.operation == "provision" else self.profile.guest_workdir
            expected = ("-i", "--user", "root", "--workdir", workdir, "--", intent.name)
            valid = len(args) > len(expected) and args[:len(expected)] == expected
        elif intent.operation == "policy-inspect":
            valid = args == ("ls", intent.name, "--json")
        elif intent.operation == "policy-allow":
            from .sandbox_network_policy import HTTP_PAIRS, MODEL_HOST
            valid = (len(args) == 9 and args[:4] == ("allow", "network", "--sandbox", intent.name)
                and args[4] == MODEL_HOST and args[5] == "--method" and args[7] == "--path"
                and (args[6], args[8]) in HTTP_PAIRS)
        elif intent.operation == "policy-remove-lock":
            import uuid
            try:
                rule_id = str(uuid.UUID(args[5])) if len(args) == 7 else None
            except (ValueError, TypeError):
                rule_id = None
            valid = (len(args) == 7 and args[:5] == ("rm", "network", "--sandbox", intent.name, "--id")
                     and rule_id == args[5] and args[6] == "--force")
        elif intent.operation in {"credential-set", "credential-remove"}:
            valid = args == ("set" if intent.operation == "credential-set" else "rm", "openai", "--sandbox", intent.name, "--force")
        else:
            valid = args == ("--json",)
        if not valid:
            raise NativeClientError("native command target does not match its durable intent")

    def recover(self) -> dict[str, Any]:
        """Diagnostic only: persisted PID checks cannot safely authorize signals.

        Across a restart, a leader can exit and its PID/PGID be reused between
        an identity check and killpg, including on Darwin. No numeric group is
        signaled here. Only a same-owner unreaped Popen reserves that identity.
        """
        self._check()
        self._verify_tools()
        observations = []
        for record in self.records():
            if record["state"] == "aborted-before-release":
                observations.append({"clientId": record["clientId"], "state": record["state"], "native": "not-released"})
                continue
            native = record["native"]
            status = "unbound"
            if native is not None:
                current = self._identity.process_identity(native["pid"])
                if self._identity.leader_matches_group(native, current):
                    creator = self._identity.process_identity(record["controllerPid"])
                    if creator is not None and creator == record["controllerStart"]:
                        status = "controller-still-live"
                    else:
                        status = "matching-orphan-uncertain"
                elif current is None:
                    status = "leaderless-uncertain" if self._identity.group_exists(native["processGroupId"]) else "native-absent"
                else:
                    status = "identity-mismatch"
            if record["state"] != "completed-acknowledged":
                self._update(record["clientId"], state="delivery-uncertain", reason=status)
            observations.append({"clientId": record["clientId"], "state": record["state"], "native": status})
        return {"schemaVersion": 1, "scope": "native-client-journal-only", "observations": observations,
                "poolBlocked": True, "serverQuiescent": False, "qualified": False,
                "reason": "Independent server queue, namespace and storage reconciliation is still required."}

    def close(self) -> None:
        """Best-effort all owned-child cleanup, then close storage; never a VM stop."""
        if os.getpid() != self._pid:
            raise NativeClientError("native custody cannot be inherited")
        if self._closed:
            return
        failure = None
        try:
            for handle in tuple(self._handles.values()):
                try:
                    if handle.process.returncode is None:
                        handle.cancel()
                    else:
                        handle._close_io()
                except Exception as exc:
                    failure = failure or exc
        finally:
            self._closed = True
            self._storage.close()
        if failure is not None:
            raise NativeClientError("owned native cleanup or journal durability remains uncertain") from failure


class GatedClient:
    """One owned native child; release is separate from normal response acknowledgment."""
    def __init__(self, journal: NativeClientJournal, client_id: str, process: _JournalProcess,
                 native: dict[str, Any], gate_fd: int, status_fd: int) -> None:
        self.journal, self.client_id, self.process = journal, client_id, process
        self.native = native
        self.stdin, self.stdout, self.stderr = process.stdin, process.stdout, process.stderr
        self._gate, self._status = gate_fd, status_fd
        self._released = self._cancelled = self._reaped = False
        self._lock = threading.RLock()
        self._pid = os.getpid()
        process._on_reap = self._exited

    def _custody(self) -> None:
        if os.getpid() != self._pid:
            raise NativeClientError("native custody cannot be inherited")
        _owner_signals()
        if self.process.pid != self.native["pid"] or not self.process._custody:
            raise NativeClientError("native Popen custody no longer matches its reserved PID")

    def _owner(self) -> None:
        self._custody()
        self.journal._check()

    def _close_io(self) -> None:
        for fd_name in ("_gate", "_status"):
            fd = getattr(self, fd_name)
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
                setattr(self, fd_name, -1)
        for stream in (self.stdin, self.stdout, self.stderr):
            with contextlib.suppress(OSError):
                stream.close()

    def _kill_owned(self) -> None:
        self._custody()
        if self.process.returncode is None:
            # Under default SIGCHLD and no foreign waitpid reaper, this owned
            # unreaped child (including a zombie) reserves its PID and PGID.
            # Do not poll first, and do not depend on proc metadata remaining
            # available after exit. This authority never survives a restart.
            try:
                os.killpg(self.native["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process._reap_owned(timeout=1)

    def _exited(self, returncode: int) -> None:
        self._reaped = True
        state = "delivery-uncertain" if self._cancelled or returncode < 0 else "client-exited"
        self.journal._update(self.client_id, state=state, returncode=returncode,
                             reason="native cancellation/disconnect" if state == "delivery-uncertain" else None)

    def release(self) -> None:
        with self._lock:
            self._owner()
            if self._released or self._gate < 0:
                raise NativeClientError("native gate cannot be released twice")
            current = self.journal._snapshot(self.process.pid)
            if current != self.native:
                raise NativeClientError("native gate identity changed before release")
            self.journal._update(self.client_id, state="release-intent")
            self._released = True  # all later failure paths are delivery-uncertain
            try:
                _fd_write(self._gate, b"G", deadline=time.monotonic() + HANDSHAKE_SECONDS)
                os.close(self._gate)
                self._gate = -1
                if _fd_read(self._status, deadline=time.monotonic() + HANDSHAKE_SECONDS) != b"":
                    raise NativeClientError("native executable was not accepted by the exec gate")
                self.journal._update(self.client_id, state="exec-channel-open")
            except BaseException:
                with contextlib.suppress(Exception):
                    self.journal._update(self.client_id, state="delivery-uncertain", reason="release or exec status is uncertain")
                raise
            finally:
                if self._status >= 0:
                    os.close(self._status)
                    self._status = -1

    def finish(self, *, timeout: float = 1.0) -> int:
        with self._lock:
            self._owner()
            if not self._released:
                raise NativeClientError("unreleased native client cannot finish a request")
            try:
                return self.process._reap_owned(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.cancel()
                raise NativeClientError("native client did not finish within its deadline")
            finally:
                if self.process.returncode is not None:
                    for stream in (self.stdin, self.stdout, self.stderr):
                        stream.close()

    def acknowledge(self, response_digest: str) -> None:
        """Trusted adapter acknowledgment only; never a server-quiescence proof."""
        with self._lock:
            self._owner()
            record = next(item for item in self.journal.records() if item["clientId"] == self.client_id)
            if (self._reaped and not self._cancelled and record["state"] == "completed-acknowledged"
                and response_digest == record["responseDigest"]):
                return
            if (not self._reaped or self._cancelled or type(response_digest) is not str
                or not _DIGEST.fullmatch(response_digest) or record["state"] != "client-exited"
                or self.process.returncode is None or self.process.returncode < 0):
                raise NativeClientError("normal native exit and an adapter response digest are required")
            self.journal._update(self.client_id, state="completed-acknowledged", responseDigest=response_digest)

    def abort_unreleased(self) -> None:
        with self._lock:
            self._custody()
            if self._released:
                raise NativeClientError("released requests cannot be marked aborted-before-release")
            if self._gate >= 0:
                os.close(self._gate)  # EOF is deliberately not a release token
                self._gate = -1
            try:
                self.process._on_reap = None
                try:
                    self.process._reap_owned(timeout=HANDSHAKE_SECONDS + 1)
                except subprocess.TimeoutExpired:
                    self._kill_owned()
                self._reaped = True
                self.journal._update(self.client_id, state="aborted-before-release",
                                     returncode=self.process.returncode, reason="parent closed unreleased gate")
            finally:
                self._close_io()

    def cancel(self) -> None:
        with self._lock:
            self._custody()
            if not self._released:
                self.abort_unreleased()
                return
            self._cancelled = True
            failure = None
            try:
                try:
                    self.journal._update(self.client_id, state="delivery-uncertain", responseDigest=None,
                                         reason="native client cancellation")
                except Exception as exc:
                    failure = exc
                # A journal/profile failure must never prevent cleanup of the
                # child whose unreaped PID reservation is still ours.
                try:
                    self._kill_owned()
                except Exception as exc:
                    failure = failure or exc
            finally:
                self._close_io()
            if failure is not None:
                raise NativeClientError("native client cleaned as far as custody permits; journal or delivery remains uncertain") from failure
