"""Fixed job RPC for the dedicated persistent controller and native clients.

The socket is an account-private host control endpoint. Guests see only the
bounded exec bridge. RPC never accepts a host executable, daemon endpoint,
profile, path selector or credentials from a guest frame.
"""
from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import stat
import struct
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli.execution_backend import GuestCommand, LaunchScope, load_profile
from startup_factory_cli.sandbox_deployment import (
    Deployment, canonical_bytes, decode_object, load_deployment, private_directory,
)
from startup_factory_cli.sandbox_qualification_evidence import verify_deployment_enrollment
from startup_factory_cli.sandbox_registry import SandboxRegistry
from startup_factory_cli.sandbox_watchdog import _peer_uid
from startup_factory_cli.secret_safety import contains_secret_like
from execution_descriptor import execution_version, expected_execution_identity, validate_sandbox_binding
from host_git import HostGit, branch_ref, oid, open_directory, read_regular
from outbox_capability import active_record, authority_lock
from sandbox_acceptance import AcceptanceStore, project_id, task_key, verify_profile_provenance
from startup_factory_cli.sandbox_enrollment import profile_basis_digest


MAX_RPC_BYTES = 512 * 1024
MAX_MESSAGES = 4096
RPC_SECONDS = 10.0
HEARTBEAT_SECONDS = 2.0
JOB_ID = re.compile(r"job-[0-9a-f]{32}\Z")
REQUEST_FIELDS = {"schemaVersion", "id", "deploymentDigest", "profileDigest", "kind",
    "repository", "workspace", "scope", "baseCommit", "targetRef", "guestCommand",
    "promptHex", "capabilityId", "transport", "executionSha256"}
JOB_KINDS = frozenset({"task", "gate", "review", "validation", "doctor", "setup"})
RESUME_MARKERS = frozenset({"resume-review", "resume-plan", "design-approved", "design-pushback",
    "sceptical-design-approved", "sceptical-design-pushback"})
CODE_APPROVALS = frozenset({"review-approval", "security-approval", "architecture-approval",
    "sceptical-architecture-approval", "team-lead-approval"})
LIFECYCLE_ENV = "STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"


class ServiceError(RuntimeError):
    pass


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def private_read(directory: int, name: str, maximum: int) -> bytes:
    if not name or "/" in name or name in {".", ".."}:
        raise ServiceError("invalid private object name")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= maximum:
            raise ServiceError("unsafe private job data")
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) != before.st_size or _stamp(before) != _stamp(os.fstat(fd)) or _stamp(before) != _stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)):
            raise ServiceError("private job data changed")
        return bytes(data)
    finally:
        os.close(fd)


def private_write(directory: int, name: str, raw: bytes, *, immutable: bool = False) -> None:
    if not name or "/" in name or name in {".", ".."} or not 0 < len(raw) <= 4 * 1024 * 1024:
        raise ServiceError("invalid bounded private write")
    pending = "." + name + ".pending"
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise ServiceError("private write made no progress")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if immutable:
        os.link(pending, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(pending, dir_fd=directory)
    else:
        os.replace(pending, name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)


def receive(connection: socket.socket, *, maximum: int = MAX_RPC_BYTES) -> dict:
    deadline = time.monotonic() + RPC_SECONDS
    def exact(size):
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ServiceError("job RPC receive deadline expired")
            connection.settimeout(remaining)
            block = connection.recv(size - len(data))
            if not block:
                raise EOFError("job connection closed")
            data.extend(block)
        return bytes(data)
    size = struct.unpack("!I", exact(4))[0]
    if not 0 < size <= maximum:
        raise ServiceError("job RPC frame exceeds its bound")
    return decode_object(exact(size), maximum=maximum)


def send(connection: socket.socket, value: dict) -> None:
    raw = canonical_bytes(value)
    if not 0 < len(raw) <= MAX_RPC_BYTES:
        raise ServiceError("job RPC response exceeds its bound")
    connection.settimeout(RPC_SECONDS)
    connection.sendall(struct.pack("!I", len(raw)) + raw)


@dataclasses.dataclass(frozen=True)
class JobRequest:
    raw: bytes
    value: dict

    @classmethod
    def parse(cls, raw: bytes, deployment: Deployment, profile) -> JobRequest:
        value = decode_object(raw, maximum=deployment.job_request_max_bytes)
        if set(value) != REQUEST_FIELDS or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or not isinstance(value["id"], str) or not JOB_ID.fullmatch(value["id"]):
            raise ServiceError("unsupported immutable job request")
        if value["deploymentDigest"] != deployment.digest or value["profileDigest"] != profile.digest or value["kind"] not in JOB_KINDS:
            raise ServiceError("job differs from the enrolled deployment/profile")
        scope = LaunchScope.from_dict(value["scope"])
        repository = Path(value["repository"])
        workspace = Path(value["workspace"])
        if not repository.is_absolute() or repository.resolve(strict=True) != repository or scope.project_id != project_id(repository):
            raise ServiceError("job project identity is not canonical")
        projects = [p for p in deployment.projects if p["projectId"] == scope.project_id and p["repository"] == str(repository)]
        if len(projects) != 1 or Path(projects[0]["workspaceRoot"]) / scope.team != workspace:
            raise ServiceError("job workspace is outside its project enrollment")
        oid(value["baseCommit"])
        branch_ref(value["targetRef"])
        command = GuestCommand.from_dict(value["guestCommand"])
        if any(contains_secret_like(argument) for argument in command.argv):
            raise ServiceError("guest command contains credential material")
        text = value["promptHex"]
        if not isinstance(text, str) or len(text) > 128 * 1024 or len(text) % 2 or any(c not in "0123456789abcdef" for c in text):
            raise ServiceError("job prompt exceeds its byte/encoding bound")
        bytes.fromhex(text).decode("utf-8", errors="strict")
        if value["kind"] in {"task", "gate", "review"}:
            if scope.task_id == "-" or scope.attempt < 1 or not isinstance(value["capabilityId"], str) or not re.fullmatch(r"cap-[0-9a-f]{32}", value["capabilityId"]) or not isinstance(value["transport"], str):
                raise ServiceError("publishing job requires an explicit task and native capability")
            supervisor = _load("_sf_service_supervisor", ROOT / "bin/publication-supervisor.py")
            if value["transport"] != supervisor.transport_locator(str(repository), value["capabilityId"], deployment.lifecycle_root):
                raise ServiceError("publication transport differs from its protected capability locator")
        elif value["capabilityId"] is not None or value["transport"] is not None:
            raise ServiceError("validation/setup jobs cannot carry publication authority")
        if value["kind"] == "task":
            if value["targetRef"] != f"refs/heads/agent-task/{scope.team}/{task_key(scope.task_id)}" or not isinstance(value["executionSha256"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["executionSha256"]):
                raise ServiceError("task request does not bind its exact execution/ref")
        elif value["executionSha256"] is not None:
            raise ServiceError("only implementation jobs may update task execution projections")
        # Snapshot all mutable caller data before retaining it.
        return cls(bytes(raw), json.loads(canonical_bytes(value)))

    @property
    def id(self):
        return self.value["id"]

    @property
    def digest(self):
        return sha(self.raw)

    @property
    def scope(self):
        return LaunchScope.from_dict(self.value["scope"])


class JobChannel:
    """One typed host-client session; heartbeat loss never waits for guest I/O."""
    def __init__(self, connection: socket.socket, *, cancel: Callable[[], None]):
        self.connection, self.cancel = connection, cancel
        self.closed = threading.Event()
        self._write_lock = threading.Lock()
        self._reply_lock = threading.Lock()
        self._pending: tuple[str, int, queue.Queue] | None = None
        self._next_id = 0
        self._messages = 0
        self._diagnostic_bytes = 0
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def emit(self, operation: str, **fields):
        if self.closed.is_set():
            raise ServiceError("native launch client disconnected")
        with self._write_lock:
            send(self.connection, {"schemaVersion": 1, "operation": operation, **fields})

    def request(self, operation: str, **fields) -> dict:
        with self._reply_lock:
            self._next_id += 1
            inbox = queue.Queue(maxsize=1)
            self._pending = (operation, self._next_id, inbox)
            try:
                self.emit(operation, sequence=self._next_id, **fields)
                result = inbox.get(timeout=RPC_SECONDS)
                if isinstance(result, BaseException):
                    raise ServiceError("native launch client response unavailable") from result
                return result
            except queue.Empty as exc:
                self.close()
                raise ServiceError("native launch client response timed out") from exc
            finally:
                self._pending = None

    def diagnostic(self, raw: bytes):
        if type(raw) is not bytes or self._diagnostic_bytes + len(raw) > 1024 * 1024:
            raise ServiceError("guest diagnostic budget exhausted")
        self._diagnostic_bytes += len(raw)
        for offset in range(0, len(raw), 8192):
            self.emit("diagnostic", dataHex=raw[offset:offset + 8192].hex())

    def _read(self):
        try:
            while not self.closed.is_set():
                message = receive(self.connection, maximum=64 * 1024)
                self._messages += 1
                if self._messages > MAX_MESSAGES or type(message.get("schemaVersion")) is not int or message["schemaVersion"] != 1:
                    raise ServiceError("job RPC budget/schema invalid")
                operation = message.get("operation")
                if operation == "heartbeat" and set(message) == {"schemaVersion", "operation"}:
                    self.emit("heartbeat")
                    continue
                pending = self._pending
                if not pending or operation != pending[0] + ".result" or type(message.get("sequence")) is not int or message["sequence"] != pending[1] or set(message) != {"schemaVersion", "operation", "sequence", "bodyHex"}:
                    raise ServiceError("unexpected job RPC response")
                encoded = message["bodyHex"]
                if not isinstance(encoded, str) or len(encoded) > 32768 or len(encoded) % 2 or any(c not in "0123456789abcdef" for c in encoded):
                    raise ServiceError("job RPC response bytes invalid")
                pending[2].put_nowait({"raw": bytes.fromhex(encoded)})
        except BaseException as exc:
            pending = self._pending
            if pending is not None:
                with contextlib.suppress(queue.Full):
                    pending[2].put_nowait(exc)
            self.close()

    def close(self):
        if self.closed.is_set():
            return
        self.closed.set()
        with contextlib.suppress(OSError):
            self.connection.shutdown(socket.SHUT_RDWR)
        # Cancellation is independent of response/diagnostic backpressure.
        with contextlib.suppress(Exception):
            self.cancel()


@contextlib.contextmanager
def task_authority(request: JobRequest):
    """Use the same authority→task transaction lock order as native consumers."""
    value, scope = request.value, request.scope
    repository, workspace = Path(value["repository"]), Path(value["workspace"])
    with authority_lock(repository):
        parent = open_directory(workspace)
        try:
            try:
                os.mkdir("executions", 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        finally:
            os.close(parent)
        directory = open_directory(workspace / "executions")
        fd = -1
        try:
            name = "." + task_key(scope.task_id) + ".transaction.lock"
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size:
                raise ServiceError("unsafe task transaction lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fd >= 0:
                fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
            os.close(directory)


def assert_current(request: JobRequest, *, authority_locked: bool = False, require_capability: bool = True,
                   allowed_artifacts: tuple = ()) -> dict | None:
    value, scope = request.value, request.scope
    repository, workspace = Path(value["repository"]), Path(value["workspace"])
    if require_capability and value["capabilityId"] is not None:
        record = active_record(str(repository), str(workspace), value["capabilityId"], authority_locked=authority_locked)
        expected = {"team": scope.team, "featureId": scope.feature_id, "role": scope.role,
                    "executionKind": "task" if value["kind"] == "task" else "gate"}
        if value["kind"] == "task":
            expected.update(taskId=scope.task_id, attempt=scope.attempt)
        if any(record[key] != expected[key] for key in expected):
            raise ServiceError("native capability is not the approved job assignment")
    holds = _load("_sf_service_holds_" + str(threading.get_ident()), ROOT / "bin/task-hold.py")
    hold_args = dict(repo=str(repository), workspace=str(workspace), team=scope.team,
        feature=scope.feature_id, task=scope.task_id)
    if holds.check(SimpleNamespace(**hold_args, marker=None)) != 0:
        # Only the broker's comment-only resume barrier exception is usable.
        # These markers were independently narrowed to the authenticated role.
        markers = [marker for marker, statuses in allowed_artifacts
                   if marker in RESUME_MARKERS and statuses == (None,)]
        if value["kind"] not in {"gate", "review"} or not markers or not any(
                holds.check(SimpleNamespace(**hold_args, marker=marker)) == 0 for marker in markers):
            raise ServiceError("assigned task is held")
    if value["kind"] != "task":
        return None
    directory = open_directory(workspace / "executions")
    try:
        record = decode_object(private_read(directory, task_key(scope.task_id) + ".json", 1024 * 1024), maximum=1024 * 1024)
    finally:
        os.close(directory)
    expected = expected_execution_identity(record, workspace=workspace, team=scope.team,
        feature=scope.feature_id, task=scope.task_id, key=task_key(scope.task_id), role=scope.role, attempt=scope.attempt)
    if any(record.get(key) != child for key, child in expected.items()):
        raise ServiceError("job task execution identity is stale")
    return record


def _workspace_json(workspace: Path, name: str, maximum: int) -> dict:
    directory = open_directory(workspace)
    try:
        return decode_object(read_regular(directory, name, maximum, private=False), maximum=maximum)
    finally:
        os.close(directory)


def publication_policy(request: JobRequest, bundle_root: Path) -> tuple:
    """Narrow the bridge to the same authenticated protocol roles as outbox."""
    if request.value["capabilityId"] is None:
        return ()
    from team_policy import load_team_policy
    scope, value = request.scope, request.value
    directory = open_directory(bundle_root / "config", root_owned=True)
    try:
        board = decode_object(read_regular(directory, "statuses.config.json", 256 * 1024, private=False), maximum=256 * 1024)
    finally:
        os.close(directory)
    policy = load_team_policy(Path(value["repository"]), Path(value["workspace"]), scope.team,
        scope.feature_id, bundle_root, bundle_root)
    protocol = {}
    for line in policy.text.splitlines():
        match = re.fullmatch(r"PROTOCOL_([A-Z_]+)=(.+)", line.strip())
        if match:
            key, concrete = match.groups()
            if key in protocol or (concrete != "null" and not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", concrete)):
                raise ServiceError("authenticated protocol roles are malformed")
            protocol[key] = concrete
    if not policy.text:
        protocol = {"TEAM_LEAD": "team-lead", "PRINCIPAL_ARCHITECT": "principal-architect",
            "SCEPTICAL_ARCHITECT": "sceptical-architect", "SECURITY_REVIEWER": "senior-security-engineer"}
    core = [protocol.get(key) for key in ("TEAM_LEAD", "PRINCIPAL_ARCHITECT", "SCEPTICAL_ARCHITECT", "SECURITY_REVIEWER")]
    if any(not role or role == "null" for role in core) or len(set(core)) != 4:
        raise ServiceError("authenticated review board must have four distinct roles")
    roles = {scope.role} | {key.lower().replace("_", "-") for key, concrete in protocol.items() if concrete == scope.role}
    result = {}
    if value["kind"] == "task":
        review_status = tuple(row["name"] for row in board["tasks"]["statuses"] if row.get("kind") == "review" and not row.get("terminal"))
        result.update({"review-request": (None, *review_status), "design-note": (None,),
            "andon": (None,), "context-request": (None,)})
    else:
        owners = {"team-lead-approval": "TEAM_LEAD", "architecture-approval": "PRINCIPAL_ARCHITECT",
            "sceptical-architecture-approval": "SCEPTICAL_ARCHITECT", "security-approval": "SECURITY_REVIEWER"}
        for marker, spec in board["markers"].items():
            if marker in {"production-approval", "deployment"} or not roles.intersection(spec.get("authorizedRoles", [])):
                continue
            if marker in owners and protocol[owners[marker]] != scope.role:
                continue
            if marker in {"product-approval", "product-pushback"}:
                product = protocol.get("PRODUCT_MANAGER")
                if (product and product != "null" and scope.role != product) or ((not product or product == "null") and "team-lead" not in roles):
                    continue
            result[marker] = (None,)
        # Pre-claim design notes are comment-only and confer no gate authority.
        result["design-note"] = (None,)
        if "team-lead" in roles:
            result.update(handoff=(None,), escalation=(None,))
    return tuple(sorted(result.items()))


class NativeJobExecutor:
    """Production resources are constructed once in the persistent service PID."""
    def __init__(self, deployment: Deployment):
        from startup_factory_cli.native_clients import GateTools, NativeClientJournal, ProgramPin
        from startup_factory_cli.native_custody import JournalCustody
        from startup_factory_cli.native_authority import NativeRuntimeAuthority
        from startup_factory_cli.sandbox_watchdog import IndependentWatchdogClient
        from startup_factory_cli.docker_backend import DockerBackend
        from startup_factory_cli.sandbox_controller import SandboxController
        from sandbox_jobs import GuestPrograms, StreamProvisioner
        from startup_factory_cli.model_credentials import ScopedModelCredentials
        self.deployment = deployment
        ambient = os.environ.get(LIFECYCLE_ENV)
        if ambient is not None and ambient != deployment.lifecycle_root:
            raise ServiceError("ambient lifecycle authority differs from protected deployment")
        os.environ[LIFECYCLE_ENV] = deployment.lifecycle_root
        if deployment.max_active_jobs != 1:
            raise ServiceError("this release requires maxActiveJobs=1 per enrolled namespace; concurrent namespace qualification is not supported")
        self.profile = load_profile(Path(deployment.profile_path))
        self.registry = SandboxRegistry(Path(deployment.registry_root), self.profile.namespace)
        verify_deployment_enrollment(deployment, self.profile, Path(deployment.receipt_path), self.registry)
        from startup_factory_cli.sandbox_network_policy import load_network_policy
        self.network_policy = load_network_policy(Path(deployment.network_policy_path), self.profile)
        pins = deployment.programs
        tools = GateTools(*(ProgramPin(Path(pins[key]["path"]), pins[key]["sha256"]) for key in ("python", "gate", "lifecycleHelper")))
        self.journal = NativeClientJournal(Path(deployment.native_journal_root), Path(deployment.profile_path), tools)
        self.custody = JournalCustody(self.journal)
        self.watchdog = IndependentWatchdogClient(deployment)
        self.authority = NativeRuntimeAuthority(deployment, self.registry, self.custody, self.watchdog)
        controller_ref = []
        backend = DockerBackend(Path(deployment.profile_path), custody=self.custody,
            native_client_reconciler=self.authority,
            permit=lambda profile, request: controller_ref[0].operation_permit(profile, request))
        self.controller = SandboxController(Path(deployment.profile_path), Path(deployment.receipt_path),
            self.registry, backend, reconciler=self.authority, provisioner=StreamProvisioner(),
            watchdog=self.watchdog, policy=lambda operation, profile, scope: profile == self.profile)
        controller_ref.append(self.controller)
        self.credentials = ScopedModelCredentials(deployment, self.custody)
        try:
            self.credentials.assert_ready()
            self.controller.start()
            self.programs = GuestPrograms.from_directory(Path(deployment.bundle_root) / "bin")
        except BaseException:
            self.close()
            raise
        self._scope_lock = threading.Lock()
        self._scopes: set[str] = set()
        self._monitors: set[threading.Thread] = set()
        self._uncertain = threading.Event()

    def _projection(self, request: JobRequest, binding: dict, *, authority_locked: bool = False):
        if request.value["kind"] != "task":
            return
        binding = validate_sandbox_binding(binding)
        with contextlib.nullcontext() if authority_locked else task_authority(request):
            current = assert_current(request, authority_locked=True, require_capability=False)
            previous = current.get("sandbox")
            if previous is not None and previous["generation"] != binding["generation"]:
                raise ServiceError("task execution has another sandbox generation")
            current.update(schemaVersion=2, sandbox=binding)
            scope = request.scope
            parent = open_directory(Path(request.value["workspace"]) / "executions")
            try:
                private_write(parent, task_key(scope.task_id) + ".json", canonical_bytes(current))
            finally:
                os.close(parent)

    def _context(self, request: JobRequest, git: HostGit, transaction, allowed_artifacts: tuple = ()) -> tuple[tuple, dict | None]:
        """Snapshot host-approved task data; tracker text cannot choose authority."""
        from review_evidence import latest_review_request, request_binding
        from delivery_profile import build_review_package
        from execution_descriptor import require_accepted_sandbox
        value, scope = request.value, request.scope
        if value["capabilityId"] is None:
            return (), None
        snapshot = _workspace_json(Path(value["workspace"]), "tasks.json", 8 * 1024 * 1024)
        tasks = snapshot.get("tasks")
        if snapshot.get("featureId") != scope.feature_id or type(tasks) is not list:
            raise ServiceError("task context is not the fresh assigned feature export")
        rows = [task for task in tasks if type(task) is dict and str(task.get("taskId")) == scope.task_id]
        if len(rows) != 1:
            raise ServiceError("assigned task is absent or duplicated in context")
        task = rows[0]
        binding = None
        files = []
        # Code verdicts require the latest exact request and an independently
        # rebuilt raw-object diff of an already accepted implementation.
        if value["kind"] in {"gate", "review"}:
            board_dir = open_directory(Path(self.deployment.bundle_root) / "config", root_owned=True)
            try:
                board = decode_object(read_regular(board_dir, "statuses.config.json", 256 * 1024, private=False), maximum=256 * 1024)
            finally:
                os.close(board_dir)
            review_statuses = {row["name"] for row in board["tasks"]["statuses"] if row.get("kind") == "review"}
            if task.get("status") in review_statuses:
                binding = request_binding(latest_review_request(snapshot, scope.task_id))
                if binding["head"] != value["baseCommit"]:
                    raise ServiceError("review source is not the latest requested head")
                directory = open_directory(Path(value["workspace"]) / "executions")
                try:
                    record = decode_object(private_read(directory, task_key(scope.task_id) + ".json", 1024 * 1024), maximum=1024 * 1024)
                finally:
                    os.close(directory)
                accepted = require_accepted_sandbox(record)
                if accepted is None or accepted["acceptedCommit"] != binding["head"] or record.get("attempt") != scope.attempt:
                    raise ServiceError("review head has no accepted sandbox import")
                implementation_scope = LaunchScope(scope.project_id, scope.team, scope.feature_id,
                    record["role"], scope.task_id, record["attempt"])
                receipt = AcceptanceStore(self.registry).verify(implementation_scope, accepted, transaction=transaction)
                verify_profile_provenance(receipt, self.deployment, self.profile)
                if git.read_ref(receipt["promotion"]["targetRef"]) != binding["head"]:
                    raise ServiceError("accepted task ref changed before review")
                package, base, head = build_review_package(git.repository, scope.task_id, binding["base"], binding["head"])
                if (base, head, sha(package)) != (binding["base"], binding["head"], binding["package"]):
                    raise ServiceError("rebuilt review package differs from latest request")
                files.extend((("review-bindings.json", canonical_bytes(binding)), ("review.diff", package)))
            elif value["kind"] == "review":
                raise ServiceError("review job is not in a review status")
        context = {"schemaVersion": 1, "scope": scope.as_dict(), "baseCommit": value["baseCommit"],
            "task": task, "reviewBinding": binding}
        grants = {marker for marker, _statuses in allowed_artifacts}
        if grants.intersection({"product-approval", "product-pushback"}):
            try:
                product = _workspace_json(Path(value["workspace"]), "product-acceptance-request.json", 128 * 1024)
            except FileNotFoundError:
                product = None
            terminal = {row["name"] for row in board["tasks"]["statuses"] if row.get("terminal") and row.get("requiresCommit")}
            if product is not None and product.get("anchorTaskId") == scope.task_id and tasks and all(row.get("status") in terminal for row in tasks):
                from product_acceptance import validate_request
                validate_request(product, snapshot)
                if product["featureId"] != scope.feature_id or git.read_ref("refs/heads/" + scope.team) != product["commit"] or product["commit"] != value["baseCommit"]:
                    raise ServiceError("product request is not bound to the current feature source")
                # This is the exact release-created request, including its
                # integration-evidence identity. Publication/release recomputes
                # that evidence; exposing context does not attest its validity.
                context["productAcceptanceRequest"] = product
        if grants.intersection(RESUME_MARKERS):
            holds = _load("_sf_service_context_holds_" + str(threading.get_ident()), ROOT / "bin/task-hold.py")
            authority = holds.protected_hold_authority(Path(value["repository"]), scope.team, scope.feature_id)
            registry = holds.load_protected_registry(authority, Path(value["repository"]), scope.team, scope.feature_id)
            entry = ((registry or {}).get("tasks") or {}).get(task_key(scope.task_id))
            if entry and entry.get("state") == "resume-review-pending":
                generation = entry.get("generation")
                if entry.get("taskId") != scope.task_id or type(generation) is not int or not 1 <= generation <= 2**31 - 1:
                    raise ServiceError("resume context has no exact protected hold generation")
                directory = Path(value["workspace"]) / "holds" / task_key(scope.task_id) / ("generation-" + str(generation))
                blocked_path = directory / "blocked-snapshot.json"
                current_path = directory / "resume-snapshot.json"
                if entry.get("blockedSnapshotPath") != str(blocked_path) or entry.get("resumeSnapshotPath") != str(current_path) or entry.get("resumeRequestPath") != str(directory / "resume-review-request.md"):
                    raise ServiceError("resume projection differs from its fixed hold slot")
                blocked = _workspace_json(directory, "blocked-snapshot.json", 128 * 1024)
                resumed = _workspace_json(directory, "resume-snapshot.json", 128 * 1024)
                resume_request = _workspace_json(directory, "resume-review-request.json", 128 * 1024)
                excluded = holds.authenticated_resolution_comment_ids(Path(value["repository"]), Path(value["workspace"]), scope.team, scope.feature_id, task)
                communication = holds.communication_digest(task, excluded)
                expected_resume = holds.full_snapshot(scope.feature_id, task)
                same_task = {key: child for key, child in resumed.items() if key != "capturedAt"} == {key: child for key, child in expected_resume.items() if key != "capturedAt"}
                if holds.digest(blocked) != entry.get("blockedSnapshotDigest") or holds.digest(resumed) != entry.get("resumeSnapshotDigest") or communication != entry.get("resumeCommunicationDigest") or not same_task:
                    raise ServiceError("resume snapshots or current communication changed")
                if resume_request.get("schemaVersion") != 1 or resume_request.get("taskId") != scope.task_id or resume_request.get("holdId") != entry.get("holdId") or resume_request.get("currentCommunicationDigest") != communication or resume_request.get("blockedCommunicationDigest") != entry.get("blockedCommunicationDigest"):
                    raise ServiceError("resume request is not the protected current hold")
                context["resumeReview"] = {"holdId": entry["holdId"], "generation": generation,
                    "blockedCommunicationDigest": entry["blockedCommunicationDigest"], "currentCommunicationDigest": communication,
                    "previousWorktreeClean": entry.get("previousWorktreeClean"),
                    "blockedSnapshot": blocked, "currentSnapshot": resumed,
                    "delta": holds.communication_delta(blocked, resumed)}
        raw = canonical_bytes(context)
        if len(raw) > 128 * 1024 or contains_secret_like(raw.decode("utf-8")):
            raise ServiceError("task context exceeds its bound or contains credentials")
        files.append(("task-context.json", raw))
        return tuple(files), binding

    def validate_request(self, request: JobRequest):
        # Private job files are data; the current enrollment remains authority.
        if self._uncertain.is_set():
            raise ServiceError("controller shutdown/cancellation is uncertain; reconciliation is required")
        verify_deployment_enrollment(self.deployment, self.profile, Path(self.deployment.receipt_path), self.registry)

    def run(self, request: JobRequest, channel: JobChannel, cancel: threading.Event) -> dict:
        from sandbox_jobs import BoundJob, SandboxJobRunner
        from sandbox_artifacts import ArtifactStore
        from startup_factory_cli.secret_safety import contains_secret_like
        value, scope = request.value, request.scope
        key = sha(canonical_bytes(scope.as_dict()))
        with self._scope_lock:
            if key in self._scopes:
                raise ServiceError("the assigned scope already has an active sandbox job")
            self._scopes.add(key)
        handle = [None]
        monitoring_done = threading.Event()
        def monitor_disconnect():
            while not monitoring_done.wait(0.05):
                if not cancel.is_set():
                    continue
                generation = handle[0]
                if generation is None:
                    continue
                # Independent ledger revocation precedes any native signal.
                with contextlib.suppress(Exception):
                    self.watchdog.fence(generation)
                with contextlib.suppress(Exception):
                    self.custody.cancel_generation(generation.name, generation.generation, generation.epoch)
                return
        monitor = threading.Thread(target=monitor_disconnect, daemon=True)
        with self._scope_lock:
            self._monitors.add(monitor)
        monitor.start()
        try:
            self.validate_request(request)
            self.credentials.assert_ready()
            allowed = publication_policy(request, Path(self.deployment.bundle_root))
            git = HostGit(Path(value["repository"]))
            publishing = value["capabilityId"] is not None
            with self.registry.locked() as transaction, (task_authority(request) if publishing else contextlib.nullcontext()):
                record = assert_current(request, authority_locked=True, allowed_artifacts=allowed) if publishing else None
                if record is not None and sha(canonical_bytes(record)) != value["executionSha256"]:
                    raise ServiceError("task execution changed after launch approval")
                context_files, review_binding = self._context(request, git, transaction, allowed)
            if review_binding is None:
                allowed = tuple((marker, statuses) for marker, statuses in allowed if marker not in CODE_APPROVALS)
            if cancel.is_set():
                raise ServiceError("native launch client disconnected before dispatch")
            if value["kind"] == "task" and git.read_ref(value["targetRef"]) != value["baseCommit"]:
                raise ServiceError("assigned task ref changed before dispatch")
            quarantine = Path(self.deployment.registry_root) / ("quarantine-" + request.id)
            quarantine.mkdir(mode=0o700)
            job = BoundJob(Path(value["repository"]), Path(value["workspace"]), scope,
                value["baseCommit"], value["targetRef"], GuestCommand.from_dict(value["guestCommand"]),
                bytes.fromhex(value["promptHex"]), value["transport"], allowed, request.digest,
                collect_changes=value["kind"] == "task", context_files=context_files,
                verify_unchanged=value["kind"] in {"validation", "gate", "review"})
            completion = None
            completion_bound = [False]
            def current(*_promotion_inputs):
                if cancel.is_set():
                    return False
                assert_current(request, authority_locked=True, allowed_artifacts=allowed)
                if review_binding is not None:
                    from review_evidence import latest_review_request, request_binding
                    snapshot = _workspace_json(Path(value["workspace"]), "tasks.json", 8 * 1024 * 1024)
                    if snapshot.get("featureId") != scope.feature_id or request_binding(latest_review_request(snapshot, scope.task_id)) != review_binding:
                        raise ServiceError("review request changed during execution")
                return True
            if value["kind"] in {"gate", "review"} and value["capabilityId"] is not None:
                from sandbox_completion import GateCompletionStore
                completion = GateCompletionStore(self.registry, authorize=current,
                    deployment_digest=self.deployment.digest, profile_basis_digest=profile_basis_digest(self.profile))
            def bound(binding, context):
                from startup_factory_cli.sandbox_controller import GenerationHandle
                handle[0] = GenerationHandle(binding["name"], binding["generation"], binding["epoch"])
                if cancel.is_set():
                    raise ServiceError("launch client disconnected before guest activation")
                if completion is not None:
                    with self.registry.locked() as transaction, task_authority(request):
                        completion.bind(capability_id=value["capabilityId"], job_id=request.id,
                            request_digest=request.digest, scope=scope, binding=binding,
                            review_binding=review_binding, transaction=transaction)
                    completion_bound[0] = True
                self._projection(request, binding)
                reply = channel.request("bound", binding=binding, relayContext=context)
                if reply["raw"] != b"ack":
                    raise ServiceError("native launch client did not acknowledge its exact binding")
            def publish(raw):
                if cancel.is_set():
                    raise ServiceError("launch client disconnected")
                return channel.request("publish", requestHex=raw.hex())["raw"]
            runner = SandboxJobRunner(self.controller, git, self.programs,
                contains_secret=contains_secret_like, publish=publish, on_bound=bound,
                on_state=lambda binding: self._projection(request, binding),
                quarantine_root=quarantine, on_diagnostic=channel.diagnostic,
                credentials=self.credentials, model_required=value["kind"] in {"task", "gate", "review", "doctor"},
                network_policy=self.network_policy,
                context_read=lambda: {"schemaVersion": 1, "scope": scope.as_dict(), "reviewBinding": review_binding,
                    "baseCommit": value["baseCommit"], "promptPath": "/opt/startup-factory/prompt.md",
                    "workspace": "/workspace/project"},
                progress_report=lambda stage, message: channel.emit("progress", stage=stage, message=message))
            try:
                result = runner.run(job)
            except BaseException:
                if completion is not None and completion_bound[0]:
                    with contextlib.suppress(Exception), self.registry.locked() as transaction:
                        completion.finish(capability_id=value["capabilityId"], job_id=request.id,
                            request_digest=request.digest, success=False, readonly_verified=False,
                            evidence_digest=sha(b"job failed or cleanup uncertain"), transaction=transaction)
                raise
            if completion is not None:
                try:
                    with self.registry.locked() as transaction, task_authority(request):
                        success = result.exit_code == 0 and not cancel.is_set() and result.verification_digest is not None
                        completion.finish(capability_id=value["capabilityId"], job_id=request.id,
                            request_digest=request.digest, success=success,
                            readonly_verified=success, evidence_digest=result.verification_digest or sha(b"job failed read-only verification"),
                            transaction=transaction)
                except BaseException:
                    with contextlib.suppress(Exception), self.registry.locked() as transaction:
                        completion.finish(capability_id=value["capabilityId"], job_id=request.id,
                            request_digest=request.digest, success=False, readonly_verified=False,
                            evidence_digest=sha(b"completion authority revoked or uncertain"), transaction=transaction)
                    raise
            answer = {"schemaVersion": 1, "jobId": request.id, "exitCode": result.exit_code,
                "status": result.status, "binding": result.binding,
                "diagnosticDigest": result.diagnostic_digest, "promotionReceipt": None}
            if result.exit_code == 0 and result.quarantine_receipt is not None:
                with self.registry.locked() as transaction, task_authority(request), ArtifactStore(git, quarantine, assignment_digest=result.assignment_digest,
                        target_ref=value["targetRef"], expected_base=value["baseCommit"],
                        authorize=current, authority_lock=contextlib.nullcontext) as store:
                    store.candidate_source(result.quarantine_receipt["exportId"], contains_secret=contains_secret_like)
                    promotion = store.promote(result.quarantine_receipt["exportId"])
                    if current() is not True:
                        raise ServiceError("task import authority was revoked")
                    from sandbox_projection import materialize
                    materialize(git, workspace=Path(value["workspace"]), team=scope.team,
                        task=scope.task_id, role=scope.role, attempt=scope.attempt,
                        base_commit=value["baseCommit"], accepted_commit=promotion["commit"],
                        staging=Path(self.deployment.registry_root) / ("projection-" + request.id))
                    binding = dict(result.binding, state="accepted", acceptedCommit=promotion["commit"],
                        acceptedTree=promotion["tree"], acceptedExportDigest=promotion["manifestDigest"])
                    AcceptanceStore(self.registry, authorize=current,
                        deployment_digest=self.deployment.digest, profile_basis_digest=profile_basis_digest(self.profile)).record(
                        scope, binding, promotion, evidence_digest=sha(canonical_bytes(promotion)), transaction=transaction)
                    self._projection(request, binding, authority_locked=True)
                answer.update(binding=binding, promotionReceipt=promotion, status="imported")
            return answer
        finally:
            monitoring_done.set()
            monitor.join(timeout=RPC_SECONDS + 5)
            with self._scope_lock:
                self._scopes.discard(key)
                if not monitor.is_alive():
                    self._monitors.discard(monitor)
                else:
                    self._uncertain.set()
            if monitor.is_alive():
                raise ServiceError("native cancellation did not quiesce; independent watchdog reconciliation is required")

    def close(self):
        if any(monitor.is_alive() for monitor in getattr(self, "_monitors", ())):
            raise ServiceError("native cancellation is still live; do not close shared custody underneath it")
        failed = False
        for resource in (self.credentials, self.custody, self.watchdog, self.registry):
            try:
                resource.close()
            except Exception:
                failed = True
        if failed:
            raise ServiceError("service shutdown remains uncertain; inspect protected custody and watchdog state")


class JobServer:
    def __init__(self, deployment: Deployment, executor: NativeJobExecutor):
        self.deployment, self.executor = deployment, executor
        if os.geteuid() != deployment.controller_uid or os.getegid() != deployment.controller_gid:
            raise ServiceError("job service requires its dedicated enrolled identity")
        private_directory(Path(deployment.job_root), deployment.controller_uid)
        self._jobs = open_directory(Path(deployment.job_root), private=True)
        self._queue_slots = threading.BoundedSemaphore(deployment.max_queued_jobs)
        self._active_slots = threading.BoundedSemaphore(deployment.max_active_jobs)
        self._lock = threading.RLock()
        self._active: set[str] = set()
        self._stop = threading.Event()
        self._socket = None
        self._socket_identity = None
        self._workers: set[threading.Thread] = set()
        self._connections: dict[socket.socket, threading.Event] = {}
        self._shutdown_lock = threading.Lock()
        self._closed = False
        self._ready = threading.Event()

    def _connection(self, connection: socket.socket, cancel: threading.Event):
        channel = None; identifier = None; active = False
        try:
            if self._stop.is_set():
                raise ServiceError("job service is stopping")
            if _peer_uid(connection) != self.deployment.controller_uid:
                raise ServiceError("job peer belongs to another account")
            initial = receive(connection, maximum=4096)
            if set(initial) != {"schemaVersion", "operation", "jobId", "requestDigest"} or type(initial["schemaVersion"]) is not int or initial["schemaVersion"] != 1 or initial["operation"] != "job.run" or not isinstance(initial["jobId"], str) or not JOB_ID.fullmatch(initial["jobId"]):
                raise ServiceError("unsupported job admission")
            identifier = initial["jobId"]
            raw = private_read(self._jobs, identifier + ".request.json", self.deployment.job_request_max_bytes)
            request = JobRequest.parse(raw, self.deployment, self.executor.profile)
            if request.id != identifier or request.digest != initial["requestDigest"]:
                raise ServiceError("immutable approved job bytes differ")
            validator = getattr(self.executor, "validate_request", None)
            if validator is not None:
                validator(request)
            with self._lock:
                if self._stop.is_set():
                    raise ServiceError("job service is stopping")
                if identifier in self._active:
                    raise ServiceError("job is already active")
                try:
                    prior = decode_object(private_read(self._jobs, identifier + ".result.json", 4 * 1024 * 1024), maximum=4 * 1024 * 1024)
                except FileNotFoundError:
                    prior = None
                if prior is not None:
                    if prior.get("requestDigest") != request.digest or prior.get("state") != "complete":
                        raise ServiceError("job history is uncertain; do not re-execute")
                    send(connection, {"schemaVersion": 1, "operation": "complete", "result": prior["result"]})
                    return
                private_write(self._jobs, identifier + ".result.json", canonical_bytes({"schemaVersion": 1, "state": "running", "requestDigest": request.digest}), immutable=True)
                self._active.add(identifier); active = True
            channel = JobChannel(connection, cancel=cancel.set)
            channel.emit("accepted", jobId=identifier)
            queue_deadline = time.monotonic() + self.executor.profile.limits.wall_seconds
            while not self._active_slots.acquire(timeout=0.2):
                if cancel.is_set() or self._stop.is_set() or time.monotonic() >= queue_deadline:
                    raise ServiceError("queued job disconnected")
            try:
                if cancel.is_set() or self._stop.is_set() or time.monotonic() >= queue_deadline:
                    raise ServiceError("job disconnected before dispatch")
                answer = self.executor.run(request, channel, cancel)
            finally:
                self._active_slots.release()
            private_write(self._jobs, identifier + ".result.json", canonical_bytes({"schemaVersion": 1, "state": "complete", "requestDigest": request.digest, "result": answer}))
            channel.emit("complete", result=answer)
        except BaseException:
            if channel is not None:
                with contextlib.suppress(Exception):
                    channel.emit("error", message="Sandbox job refused or uncertain; inspect protected job and watchdog state.")
            else:
                with contextlib.suppress(Exception):
                    send(connection, {"schemaVersion": 1, "operation": "error", "message": "Sandbox job admission refused."})
        finally:
            if channel is not None:
                channel.close()
            connection.close()
            if active:
                with self._lock:
                    self._active.discard(identifier)
            with self._lock:
                self._connections.pop(connection, None)
                self._workers.discard(threading.current_thread())
            self._queue_slots.release()

    def serve(self):
        path = Path(self.deployment.socket_path)
        private_directory(path.parent, self.deployment.controller_uid)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket = listener
        try:
            listener.bind(str(path))  # A stale/replaced endpoint is never unlinked/adopted.
            os.chmod(path, 0o600)
            info = path.lstat(); self._socket_identity = (info.st_dev, info.st_ino)
            listener.listen(self.deployment.max_queued_jobs)
            listener.settimeout(0.2)
            self._ready.set()
            while not self._stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                if not self._queue_slots.acquire(blocking=False):
                    connection.close(); continue
                cancel = threading.Event()
                worker = threading.Thread(target=self._connection, args=(connection, cancel), daemon=True)
                with self._lock:
                    if self._stop.is_set():
                        connection.close(); self._queue_slots.release(); continue
                    self._connections[connection] = cancel
                    self._workers.add(worker)
                try:
                    worker.start()
                except BaseException:
                    with self._lock:
                        self._workers.discard(worker); self._connections.pop(connection, None)
                    connection.close(); self._queue_slots.release()
                    raise
        finally:
            listener.close()
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == self._socket_identity:
                    path.unlink()
            except FileNotFoundError:
                pass

    def stop(self):
        self._stop.set()
        with self._lock:
            connections = list(self._connections.items())
        for connection, cancel in connections:
            cancel.set()
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)

    def close(self):
        with self._shutdown_lock:
            if self._closed:
                return
            self.stop()
            deadline = time.monotonic() + min(30.0, self.executor.profile.limits.wall_seconds + 5.0)
            while True:
                with self._lock:
                    workers = list(self._workers)
                if not workers:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Do not close registry/custody descriptors underneath a
                    # worker. Process exit leaves recovery to the independent
                    # watchdog and durable uncertain history.
                    raise ServiceError("job shutdown is uncertain; independent watchdog reconciliation is required")
                workers[0].join(timeout=min(0.1, remaining))
            self.executor.close()
            os.close(self._jobs)
            self._closed = True
