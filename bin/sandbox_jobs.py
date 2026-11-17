#!/usr/bin/env python3
"""Trusted host job orchestration and finite binary transfers.

This library runs in the dedicated persistent controller service. It never
creates enrollment, accepts guest-selected host paths, or promotes on agent
exit. The native launch client supplies a bounded publication callback whose
relay remains a publication-supervisor descendant. All guest bytes are data.
"""
from __future__ import annotations

import dataclasses
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import sys
import time
import zlib
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from startup_factory_cli.execution_backend import (  # noqa: E402
    ArtifactReference, GuestCommand, LaunchScope, LaunchSpec, _read_protected,
    canonical_digest,
)
from startup_factory_cli.sandbox_controller import (  # noqa: E402
    AuthorityProof, provisioning_request_digest,
)
from host_git import HostGit, branch_ref, oid  # noqa: E402
from sandbox_artifacts import ArtifactLimits, ArtifactStore, parse_manifest, _json  # noqa: E402
from sandbox_ingest import BoundContext, parse_request  # noqa: E402
from sandbox_source import MAX_PACKAGE_BYTES, build_source_package, parse_source_package  # noqa: E402
from sandbox_transport import RelayContext, RelayLimits, response_frame  # noqa: E402
from sandbox_transport import verify_watchdog_lease  # noqa: E402


MAX_PROVISION_BYTES = 44 * 1024 * 1024
MAX_EXPORT_BYTES = 36 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 1024 * 1024
PROGRAM_NAMES = frozenset({"sandbox_source.py", "sandbox_guest_bridge.py",
    "sandbox_guest_client.py", "sandbox_export.py", "submit-artifact.sh",
    "sandbox_guest_context.py", "sandbox_guest_progress.py", "sandbox_guest_review.py"})
CONTEXT_LIMITS = {"task-context.json": 128 * 1024, "review-bindings.json": 128 * 1024, "review.diff": 2 * 1024 * 1024}
GUEST_BIN = "/opt/startup-factory/bin"
GUEST_SOURCE = "/opt/startup-factory/input.json"
GUEST_SOCKET = "/workspace/.sf-agent/artifacts.sock"
AGENT_UID = 2000

# Fixed installation logic runs only in the guest. Its argv stays below the
# GuestCommand per-argument bound; code bytes and source arrive through stdin.
BOOTSTRAP = r'''import hashlib,json,os,pathlib,struct,sys
def exact(n):
 b=bytearray()
 while len(b)<n:
  c=os.read(0,min(65536,n-len(b)))
  if not c:raise ValueError('truncated')
  b.extend(c)
 return bytes(b)
n=struct.unpack('!I',exact(4))[0]
if not 0<n<=1048576:raise ValueError('header')
h=json.loads(exact(n))
if set(h)!={'schemaVersion','programs','sourceBytes','sourceDigest','promptHex','contexts','inputDigest'} or type(h['schemaVersion'])is not int or h['schemaVersion']!=1:raise ValueError('schema')
names={'sandbox_source.py','sandbox_guest_bridge.py','sandbox_guest_client.py','sandbox_export.py','submit-artifact.sh','sandbox_guest_context.py','sandbox_guest_progress.py','sandbox_guest_review.py'}
if type(h['programs'])is not dict or set(h['programs'])!=names or type(h['sourceBytes'])is not int or not 0<h['sourceBytes']<=41943040:raise ValueError('limits')
root=pathlib.Path('/opt/startup-factory');root.mkdir(mode=0o755)
folder=root/'bin';folder.mkdir(mode=0o755)
root.chmod(0o755);folder.chmod(0o755)
def write(p,b,mode):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 try:
  os.fchmod(fd,mode)
  v=memoryview(b)
  while v:
   n=os.write(fd,v)
   if n<=0:raise ValueError('write')
   v=v[n:]
 finally:os.close(fd)
for name,value in h['programs'].items():
 if type(value)is not str or len(value)>262144:raise ValueError('program')
 write(folder/name,bytes.fromhex(value),0o755)
prompt=bytes.fromhex(h['promptHex'])
if len(prompt)>65536:raise ValueError('prompt')
write(root/'prompt.md',prompt,0o644)
source=exact(h['sourceBytes'])
if 'sha256:'+hashlib.sha256(source).hexdigest()!=h['sourceDigest']:raise ValueError('source')
write(root/'input.json',source,0o600)
contexts=root/'context';contexts.mkdir(mode=0o755);contexts.chmod(0o755)
limits={'task-context.json':131072,'review-bindings.json':131072,'review.diff':2097152};digests={}
if type(h['contexts'])is not dict or set(h['contexts'])-set(limits):raise ValueError('contexts')
for name,meta in sorted(h['contexts'].items()):
 if set(meta)!={'size','sha256'} or type(meta['size'])is not int or not 0<=meta['size']<=limits[name]:raise ValueError('context size')
 value=exact(meta['size']);digest='sha256:'+hashlib.sha256(value).hexdigest()
 if digest!=meta['sha256']:raise ValueError('context digest')
 digests[name]=digest;write(contexts/name,value,0o444)
expected=h['sourceDigest'] if not digests else 'sha256:'+hashlib.sha256(json.dumps({'source':h['sourceDigest'],'contextFiles':digests},sort_keys=True,separators=(',',':')).encode()).hexdigest()
if expected!=h['inputDigest'] or os.read(0,1):raise ValueError('input')
workspace=pathlib.Path('/workspace');workspace.mkdir(mode=0o700,exist_ok=True)
(workspace/'.sf-agent').mkdir(mode=0o700)
sys.path.insert(0,str(folder))
from sandbox_source import initialize_guest,initialize_agent_identity
initialize_agent_identity()
receipt=initialize_guest(source,workspace/'project')
receipt['inputDigest']=expected
workspace.chmod(0o755)
for current,dirs,files in os.walk(workspace/'project',followlinks=False):
 os.chown(current,2000,2000)
 for name in files:os.chown(pathlib.Path(current)/name,2000,2000,follow_symlinks=False)
home=pathlib.Path('/home/sf-agent');home.mkdir(mode=0o700,exist_ok=True)
if home.is_symlink() or not home.is_dir() or home.stat().st_uid not in {0,2000} or home.stat().st_mode&0o022:raise ValueError('home')
os.chown(home,2000,2000)
home.chmod(0o700)
print(json.dumps(receipt,sort_keys=True,separators=(',',':')),flush=True)
'''
PROVISION_CODE = "import base64,zlib;exec(zlib.decompress(base64.b64decode(" + repr(base64.b64encode(zlib.compress(BOOTSTRAP.encode())).decode()) + ")))"
PROVISION_COMMAND = GuestCommand(("/usr/bin/python3", "-I", "-B", "-c", PROVISION_CODE))


class JobError(RuntimeError):
    pass


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def input_digest(source: bytes, context_files: tuple[tuple[str, bytes], ...] = ()) -> str:
    return _sha(source) if not context_files else canonical_digest({"source": _sha(source),
        "contextFiles": {name: _sha(raw) for name, raw in context_files}})


@dataclasses.dataclass(frozen=True)
class GuestPrograms:
    programs: tuple[tuple[str, bytes], ...]

    def __post_init__(self):
        if type(self.programs) is not tuple or len(self.programs) != len(PROGRAM_NAMES) or {name for name, _raw in self.programs} != PROGRAM_NAMES:
            raise JobError("exact installed guest program set required")
        if any(type(raw) is not bytes or not 0 < len(raw) <= 128 * 1024 for _name, raw in self.programs) or sum(len(raw) for _name, raw in self.programs) > 512 * 1024:
            raise JobError("guest program bytes exceed their bound")

    @classmethod
    def from_directory(cls, root: Path):
        """Read installed root-protected bytes; no project-controlled loader."""
        values = []
        for name in sorted(PROGRAM_NAMES):
            raw, _digest = _read_protected(Path(root) / name, maximum=128 * 1024, capture=True, executable=False)
            values.append((name, raw))
        return cls(tuple(values))


@dataclasses.dataclass(frozen=True)
class BoundJob:
    repository: Path
    workspace: Path
    scope: LaunchScope
    base_commit: str
    target_ref: str
    agent_command: GuestCommand
    prompt: bytes
    outbox_transport: str | None
    allowed_artifacts: tuple[tuple[str, tuple[str | None, ...]], ...]
    assignment_digest: str
    source_package: bytes | None = None
    collect_changes: bool = True
    context_files: tuple[tuple[str, bytes], ...] = ()
    verify_unchanged: bool = False

    def __post_init__(self):
        for name in ("repository", "workspace"):
            path = Path(getattr(self, name))
            if not path.is_absolute() or str(path) != os.path.abspath(path):
                raise JobError("job paths require canonical host bindings")
            object.__setattr__(self, name, path)
        self.workspace.relative_to(self.repository)
        if type(self.scope) is not LaunchScope or type(self.agent_command) is not GuestCommand or self.scope.project_id != _sha(str(self.repository).encode()):
            raise JobError("job scope differs from its canonical project")
        oid(self.base_commit)
        branch_ref(self.target_ref)
        if type(self.prompt) is not bytes or len(self.prompt) > 65536:
            raise JobError("prompt exceeds its guest byte bound")
        self.prompt.decode("utf-8", errors="strict")
        if type(self.assignment_digest) is not str or not self.assignment_digest.startswith("sha256:") or len(self.assignment_digest) != 71 or any(c not in "0123456789abcdef" for c in self.assignment_digest[7:]):
            raise JobError("job assignment requires an approved content digest")
        if self.source_package is not None and (type(self.source_package) is not bytes or len(self.source_package) > MAX_PACKAGE_BYTES):
            raise JobError("candidate source exceeds its bound")
        if type(self.collect_changes) is not bool or type(self.verify_unchanged) is not bool:
            raise JobError("output collection policy must be host assigned")
        if self.collect_changes and self.verify_unchanged:
            raise JobError("read-only verification cannot import changes")
        if type(self.context_files) is not tuple or len(self.context_files) > len(CONTEXT_LIMITS) or len({name for name, _raw in self.context_files}) != len(self.context_files) or any(name not in CONTEXT_LIMITS or type(raw) is not bytes or len(raw) > CONTEXT_LIMITS[name] for name, raw in self.context_files) or sum(len(raw) for _name, raw in self.context_files) > 3 * 1024 * 1024:
            raise JobError("approved context files exceed their closed names/byte limits")
        # Gate VM scopes remain broad, but checkpoint publication always has a
        # concrete task assignment. A gate job supplies that in a task scope.
        if self.outbox_transport is None and (self.allowed_artifacts or self.collect_changes):
            raise JobError("no-publication jobs cannot import or publish artifacts")
        if self.scope.task_id == "-" and (self.allowed_artifacts or self.collect_changes or self.outbox_transport is not None):
            raise JobError("gate-wide jobs cannot import or publish artifacts")


@dataclasses.dataclass(frozen=True)
class JobResult:
    status: str
    exit_code: int
    binding: dict[str, Any]
    quarantine_receipt: dict[str, Any] | None
    assignment_digest: str
    diagnostic_digest: str
    verification_digest: str | None = None


class StreamProvisioner:
    """Concrete input transfer over an explicitly permitted provision session."""
    def validate_backend(self, backend, profile):
        return callable(getattr(backend, "open_session", None))

    def provision(self, *args, **kwargs):
        raise JobError("use the job runner's bounded provision transfer")


def _communicate(session, payload: bytes, *, maximum: int, deadline: float, on_diagnostic: Callable[[bytes], None] | None = None) -> tuple[int, bytes, bytes]:
    """Drain both pipes while writing bounded stdin; cancellation owns cleanup."""
    if len(payload) > MAX_PROVISION_BYTES or not 0 <= maximum <= MAX_EXPORT_BYTES:
        raise JobError("native transfer exceeds its bound")
    output, errors, offset = bytearray(), bytearray(), 0
    read = {session.stdout.fileno(): (session.stdout, output), session.stderr.fileno(): (session.stderr, errors)}
    write = session.stdin.fileno()
    for descriptor in (*read, write):
        os.set_blocking(descriptor, False)
    try:
        if not payload:
            session.stdin.close()
            write = None
        while read or write is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise JobError("native transfer deadline exceeded")
            ready_read, ready_write, _ = select.select(list(read), [] if write is None else [write], [], remaining)
            for descriptor in ready_read:
                try:
                    block = read[descriptor][0].read(65536)
                except BlockingIOError:
                    continue
                if not block:
                    del read[descriptor]
                else:
                    target = read[descriptor][1]
                    if len(target) + len(block) > (maximum if target is output else MAX_DIAGNOSTIC_BYTES):
                        raise JobError("native transfer output exceeded its bound")
                    if target is errors and on_diagnostic is not None:
                        on_diagnostic(block)
                    target.extend(block)
            if write in ready_write:
                try:
                    count = session.stdin.write(payload[offset:offset + 65536])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise JobError("native transfer input closed")
                offset += count
                if offset == len(payload):
                    session.stdin.close()
                    write = None
        code = session.finish(timeout=min(1.0, max(0.001, deadline - time.monotonic())))
        return code, bytes(output), bytes(errors)
    except BaseException:
        session.cancel()
        raise


def decode_export(raw: bytes, *, base_commit: str, base_tree: str, limits: ArtifactLimits) -> tuple[dict, dict[str, bytes]]:
    if len(raw) < 4 or struct.unpack("!I", raw[:4])[0] != len(raw) - 4 or len(raw) - 4 > MAX_EXPORT_BYTES:
        raise JobError("guest export frame is invalid")
    packet = _json(raw[4:], MAX_EXPORT_BYTES)
    if set(packet) != {"schemaVersion", "operation", "manifest", "blobs"} or type(packet["schemaVersion"]) is not int or packet["schemaVersion"] != 1 or packet["operation"] != "workspace.export" or type(packet["blobs"]) is not dict:
        raise JobError("guest export schema is invalid")
    manifest = packet["manifest"]
    if type(manifest) is not dict or manifest.get("baseCommit") != base_commit:
        raise JobError("guest export base differs from its assignment")
    if manifest.get("changes") == []:
        if set(manifest) != {"schemaVersion", "id", "baseCommit", "resultingTree", "changes"} or type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 1 or manifest["resultingTree"] != base_tree or packet["blobs"]:
            raise JobError("empty guest export does not match its approved tree")
        return manifest, {}
    manifest = parse_manifest(manifest, limits)
    required = {change["sha256"] for change in manifest["changes"] if change["operation"] != "delete"}
    if set(packet["blobs"]) != required:
        raise JobError("guest export has missing or unrelated content")
    blobs, total = {}, 0
    for digest, value in packet["blobs"].items():
        if type(value) is not str or len(value) > limits.max_file_bytes * 2 or len(value) % 2 or any(c not in "0123456789abcdef" for c in value):
            raise JobError("guest content encoding is invalid")
        body = bytes.fromhex(value)
        total += len(body)
        if total > limits.max_total_bytes or _sha(body) != digest:
            raise JobError("guest content differs from its manifest")
        blobs[digest] = body
    return manifest, blobs


class SandboxJobRunner:
    def __init__(self, controller, git: HostGit, programs: GuestPrograms, *, contains_secret: Callable[[str], bool], publish: Callable[[bytes], bytes] | None, on_bound: Callable[[dict, dict | None], None], on_state: Callable[[dict], None], quarantine_root: Path, artifact_store_factory: Callable[..., ArtifactStore] | None = None, context_read: Callable[[], dict] | None = None, progress_report: Callable[[str, str], None] | None = None, watchdog_verify: Callable | None = None, on_diagnostic: Callable[[bytes], None] | None = None, credentials=None, model_required: bool = True, network_policy=None):
        if type(programs) is not GuestPrograms or not all(callable(value) for value in (contains_secret, on_bound, on_state)) or (publish is not None and not callable(publish)) or not isinstance(controller.provisioner, StreamProvisioner):
            raise JobError("job runner requires concrete host authority and transfer bindings")
        self.controller, self.git, self.programs = controller, git, programs
        self.contains_secret, self.publish = contains_secret, publish
        self.on_bound, self.on_state = on_bound, on_state
        self.quarantine_root = Path(quarantine_root)
        self.artifact_store_factory = artifact_store_factory or ArtifactStore
        self.context_read, self.progress_report = context_read, progress_report
        self.watchdog_verify = watchdog_verify or verify_watchdog_lease
        if on_diagnostic is not None and not callable(on_diagnostic):
            raise JobError("diagnostic handler must be trusted native code")
        self.on_diagnostic = on_diagnostic
        self._diagnostic_bytes = 0
        self.credentials = credentials
        if type(model_required) is not bool:
            raise JobError("model requirement must come from the approved native job kind")
        self.model_required = model_required
        self.network_policy = network_policy

    def _diagnostic(self, raw: bytes):
        self._diagnostic_bytes += len(raw)
        if self._diagnostic_bytes > MAX_DIAGNOSTIC_BYTES:
            raise JobError("whole-job diagnostic budget exhausted")
        if self.on_diagnostic is not None:
            self.on_diagnostic(raw)  # callback MUST enforce its IPC deadline

    def _local_request(self, request, handle):
        if type(request) is not dict or type(request.get("schemaVersion")) is not int or request["schemaVersion"] != 1 or type(request.get("operation")) is not str or request["operation"] not in {"context.read", "progress.report"} or type(request.get("id")) is not str or not 16 <= len(request["id"]) <= 128 or any(char not in "0123456789abcdef" for char in request["id"]):
            raise JobError("guest local request is invalid")
        watchdog = self.controller.watchdog.binding(handle)
        if self.watchdog_verify(Path(watchdog["deploymentPath"]), name=handle.name,
            generation=handle.generation, epoch=handle.epoch, lease_id=watchdog["leaseId"], deadline=watchdog["deadline"]) is not True:
            raise JobError("guest local request is no longer authorized")
        response = {"schemaVersion": 1, "id": request["id"], "operation": request["operation"]}
        if request["operation"] == "context.read":
            if set(request) != {"schemaVersion", "id", "operation"} or not callable(self.context_read):
                raise JobError("guest context read denied")
            context = self.context_read()
            if type(context) is not dict:
                raise JobError("approved context is invalid")
            response.update(status="ok", context=context)
        elif request["operation"] == "progress.report":
            if set(request) != {"schemaVersion", "id", "operation", "stage", "message"} or type(request["stage"]) is not str or request["stage"] not in {"starting", "working", "waiting", "validating", "completed", "failed"} or type(request["message"]) is not str or len(request["message"].encode("utf-8")) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in request["message"]) or not callable(self.progress_report):
                raise JobError("guest progress report denied")
            if self.contains_secret(request["message"]) is not False:
                raise JobError("guest progress contains a credential")
            self.progress_report(request["stage"], request["message"])
            response["status"] = "recorded"
        else:
            raise JobError("unsupported guest local operation")
        raw = json.dumps(response, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > 16 * 1024 or self.contains_secret(raw.decode("utf-8")) is not False:
            raise JobError("approved local response exceeds its policy")
        return struct.pack("!I", len(raw)) + raw

    def _source(self, job):
        source = job.source_package
        if source is None:
            source = build_source_package(job.base_commit, self.git.read_object, contains_secret=self.contains_secret)
        base, tree, objects, _files = parse_source_package(source)
        if base != job.base_commit:
            raise JobError("approved source base differs from the job")
        # Repeat the complete scanner, including UTF-16/32 views, for candidate
        # packages. A quarantine receipt cannot disable credential filtering.
        build_source_package(base, lambda kind, identifier: objects[identifier][1], contains_secret=self.contains_secret)
        if self.contains_secret(job.prompt.decode("utf-8")) is not False:
            raise JobError("prompt denied by credential scanner")
        for _name, raw in job.context_files:
            if self.contains_secret(raw.decode("utf-8", errors="strict")) is not False:
                raise JobError("approved context denied by credential scanner")
        return source, tree

    def _relay(self, session, *, deadline, job, handle):
        errors, requests, total = bytearray(), 0, 0
        stdout, stderr, stdin = session.stdout.fileno(), session.stderr.fileno(), session.stdin.fileno()
        for descriptor in (stdout, stderr, stdin):
            os.set_blocking(descriptor, False)
        logs_open = True
        def exact(size, *, clean=False, read_deadline=None):
            nonlocal logs_open
            value = bytearray()
            while len(value) < size:
                remaining = min(deadline, read_deadline or deadline) - time.monotonic()
                if remaining <= 0:
                    raise JobError("guest job deadline exceeded")
                ready, _, _ = select.select([stdout] + ([stderr] if logs_open else []), [], [], remaining)
                if stderr in ready:
                    block = session.stderr.read(8192)
                    if not block:
                        logs_open = False
                    elif len(errors) + len(block) > MAX_DIAGNOSTIC_BYTES:
                        raise JobError("guest diagnostic limit exceeded")
                    else:
                        self._diagnostic(block)
                        errors.extend(block)
                if stdout in ready:
                    block = session.stdout.read(size - len(value))
                    if not block:
                        if clean and not value:
                            return None
                        raise JobError("guest channel truncated")
                    value.extend(block)
            return bytes(value)
        try:
            while True:
                first = exact(1, clean=True)
                if first is None:
                    break
                frame_deadline = min(deadline, time.monotonic() + 10)
                header = first + exact(3, read_deadline=frame_deadline)
                size = struct.unpack("!I", header)[0]
                if not 0 < size <= 192 * 1024:
                    raise JobError("guest frame exceeded its bound")
                raw = exact(size, read_deadline=frame_deadline)
                request = _json(raw, 192 * 1024)
                requests += 1
                total += len(raw)
                if requests > 64 or total > 4 * 1024 * 1024:
                    raise JobError("guest checkpoint budget exhausted")
                if request.get("operation") == "artifact.submit":
                    request, _body = parse_request(raw)
                    if job.outbox_transport is None or not callable(self.publish):
                        raise JobError("this job cannot publish artifacts")
                    receipt_raw = self.publish(raw)  # callback MUST enforce its IPC deadline
                    receipt = _json(receipt_raw, 16 * 1024)
                    if receipt.get("id") != request["id"]:
                        raise JobError("checkpoint receipt does not match the request")
                    framed = response_frame(receipt)
                else:
                    framed = self._local_request(request, handle)
                offset = 0
                response_deadline = min(deadline, time.monotonic() + 10)
                while offset < len(framed):
                    remaining = response_deadline - time.monotonic()
                    if remaining <= 0 or not select.select([], [stdin], [], remaining)[1]:
                        raise JobError("checkpoint response deadline exceeded")
                    count = session.stdin.write(framed[offset:])
                    if count <= 0:
                        raise JobError("checkpoint response input closed")
                    offset += count
            # Drain trailing diagnostics and acknowledge the native command.
            if logs_open:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([stderr], [], [], remaining)[0]:
                        raise JobError("guest diagnostic drain timed out")
                    block = session.stderr.read(8192)
                    if not block:
                        break
                    if len(errors) + len(block) > MAX_DIAGNOSTIC_BYTES:
                        raise JobError("guest diagnostic limit exceeded")
                    self._diagnostic(block)
                    errors.extend(block)
            session.stdin.close()
            return session.finish(timeout=min(1.0, max(0.001, deadline - time.monotonic()))), bytes(errors)
        except BaseException:
            session.cancel()
            raise

    def run(self, job: BoundJob) -> JobResult:
        if type(job) is not BoundJob or job.repository != self.git.repository:
            raise JobError("job does not match its protected host repository")
        controller = self.controller
        self._diagnostic_bytes = 0
        if controller.epoch is None:
            controller.start()
        profile = controller.profile
        if self.credentials is not None:
            self.credentials.assert_ready()
        source, base_tree = self._source(job)
        source_digest = input_digest(source, job.context_files)
        header = {"schemaVersion": 1, "programs": {name: raw.hex() for name, raw in self.programs.programs},
                  "sourceBytes": len(source), "sourceDigest": _sha(source), "promptHex": job.prompt.hex(),
                  "contexts": {name: {"size": len(raw), "sha256": _sha(raw)} for name, raw in job.context_files},
                  "inputDigest": source_digest}
        encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        payload = struct.pack("!I", len(encoded)) + encoded + source + b"".join(raw for _name, raw in sorted(job.context_files))
        if len(encoded) > 1024 * 1024 or len(payload) > MAX_PROVISION_BYTES:
            raise JobError("provisioning payload exceeds its bound")
        bridge = GuestCommand(("/usr/bin/python3", "-I", "-B", GUEST_BIN + "/sandbox_guest_bridge.py", "--guest-only",
            "--socket", GUEST_SOCKET, "--wall-seconds", str(profile.limits.wall_seconds), "--agent-uid", str(AGENT_UID), "--", *job.agent_command.argv))
        handle = controller.allocate(LaunchSpec(job.scope, profile.digest, bridge))
        binding, diagnostics, receipt, credential_lease, verification_digest = None, b"", None, None, None
        deadline = time.monotonic() + profile.limits.wall_seconds
        effective_assignment = canonical_digest({"approvedJob": job.assignment_digest, "generation": handle.as_dict(), "inputDigest": source_digest})
        try:
            if self.network_policy is not None:
                controller.configure_network(handle, self.network_policy)
            if self.credentials is not None:
                with controller.registry.locked() as transaction:
                    credential_record = next(record for record in transaction.records() if record["name"] == handle.name)
                credential_identity = controller._identity(credential_record)
                # The prepared durable lease exists before the first native
                # set operation. A partial installation cannot lose cleanup.
                credential_lease = self.credentials.prepare(profile, handle, credential_identity, job.scope, require_model=self.model_required)
                controller.install_credentials(handle, self.credentials, credential_lease)
            session = controller.open_provision_session(handle, PROVISION_COMMAND)
            code, output, diagnostics = _communicate(session, payload, maximum=65536, deadline=deadline, on_diagnostic=self._diagnostic)
            acknowledgment = _json(output, 65536)
            if code != 0 or acknowledgment.get("schemaVersion") != 1 or acknowledgment.get("baseCommit") != job.base_commit or acknowledgment.get("tree") != base_tree or acknowledgment.get("inputDigest") != source_digest:
                raise JobError("guest provisioning did not acknowledge the approved bytes")
            manifest = ArtifactReference(_sha(payload))
            with controller.registry.locked() as transaction:
                record = next(record for record in transaction.records() if record["name"] == handle.name)
            identity = controller._identity(record)
            proof = AuthorityProof(provisioning_request_digest(profile, handle, identity, job.scope, manifest), source_digest)
            controller.complete_provision(handle, manifest, proof)
            binding = {"schemaVersion": 1, "backend": profile.backend, "namespace": profile.namespace,
                "name": handle.name, "sandboxId": identity.sandbox_id, "createdAt": identity.created_at,
                "generation": handle.generation, "epoch": handle.epoch, "profileDigest": profile.digest,
                "policyDigest": profile.policy_digest, "image": profile.image, "inputDigest": source_digest,
                "baseCommit": job.base_commit, "state": "ready", "acceptedCommit": None,
                "acceptedTree": None, "acceptedExportDigest": None}
            context = None
            if job.outbox_transport is not None:
                bound = BoundContext(job.repository, job.workspace, job.scope.team, job.scope.feature_id,
                    job.scope.role, job.scope.task_id, job.scope.attempt, handle.generation, job.outbox_transport)
                context = RelayContext.from_dict({"schemaVersion": 1, "registryRoot": str(controller.registry.root),
                "registryId": controller.enrollment.registry_id, "namespace": profile.namespace,
                "name": handle.name, "generation": handle.generation, "epoch": handle.epoch,
                "sandboxId": identity.sandbox_id, "createdAt": identity.created_at,
                "scope": job.scope.as_dict(), "boundContext": bound.as_dict(),
                "allowedArtifacts": {name: list(statuses) for name, statuses in job.allowed_artifacts},
                "watchdog": controller.watchdog.binding(handle),
                    "limits": RelayLimits(wall_seconds=profile.limits.wall_seconds).as_dict()})
            self.on_bound(dict(binding), context.as_dict() if context is not None else None)
            controller.activate(handle)
            binding["state"] = "running"
            self.on_state(dict(binding))
            code, logs = self._relay(controller.open_session(handle), deadline=deadline, job=job, handle=handle)
            diagnostics += logs
            controller.begin_collection(handle)
            binding["state"] = "collecting"
            self.on_state(dict(binding))
            if job.collect_changes or job.verify_unchanged:
                export_id = hashlib.sha256((effective_assignment + ":final").encode()).hexdigest()
                command = GuestCommand(("/usr/bin/python3", "-I", "-B", GUEST_BIN + "/sandbox_export.py", "--guest-only", "--quiesce-agent", str(AGENT_UID), "--export-id", export_id))
                collect = controller.open_collection_session(handle, command)
                export_code, output, errors = _communicate(collect, b"", maximum=MAX_EXPORT_BYTES, deadline=deadline, on_diagnostic=self._diagnostic)
                diagnostics += errors
                if export_code != 0:
                    raise JobError("guest output collection failed")
                manifest, blobs = decode_export(output, base_commit=job.base_commit, base_tree=base_tree, limits=ArtifactLimits())
                if manifest["id"] != export_id:
                    raise JobError("guest export identity differs from its assignment")
                if job.verify_unchanged and any(change["operation"] != "add" for change in manifest["changes"]):
                    raise JobError("read-only job changed its approved tracked source")
                with self.artifact_store_factory(self.git, self.quarantine_root, assignment_digest=effective_assignment,
                        target_ref=job.target_ref, expected_base=job.base_commit) as store:
                    collected = store.collect(manifest, blobs)
                    if job.collect_changes:
                        receipt = collected
                    if job.verify_unchanged:
                        verification_digest = canonical_digest({"baselineInputDigest": source_digest,
                            "exportManifestDigest": collected["manifestDigest"],
                            "generation": handle.as_dict(), "trackedUnchanged": True})
            binding["state"] = "work-complete" if code == 0 else "failed"
            self.on_state(dict(binding))
            return JobResult("collected" if code == 0 else "failed", code, dict(binding), receipt,
                             effective_assignment, _sha(diagnostics), verification_digest)
        finally:
            # Every path fences publication before exact-generation cleanup.
            # A cleanup failure propagates: a job must not claim safe success.
            try:
                try:
                    if binding is not None:
                        binding["state"] = "fenced"
                        self.on_state(dict(binding))
                finally:
                    if credential_lease is not None:
                        controller.remove_credentials(handle, self.credentials, credential_lease)
            finally:
                controller.cancel(handle)
            if binding is not None:
                binding["state"] = "removed"
                self.on_state(dict(binding))


class SandboxWorkflow:
    """Host structural task-ref import, then fresh independent checks.

    Acceptance is a source-data import. Existing broker evidence and feature
    integration gates remain authoritative after it; this class mints no code
    approval from model text and never updates a feature integration ref.
    """
    def __init__(self, runner_factory: Callable[[BoundJob], SandboxJobRunner], *,
                 promotion_store: Callable[[BoundJob, JobResult], ArtifactStore],
                 record_acceptance: Callable[[dict, dict, dict], None]):
        if not all(callable(value) for value in (runner_factory, promotion_store, record_acceptance)):
            raise JobError("workflow requires native import and acceptance authorities")
        self.runner_factory = runner_factory
        self.promotion_store = promotion_store
        self.record_acceptance = record_acceptance

    def run(self, task_job: BoundJob, *, review_job_factory: Callable[[bytes, dict], BoundJob],
            validation_job_factories: tuple[Callable[[bytes, dict], BoundJob], ...]) -> dict:
        if not callable(review_job_factory) or type(validation_job_factories) is not tuple or not validation_job_factories or not all(callable(factory) for factory in validation_job_factories):
            raise JobError("fresh review and at least one approved validation are required")
        task_runner = self.runner_factory(task_job)
        result = task_runner.run(task_job)
        if result.exit_code != 0 or result.quarantine_receipt is None:
            raise JobError("task did not produce a complete quarantined candidate")
        with self.promotion_store(task_job, result) as store:
            # The store's external authorizer repeats current assignment/hold
            # checks under its task lock before and immediately before ref CAS.
            # Scan the entire candidate before publishing even raw objects to
            # the assigned task ref. A source-import receipt is not a scanner.
            candidate = store.candidate_source(result.quarantine_receipt["exportId"], contains_secret=task_runner.contains_secret)
            receipt = store.promote(result.quarantine_receipt["exportId"])
        binding = dict(result.binding)
        binding.update(state="accepted", acceptedCommit=receipt["commit"],
                       acceptedTree=receipt["tree"], acceptedExportDigest=receipt["manifestDigest"])
        self.record_acceptance(dict(binding), dict(receipt), {"assignmentDigest": result.assignment_digest,
            "inputDigest": binding["inputDigest"], "kind": "structural-source-import"})
        checks = []
        jobs = [review_job_factory(candidate, dict(binding))]
        jobs.extend(factory(candidate, dict(binding)) for factory in validation_job_factories)
        generations = {binding["generation"]}
        for index, job in enumerate(jobs):
            same_project = type(job) is BoundJob and (job.scope.project_id, job.scope.team, job.scope.feature_id) == (task_job.scope.project_id, task_job.scope.team, task_job.scope.feature_id)
            same_task = same_project and ((job.scope.task_id, job.scope.attempt) == (task_job.scope.task_id, task_job.scope.attempt) or index > 0 and job.scope.task_id == "-" and job.outbox_transport is None)
            if not same_task or job.source_package != candidate or job.base_commit != receipt["commit"] or job.collect_changes is not False or job.scope.role == task_job.scope.role:
                raise JobError("independent check differs from the accepted candidate assignment")
            check = self.runner_factory(job).run(job)
            if check.binding["generation"] in generations or check.binding["image"] != binding["image"] or check.binding["inputDigest"] != input_digest(candidate, job.context_files):
                raise JobError("independent check reused a VM or changed its approved image/input")
            generations.add(check.binding["generation"])
            checks.append({"kind": "review" if index == 0 else "validation",
                "exitCode": check.exit_code, "binding": dict(check.binding),
                "diagnosticDigest": check.diagnostic_digest})
            if check.exit_code != 0:
                raise JobError("independent check failed; feature integration remains blocked")
        return {"schemaVersion": 1, "kind": "sandbox-workflow", "binding": binding,
                "promotionReceipt": receipt, "checks": checks,
                "codeApproved": False, "featureIntegrated": False}
