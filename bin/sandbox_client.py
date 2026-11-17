"""Native launcher client; publication relay remains its real OS descendant."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli.execution_backend import GuestCommand, LaunchScope, load_profile
from startup_factory_cli.sandbox_deployment import canonical_bytes, load_deployment, private_directory, verify_deployment
from startup_factory_cli.sandbox_watchdog import _peer_uid
from execution_descriptor import execution_version, validate_sandbox_binding
from host_git import HostGit, open_directory
from sandbox_service import (HEARTBEAT_SECONDS, JOB_ID, RPC_SECONDS, JobRequest, ServiceError,
                             private_read, private_write, receive, send, sha)
from sandbox_acceptance import project_id, task_key
from sandbox_transport import RelayContext


def prepare_request(deployment, *, repository: Path, workspace: Path, scope: LaunchScope,
                    kind: str, base_commit: str, target_ref: str, guest_command: GuestCommand,
                    prompt: bytes, capability_id: str | None = None, transport: str | None = None) -> Path:
    profile = load_profile(Path(deployment.profile_path))
    verify_deployment(deployment, profile)
    if kind == "task":
        directory = open_directory(workspace / "executions")
        try:
            raw = private_read(directory, task_key(scope.task_id) + ".json", 1024 * 1024)
        finally:
            os.close(directory)
        record = json.loads(raw)
        if execution_version(record) != 1:
            raise ServiceError("this task attempt already has a sandbox binding; use a new authorized attempt")
        execution_digest = sha(canonical_bytes(record))
    else:
        execution_digest = None
    value = {"schemaVersion": 1, "id": "job-" + uuid.uuid4().hex,
        "deploymentDigest": deployment.digest, "profileDigest": profile.digest, "kind": kind,
        "repository": str(repository), "workspace": str(workspace), "scope": scope.as_dict(),
        "baseCommit": base_commit, "targetRef": target_ref, "guestCommand": guest_command.as_dict(),
        "promptHex": prompt.hex(), "capabilityId": capability_id, "transport": transport,
        "executionSha256": execution_digest}
    raw = canonical_bytes(value)
    JobRequest.parse(raw, deployment, profile)
    directory = open_directory(Path(deployment.job_root), private=True)
    try:
        if len(os.listdir(directory)) >= 3 * 1024:
            raise ServiceError("permanent job history quota exhausted")
        private_write(directory, value["id"] + ".request.json", raw, immutable=True)
    finally:
        os.close(directory)
    return Path(deployment.job_root) / (value["id"] + ".request.json")


def _relay(deployment, context_path: Path, raw: bytes) -> bytes:
    """One bounded trusted child; no guest byte is an argv or host path."""
    argv = [deployment.programs["python"]["path"], "-I", "-B",
            str(Path(deployment.bundle_root) / "bin/sandbox-relay.py"), "--context", str(context_path)]
    payload = struct.pack("!I", len(raw)) + raw
    if len(raw) > 192 * 1024:
        raise ServiceError("artifact request exceeds its frame limit")
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True, close_fds=True,
        env={"PATH": "/usr/bin:/bin", "HOME": deployment.account_home, "LANG": "C", "LC_ALL": "C"})
    output, errors, offset = bytearray(), bytearray(), 0
    streams = {process.stdout.fileno(): (process.stdout, output), process.stderr.fileno(): (process.stderr, errors)}
    writer = process.stdin.fileno()
    for fd in (*streams, writer):
        os.set_blocking(fd, False)
    deadline = time.monotonic() + RPC_SECONDS - 1
    try:
        while streams or writer is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ServiceError("native artifact relay deadline exceeded")
            readable, writable, _ = select.select(list(streams), [] if writer is None else [writer], [], remaining)
            for fd in readable:
                try:
                    block = os.read(fd, 8192)
                except BlockingIOError:
                    continue
                if not block:
                    del streams[fd]
                else:
                    destination = streams[fd][1]
                    if len(destination) + len(block) > 16 * 1024 + 4:
                        raise ServiceError("native artifact relay output budget exhausted")
                    destination.extend(block)
            if writer in writable:
                try:
                    count = os.write(writer, payload[offset:offset + 8192])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise ServiceError("native artifact relay input closed")
                offset += count
                if offset == len(payload):
                    process.stdin.close(); writer = None
        code = process.wait(timeout=max(.01, deadline - time.monotonic()))
        if code != 0 or len(output) < 4 or struct.unpack("!I", output[:4])[0] != len(output) - 4:
            raise ServiceError("native artifact relay refused publication")
        return bytes(output[4:])
    finally:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def run_client(deployment, request_path: Path, *, diagnostic=None) -> dict:
    profile = load_profile(Path(deployment.profile_path))
    verify_deployment(deployment, profile)
    name = request_path.name
    if request_path.parent != Path(deployment.job_root) or not name.endswith(".request.json") or not JOB_ID.fullmatch(name[:-13]):
        raise ServiceError("launch client accepts only a protected prepared job name")
    directory = open_directory(Path(deployment.job_root), private=True)
    try:
        raw = private_read(directory, name, deployment.job_request_max_bytes)
    finally:
        os.close(directory)
    request = JobRequest.parse(raw, deployment, profile)
    private_directory(Path(deployment.socket_path).parent, deployment.controller_uid)
    socket_info = Path(deployment.socket_path).lstat()
    if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != deployment.controller_uid or stat.S_IMODE(socket_info.st_mode) != 0o600:
        raise ServiceError("unsafe custody service socket")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(RPC_SECONDS)
    connection.connect(deployment.socket_path)
    if _peer_uid(connection) != deployment.controller_uid:
        connection.close()
        raise ServiceError("custody service belongs to another account")
    lock = threading.Lock(); done = threading.Event(); context_path = None
    def emit(value):
        with lock:
            send(connection, value)
    def heartbeat():
        while not done.wait(HEARTBEAT_SECONDS):
            try:
                emit({"schemaVersion": 1, "operation": "heartbeat"})
            except Exception:
                with contextlib.suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)
                return
    thread = threading.Thread(target=heartbeat, daemon=True)
    count = total_diagnostics = 0
    last_sequence = 0
    bound_seen = False
    try:
        emit({"schemaVersion": 1, "operation": "job.run", "jobId": request.id, "requestDigest": request.digest})
        thread.start()
        deadline = time.monotonic() + 2 * profile.limits.wall_seconds + 30
        while True:
            if time.monotonic() >= deadline:
                raise ServiceError("native job client wall limit exceeded")
            message = receive(connection)
            count += 1
            if count > 4096 or type(message.get("schemaVersion")) is not int or message["schemaVersion"] != 1:
                raise ServiceError("invalid custody response budget/schema")
            operation = message.get("operation")
            if operation == "heartbeat" and set(message) == {"schemaVersion", "operation"}:
                continue
            if operation == "accepted" and set(message) == {"schemaVersion", "operation", "jobId"} and message["jobId"] == request.id:
                continue
            if operation == "bound" and set(message) == {"schemaVersion", "operation", "sequence", "binding", "relayContext"}:
                if bound_seen or type(message["sequence"]) is not int or message["sequence"] != last_sequence + 1:
                    raise ServiceError("duplicate or out-of-order sandbox binding")
                bound_seen = True
                last_sequence = message["sequence"]
                binding = validate_sandbox_binding(message["binding"])
                if binding["profileDigest"] != profile.digest or binding["policyDigest"] != profile.policy_digest or binding["image"] != profile.image or binding["baseCommit"] != request.value["baseCommit"]:
                    raise ServiceError("guest binding differs from its approved launch")
                if message["relayContext"] is None:
                    if request.value["capabilityId"] is not None:
                        raise ServiceError("publishing job has no native relay context")
                else:
                    context = RelayContext.from_dict(message["relayContext"])
                    if (context.registry_root != Path(deployment.registry_root) or context.scope != request.scope
                        or context.namespace != profile.namespace or context.bound.transport != request.value["transport"]
                        or context.watchdog[0] != str(deployment.source_path)
                        or context.bound.repository != Path(request.value["repository"])
                        or context.bound.workspace != Path(request.value["workspace"])
                        or (context.name, context.generation, context.epoch, context.sandbox_id, context.created_at)
                           != tuple(binding[key] for key in ("name", "generation", "epoch", "sandboxId", "createdAt"))):
                        raise ServiceError("native relay context differs from the approved job")
                    parent = open_directory(Path(deployment.registry_root), private=True)
                    try:
                        leaf = "relay-" + binding["generation"] + ".json"
                        private_write(parent, leaf, canonical_bytes(context.as_dict()), immutable=True)
                    finally:
                        os.close(parent)
                    context_path = Path(deployment.registry_root) / leaf
                emit({"schemaVersion": 1, "operation": "bound.result", "sequence": message["sequence"], "bodyHex": b"ack".hex()})
                continue
            if operation == "publish" and set(message) == {"schemaVersion", "operation", "sequence", "requestHex"}:
                if not bound_seen or type(message["sequence"]) is not int or message["sequence"] != last_sequence + 1:
                    raise ServiceError("out-of-order sandbox publication")
                last_sequence = message["sequence"]
                if context_path is None or not isinstance(message["requestHex"], str) or len(message["requestHex"]) > 384 * 1024:
                    raise ServiceError("job has no scoped native publication channel")
                result = _relay(deployment, context_path, bytes.fromhex(message["requestHex"]))
                emit({"schemaVersion": 1, "operation": "publish.result", "sequence": message["sequence"], "bodyHex": result.hex()})
                continue
            if operation == "diagnostic" and set(message) == {"schemaVersion", "operation", "dataHex"}:
                if not isinstance(message["dataHex"], str) or len(message["dataHex"]) > 16384:
                    raise ServiceError("invalid guest diagnostic bytes")
                data = bytes.fromhex(message["dataHex"])
                total_diagnostics += len(data)
                if total_diagnostics > 1024 * 1024:
                    raise ServiceError("guest diagnostic budget exhausted")
                if diagnostic is not None:
                    diagnostic(data)
                else:
                    os.write(2, data)
                continue
            if operation == "progress" and set(message) == {"schemaVersion", "operation", "stage", "message"}:
                continue  # Presentation only, never execution/import authority.
            if operation == "complete" and set(message) == {"schemaVersion", "operation", "result"}:
                result = message["result"]
                if type(result) is not dict or result.get("jobId") != request.id or type(result.get("exitCode")) is not int or not 0 <= result["exitCode"] <= 255:
                    raise ServiceError("invalid protected job completion")
                return result
            if operation == "error" and set(message) == {"schemaVersion", "operation", "message"}:
                raise ServiceError("sandbox job refused or uncertain; inspect protected controller state")
            raise ServiceError("unsupported custody response")
    except (EOFError, OSError, ValueError) as exc:
        raise ServiceError("sandbox job connection closed or protocol invalid") from exc
    finally:
        done.set()
        connection.close()
        if thread.is_alive():
            thread.join(timeout=1)
