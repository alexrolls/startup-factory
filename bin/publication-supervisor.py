#!/usr/bin/env python3
"""Secret-free worker publication transport.

The launcher runs this process outside the agent sandbox.  It owns the broker
capability record and gives the worker only a Unix-socket locator.  Every
request is authenticated as a live bounded descendant of the exact launched
child generation and is signed only while the exact capability id remains the
active pointer.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import subprocess
import sys
import time
from typing import Any


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from outbox_capability import (  # noqa: E402
    MAX_TRANSPORT_REQUEST_BYTES,
    CapabilityError,
    active_record,
    revoke_exact,
    sign_active_entry,
)


FRAME_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 16 * 1024
POLL_SECONDS = 0.05
DARWIN_SOL_LOCAL = 0
DARWIN_LOCAL_PEERTOKEN = 0x006
LINUX_SO_PEERCRED = 17
LINUX_SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)


class SupervisorError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start: str


class ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def transport_locator(
    repository: str, capability_id: str, lifecycle_root: str
) -> str:
    material = (os.path.realpath(repository) + "\0" + capability_id).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:32]
    root = Path(lifecycle_root)
    if not root.is_absolute() or Path(os.path.abspath(root)) != root:
        raise SupervisorError("protected lifecycle root must use its canonical path")
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise SupervisorError("protected lifecycle root is unavailable") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise SupervisorError("protected lifecycle root is unsafe")
    if root_info.st_uid != os.geteuid() or stat.S_IMODE(root_info.st_mode) != 0o700:
        raise SupervisorError("protected lifecycle root must be owner-only")
    # Keep the broker-owned leaf deliberately short for Darwin's AF_UNIX path
    # limit; the opaque digest and socket type make an extension unnecessary.
    directory = root / "p"
    locator = directory / digest
    if len(os.fsencode(locator)) >= 100:
        raise SupervisorError("publication transport locator is too long")
    return str(locator)


def protected_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    try:
        info = path.lstat()
    except OSError as exc:
        raise SupervisorError("publication transport directory is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SupervisorError("publication transport directory is unsafe")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise SupervisorError("publication transport directory must be owner-only")


def publish_ready(
    ready_file: str,
    lifecycle_root: str,
    *,
    capability_id: str,
    supervisor_pid: int,
    created_at: str,
    child: ProcessIdentity,
    endpoint_identity: tuple[int, int],
) -> None:
    path = Path(ready_file)
    root = Path(lifecycle_root)
    try:
        parent = path.parent.resolve(strict=True)
        info = parent.lstat()
    except OSError as exc:
        raise SupervisorError("protected supervisor-ready directory is unavailable") from exc
    if (
        not path.is_absolute()
        or Path(os.path.abspath(path)) != path
        or path.name != "supervisor.ready"
        or parent.parent != root
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SupervisorError("protected supervisor-ready path is unsafe")
    value = {
        "schemaVersion": 1,
        "capabilityId": capability_id,
        "supervisorPid": supervisor_pid,
        "lifecycleCreatedAt": created_at,
        "childPid": child.pid,
        "childStart": child.start,
        "socketDevice": endpoint_identity[0],
        "socketInode": endpoint_identity[1],
    }
    # Build the receipt under a private sibling name, then publish it with one
    # atomic rename.  Creating the final path before writing lets a polling
    # launcher observe an empty or partial JSON document and reject an
    # otherwise healthy supervisor under scheduler or I/O pressure.
    pending_name = ".%s.pending" % path.name
    directory = -1
    descriptor = -1
    pending_created = False
    try:
        # Pin the verified directory before publication.  The launcher owns
        # the one-shot receipt and may unlink it and rmdir its barrier as soon
        # as the rename becomes visible; the held descriptor keeps the final
        # durability fsync valid across that retirement.
        directory = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(directory)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise SupervisorError(
                "protected supervisor-ready directory changed while being opened"
            )
        descriptor = os.open(
            pending_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        pending_created = True
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SupervisorError("protected supervisor-ready receipt already exists")
        os.replace(
            pending_name,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        pending_created = False
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0 and pending_created:
            try:
                os.unlink(pending_name, dir_fd=directory)
            except FileNotFoundError:
                pass
        if directory >= 0:
            os.close(directory)


def receive_exact(connection: socket.socket, size: int, deadline: float) -> bytes:
    value = bytearray()
    while len(value) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SupervisorError("publication request exceeded its frame deadline")
        connection.settimeout(remaining)
        block, ancillary, _flags, _address = connection.recvmsg(
            size - len(value), 256
        )
        if ancillary:
            raise SupervisorError("publication request carried ancillary data")
        if not block:
            raise SupervisorError("incomplete publication request")
        value.extend(block)
    return bytes(value)


def _darwin_bsd_info(pid: int) -> ProcBsdInfo:
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        libproc.proc_pidinfo.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        info = ProcBsdInfo()
        size = libproc.proc_pidinfo(
            pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)
        )
    except (OSError, AttributeError) as exc:
        raise SupervisorError("Darwin process identity is unavailable") from exc
    if size != ctypes.sizeof(info) or info.pbi_pid != pid:
        raise SupervisorError("Darwin process identity is unavailable")
    return info


def process_start_identity(pid: int) -> str:
    if sys.platform.startswith("linux"):
        try:
            raw = Path("/proc/%s/stat" % pid).read_text()
            fields = raw.rsplit(")", 1)[1].split()
            return fields[19]
        except (OSError, IndexError) as exc:
            raise SupervisorError("process generation is unavailable") from exc
    if sys.platform == "darwin":
        info = _darwin_bsd_info(pid)
        return "%s:%s:%s" % (
            info.pbi_start_tvsec,
            info.pbi_start_tvusec,
            info.pbi_pid,
        )
    raise SupervisorError("publication transport is unsupported on this platform")


_WORKER_EXEC_GATE = r"""
import os
import signal
import sys

gate_fd = int(sys.argv[1])
status_fd = int(sys.argv[2])
command = sys.argv[3:]
try:
    if os.read(gate_fd, 1) != b"1":
        raise OSError("worker exec gate was not released")
    os.close(gate_fd)
    # Successful exec closes this descriptor and gives the supervisor an EOF.
    # A failed exec writes one opaque byte instead; command details stay local.
    os.set_inheritable(status_fd, False)
    # Match subprocess.Popen(restore_signals=True).  Python ignores these
    # signals while its runtime is active; the final non-Python worker must not
    # inherit that interpreter-specific disposition through this exec gate.
    for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
        number = getattr(signal, name, None)
        if number is not None:
            signal.signal(number, signal.SIG_DFL)
    os.execvpe(command[0], command, os.environ)
except BaseException:
    try:
        os.write(status_fd, b"1")
    finally:
        os._exit(127)
"""


def spawn_identified_worker(
    command: list[str],
) -> tuple[subprocess.Popen[bytes], ProcessIdentity]:
    """Start one worker without racing its process-generation lookup.

    The trusted Python gate has the same PID and process start identity as the
    eventual worker after exec.  Holding it until that identity is captured
    keeps even an immediate-exit command from disappearing first.  The second
    pipe preserves Popen's exec-success boundary before a ready receipt can be
    published.
    """
    if not command:
        raise SupervisorError("publication supervisor command is absent")
    gate_read, gate_write = os.pipe()
    try:
        status_read, status_write = os.pipe()
    except BaseException:
        os.close(gate_read)
        os.close(gate_write)
        raise
    child: subprocess.Popen[bytes] | None = None
    try:
        child = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _WORKER_EXEC_GATE,
                str(gate_read),
                str(status_write),
                *command,
            ],
            close_fds=True,
            pass_fds=(gate_read, status_write),
        )
    except BaseException:
        os.close(gate_write)
        os.close(status_read)
        raise
    finally:
        os.close(gate_read)
        os.close(status_write)
    try:
        identity = ProcessIdentity(child.pid, process_start_identity(child.pid))
        if os.write(gate_write, b"1") != 1:
            raise SupervisorError("worker exec gate could not be released")
        os.close(gate_write)
        gate_write = -1
        if os.read(status_read, 1):
            child.wait(timeout=2)
            raise SupervisorError("worker command could not be executed")
        return child, identity
    except BaseException:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        raise
    finally:
        if gate_write >= 0:
            os.close(gate_write)
        os.close(status_read)


def parent_pid(pid: int) -> int:
    if sys.platform.startswith("linux"):
        try:
            raw = Path("/proc/%s/stat" % pid).read_text()
            fields = raw.rsplit(")", 1)[1].split()
            return int(fields[1])
        except (OSError, IndexError, ValueError) as exc:
            raise SupervisorError("process ancestry is unavailable") from exc
    if sys.platform == "darwin":
        return int(_darwin_bsd_info(pid).pbi_ppid)
    raise SupervisorError("publication transport is unsupported on this platform")


def walk_ancestry(
    peer: ProcessIdentity, child: ProcessIdentity, maximum: int = 64
) -> tuple[ProcessIdentity, ...]:
    result: list[ProcessIdentity] = []
    current = peer
    seen: set[int] = set()
    for _ in range(maximum):
        if current.pid in seen or process_start_identity(current.pid) != current.start:
            raise SupervisorError("publication peer ancestry changed")
        seen.add(current.pid)
        result.append(current)
        if current == child:
            return tuple(result)
        parent = parent_pid(current.pid)
        if parent <= 1:
            break
        current = ProcessIdentity(parent, process_start_identity(parent))
    raise SupervisorError("publication peer is not a bounded child descendant")


def _pidfd_live(pidfd: int) -> None:
    if select.select([pidfd], [], [], 0)[0]:
        raise SupervisorError("publication peer generation already exited")


def _pidfd_process(pidfd: int) -> int:
    """Return the kernel identity attached to an accepted-socket pidfd."""
    try:
        fields = {}
        for line in Path("/proc/self/fdinfo/%s" % pidfd).read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        pid = int(fields.get("Pid", "0"))
    except (OSError, ValueError) as exc:
        raise SupervisorError("Linux publication peer pidfd is unreadable") from exc
    if pid <= 1:
        raise SupervisorError("Linux publication peer pidfd is invalid")
    return pid


def peer_identity(
    connection: socket.socket,
) -> tuple[ProcessIdentity, int | None, bytes, int | None]:
    if sys.platform.startswith("linux"):
        raw = connection.getsockopt(socket.SOL_SOCKET, LINUX_SO_PEERCRED, 12)
        pid, uid, _gid = struct.unpack("3i", raw)
        try:
            pidfd_raw = connection.getsockopt(
                socket.SOL_SOCKET, LINUX_SO_PEERPIDFD, struct.calcsize("i")
            )
            if len(pidfd_raw) != struct.calcsize("i"):
                raise OSError("short SO_PEERPIDFD result")
            pidfd = struct.unpack("i", pidfd_raw)[0]
        except OSError as exc:
            raise SupervisorError(
                "accepted-socket Linux peer handles are unavailable"
            ) from exc
        if pidfd < 0 or _pidfd_process(pidfd) != pid:
            if pidfd >= 0:
                os.close(pidfd)
            raise SupervisorError("Linux peer credentials and pidfd disagree")
        return ProcessIdentity(pid, process_start_identity(pid)), uid, raw, pidfd
    if sys.platform == "darwin":
        token = connection.getsockopt(
            DARWIN_SOL_LOCAL, DARWIN_LOCAL_PEERTOKEN, 32
        )
        if len(token) != 32:
            raise SupervisorError("stable Darwin publication peer token is unavailable")
        try:
            bsm = ctypes.CDLL("/usr/lib/libbsm.dylib")
            array = (ctypes.c_uint32 * 8).from_buffer_copy(token)
            pointer = ctypes.POINTER(ctypes.c_uint32)
            bsm.audit_token_to_pid.argtypes = [pointer]
            bsm.audit_token_to_euid.argtypes = [pointer]
            bsm.audit_token_to_pidversion.argtypes = [pointer]
            pid = int(bsm.audit_token_to_pid(array))
            uid = int(bsm.audit_token_to_euid(array))
            version = int(bsm.audit_token_to_pidversion(array))
        except (OSError, AttributeError, ValueError) as exc:
            raise SupervisorError("Darwin peer audit token is unavailable") from exc
        if pid <= 1 or uid != os.geteuid() or version <= 0:
            raise SupervisorError("Darwin peer audit token is invalid")
        return ProcessIdentity(pid, process_start_identity(pid)), uid, token, None
    raise SupervisorError("publication transport is unsupported on this platform")


def authenticate_peer(
    connection: socket.socket, child: ProcessIdentity
) -> tuple[
    ProcessIdentity,
    int | None,
    bytes,
    int | None,
    tuple[ProcessIdentity, ...],
]:
    try:
        peer, peer_uid, token, pidfd = peer_identity(connection)
        if peer.pid <= 1 or peer_uid != os.geteuid():
            raise SupervisorError("publication peer owner does not match")
        first = walk_ancestry(peer, child)
        if pidfd is not None:
            _pidfd_live(pidfd)
        second = walk_ancestry(peer, child)
        if first != second:
            raise SupervisorError("publication peer ancestry was unstable")
        if pidfd is not None:
            _pidfd_live(pidfd)
        return peer, peer_uid, token, pidfd, first
    except OSError as exc:
        raise SupervisorError("publication peer identity is unavailable") from exc


def reauthenticate_peer(
    connection: socket.socket,
    child: ProcessIdentity,
    proof: tuple[
        ProcessIdentity,
        int | None,
        bytes,
        int | None,
        tuple[ProcessIdentity, ...],
    ],
) -> None:
    first_peer, first_uid, first_token, pidfd, first_walk = proof
    second_pidfd: int | None = None
    try:
        second_peer, second_uid, second_token, second_pidfd = peer_identity(connection)
        if (first_peer, first_uid, first_token) != (
            second_peer,
            second_uid,
            second_token,
        ):
            raise SupervisorError("publication peer generation changed")
        if pidfd is not None:
            _pidfd_live(pidfd)
        if walk_ancestry(first_peer, child) != first_walk:
            raise SupervisorError("publication peer ancestry changed")
    except OSError as exc:
        raise SupervisorError(
            "publication peer generation cannot be revalidated"
        ) from exc
    finally:
        if second_pidfd is not None:
            os.close(second_pidfd)


def lifecycle_generation(
    *,
    lifecycle_root: str,
    repository: str,
    team: str,
    category: str,
    instance: str,
    supervisor_pid: int,
    expected_created_at: str | None = None,
) -> str:
    command = [
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve().with_name("process-lifecycle.py")),
        "verify",
        "--root",
        lifecycle_root,
        "--repo",
        repository,
        "--team",
        team,
        "--category",
        category,
        "--instance",
        instance,
    ]
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SupervisorError("protected lifecycle generation is not current")
    try:
        record = json.loads(result.stdout)
    except (UnicodeError, ValueError) as exc:
        raise SupervisorError("protected lifecycle generation is malformed") from exc
    if (
        not isinstance(record, dict)
        or record.get("pid") != supervisor_pid
        or record.get("processGroupId") != supervisor_pid
        or record.get("sessionId") != supervisor_pid
        or record.get("team") != team
        or record.get("category") != category
        or record.get("instance") != instance
    ):
        raise SupervisorError("protected lifecycle generation does not bind the supervisor")
    created_at = record.get("createdAt")
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        raise SupervisorError("protected lifecycle generation time is invalid")
    if expected_created_at is not None and created_at != expected_created_at:
        raise SupervisorError("protected lifecycle generation changed")
    return created_at


def decode_request(
    connection: socket.socket, deadline: float
) -> tuple[dict[str, Any], bytes]:
    header = receive_exact(connection, 4, deadline)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_TRANSPORT_REQUEST_BYTES:
        raise SupervisorError("publication request has an invalid size")
    try:
        raw = receive_exact(connection, size, deadline)
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = item
            return result

        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, ValueError) as exc:
        raise SupervisorError("publication request is malformed") from exc
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SupervisorError("publication request exceeded its frame deadline")
    connection.settimeout(remaining)
    trailing, ancillary, _flags, _address = connection.recvmsg(1, 256)
    if trailing or ancillary:
        raise SupervisorError("publication request has trailing or ancillary data")
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "entry",
        "bodyHex",
    }:
        raise SupervisorError("publication request has an invalid shape")
    if value.get("schemaVersion") != 1 or not isinstance(value.get("entry"), dict):
        raise SupervisorError("publication request has an invalid schema")
    body_hex = value.get("bodyHex")
    if not isinstance(body_hex, str) or len(body_hex) < 2 or len(body_hex) > 131072:
        raise SupervisorError("publication request body is invalid")
    try:
        body = bytes.fromhex(body_hex)
    except ValueError as exc:
        raise SupervisorError("publication request body is invalid") from exc
    if body.hex() != body_hex or not body or len(body) > 65536:
        raise SupervisorError("publication request body is invalid")
    if value["entry"].get("producerCapability") is not None:
        raise SupervisorError("publication request is already signed")
    return value["entry"], body


def send_response(connection: socket.socket, value: dict[str, Any]) -> None:
    payload = canonical(value)
    if not payload or len(payload) > MAX_RESPONSE_BYTES:
        raise SupervisorError("publication response is too large")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def serve_connection(
    connection: socket.socket,
    repository: str,
    workspace: str,
    capability_id: str,
    supervisor_pid: int,
    child: ProcessIdentity,
    lifecycle: dict[str, str],
    created_at: str,
) -> None:
    deadline = time.monotonic() + FRAME_TIMEOUT_SECONDS
    proof: tuple[
        ProcessIdentity,
        int | None,
        bytes,
        int | None,
        tuple[ProcessIdentity, ...],
    ] | None = None
    try:
        proof = authenticate_peer(connection, child)
        entry, body = decode_request(connection, deadline)
        reauthenticate_peer(connection, child, proof)
        lifecycle_generation(
            lifecycle_root=lifecycle["root"],
            repository=repository,
            team=lifecycle["team"],
            category=lifecycle["category"],
            instance=lifecycle["instance"],
            supervisor_pid=supervisor_pid,
            expected_created_at=created_at,
        )
        capability = sign_active_entry(
            repository, workspace, capability_id, entry, body
        )
        reauthenticate_peer(connection, child, proof)
        send_response(
            connection,
            {"schemaVersion": 1, "producerCapability": capability},
        )
    except (CapabilityError, SupervisorError, OSError) as exc:
        # The client receives one bounded generic denial.  Broker paths, keys,
        # capability ids, and verifier details never cross the worker boundary.
        print(
            "publication-supervisor: publication request denied: %s" % exc,
            file=sys.stderr,
        )
        try:
            send_response(
                connection,
                {"schemaVersion": 1, "error": "publication request denied"},
            )
        except (OSError, SupervisorError):
            pass
    finally:
        if proof is not None and proof[3] is not None:
            os.close(proof[3])


def become_session_leader() -> int:
    pid = os.getpid()
    if os.getsid(0) != pid:
        try:
            os.setsid()
        except OSError as exc:
            raise SupervisorError(
                "publication supervisor requires a dedicated process session"
            ) from exc
    if os.getsid(0) != pid or os.getpgrp() != pid:
        raise SupervisorError("publication supervisor session binding failed")
    return pid


def run_supervisor(args: argparse.Namespace) -> int:
    if not args.command:
        raise SupervisorError("publication supervisor command is absent")
    expected_locator = transport_locator(args.repo, args.handle, args.lifecycle_root)
    if args.socket != expected_locator:
        raise SupervisorError("publication transport locator does not match its handle")
    active_record(args.repo, args.workspace, args.handle)
    supervisor_pid = become_session_leader()
    lifecycle = {
        "root": args.lifecycle_root,
        "team": args.team,
        "category": args.category,
        "instance": args.instance,
    }
    created_at = lifecycle_generation(
        lifecycle_root=args.lifecycle_root,
        repository=args.repo,
        team=args.team,
        category=args.category,
        instance=args.instance,
        supervisor_pid=supervisor_pid,
    )

    locator = Path(args.socket)
    protected_directory(locator.parent)
    if locator.exists() or locator.is_symlink():
        raise SupervisorError("publication transport endpoint already exists")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    child: subprocess.Popen[bytes] | None = None
    child_identity: ProcessIdentity | None = None
    endpoint_identity: tuple[int, int] | None = None
    try:
        previous_umask = os.umask(0o177)
        try:
            listener.bind(str(locator))
        finally:
            os.umask(previous_umask)
        locator.chmod(0o600)
        endpoint = locator.lstat()
        if (
            not stat.S_ISSOCK(endpoint.st_mode)
            or endpoint.st_uid != os.geteuid()
            or stat.S_IMODE(endpoint.st_mode) != 0o600
        ):
            raise SupervisorError("publication transport endpoint is unsafe")
        endpoint_identity = (endpoint.st_dev, endpoint.st_ino)
        listener.listen(16)
        listener.settimeout(POLL_SECONDS)
        child, child_identity = spawn_identified_worker(args.command)
        publish_ready(
            args.ready_file,
            args.lifecycle_root,
            capability_id=args.handle,
            supervisor_pid=supervisor_pid,
            created_at=created_at,
            child=child_identity,
            endpoint_identity=endpoint_identity,
        )
        while True:
            result = child.poll()
            if result is not None:
                return result
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            except socket.timeout:
                continue
            with connection:
                serve_connection(
                    connection,
                    args.repo,
                    args.workspace,
                    args.handle,
                    supervisor_pid,
                    child_identity,
                    lifecycle,
                    created_at,
                )
    finally:
        listener.close()
        cleanup_error: SupervisorError | None = None
        try:
            current = locator.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_error = SupervisorError(
                "publication transport endpoint cannot be inspected"
            )
        else:
            if (
                endpoint_identity is None
                or (current.st_dev, current.st_ino) != endpoint_identity
                or not stat.S_ISSOCK(current.st_mode)
                or current.st_uid != os.geteuid()
            ):
                cleanup_error = SupervisorError(
                    "publication transport endpoint identity changed"
                )
            else:
                locator.unlink()
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        # Exact-id compare-and-revoke cannot remove a successor pointer.  A
        # normal agent exit and every supervisor failure therefore fence only
        # this launch generation before lifecycle retirement can proceed.
        try:
            revoke_exact(args.repo, args.workspace, args.handle)
        except CapabilityError as exc:
            raise SupervisorError(
                "publication generation could not be retired"
            ) from exc
        if cleanup_error is not None:
            raise cleanup_error


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    locator_parser = subparsers.add_parser("locator")
    locator_parser.add_argument("--repo", required=True)
    locator_parser.add_argument("--handle", required=True)
    locator_parser.add_argument("--lifecycle-root", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--repo", required=True)
    run_parser.add_argument("--workspace", required=True)
    run_parser.add_argument("--handle", required=True)
    run_parser.add_argument("--socket", required=True)
    run_parser.add_argument("--lifecycle-root", required=True)
    run_parser.add_argument("--team", required=True)
    run_parser.add_argument("--category", choices=("gate", "task"), required=True)
    run_parser.add_argument("--instance", required=True)
    run_parser.add_argument("--ready-file", required=True)
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.operation == "locator":
            print(
                transport_locator(
                    args.repo, args.handle, args.lifecycle_root
                )
            )
            return 0
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        return run_supervisor(args)
    except (CapabilityError, SupervisorError, OSError) as exc:
        if getattr(args, "operation", None) == "run":
            try:
                revoke_exact(args.repo, args.workspace, args.handle)
            except (CapabilityError, OSError):
                pass
        print("publication-supervisor: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
