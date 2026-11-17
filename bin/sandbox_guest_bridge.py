#!/usr/bin/env python3
"""Guest-only bridge: private local requests to non-TTY framed exec I/O.

Run only inside a disposable sandbox. Agent stdout/stderr are bounded diagnostic
data on stderr; only local artifact requests reach framed stdout. Guest root can
replace this helper: it is a convenience, never a host authorization boundary.
The external controller still owns VM deadlines, revocation, and removal.
"""
from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_guest_client import MAX_REQUEST, MAX_RESPONSE, GuestProtocolError, decode

MAX_REQUESTS = 64
MAX_LOG_BYTES = 1024 * 1024
FRAME_SECONDS = 10


class Bridge:
    def __init__(self, command: list[str], socket_path: Path, wall_seconds: int, agent_uid: int | None = None):
        self.command = command
        self.path = socket_path
        self.deadline = time.monotonic() + wall_seconds
        self.logs: set[int] = set()
        self.log_bytes = 0
        self.agent_uid = agent_uid

    def drain(self, descriptor: int) -> None:
        try:
            chunk = os.read(descriptor, 8192)
        except BlockingIOError:
            return
        if not chunk:
            self.logs.discard(descriptor)
            return
        self.log_bytes += len(chunk)
        if self.log_bytes > MAX_LOG_BYTES:
            raise GuestProtocolError("guest diagnostic budget exhausted")
        try:
            # Never wait for a diagnostic reader. Partial writes are dropped;
            # input bytes are still counted against the complete log budget.
            os.write(2, chunk)
        except BlockingIOError:
            pass

    def wait(self, descriptor: int, *, write: bool, deadline: float) -> None:
        while True:
            remaining = min(deadline, self.deadline) - time.monotonic()
            if remaining <= 0:
                raise GuestProtocolError("guest channel deadline exceeded")
            readable, writable, _ = select.select(
                list(self.logs) + ([] if write else [descriptor]),
                [descriptor] if write else [], [], remaining,
            )
            for source in self.logs.intersection(readable):
                self.drain(source)
            if descriptor in (writable if write else readable):
                return

    def read(self, descriptor: int, size: int, deadline: float) -> bytes:
        result = bytearray()
        while len(result) < size:
            self.wait(descriptor, write=False, deadline=deadline)
            try:
                chunk = os.read(descriptor, min(8192, size - len(result)))
            except BlockingIOError:
                continue
            if not chunk:
                raise GuestProtocolError("guest channel closed")
            result.extend(chunk)
        return bytes(result)

    def frame(self, descriptor: int, maximum: int, deadline: float) -> bytes:
        size = struct.unpack("!I", self.read(descriptor, 4, deadline))[0]
        if not 0 < size <= maximum:
            raise GuestProtocolError("guest frame exceeds its limit")
        return self.read(descriptor, size, deadline)

    def write(self, descriptor: int, raw: bytes, deadline: float) -> None:
        frame = struct.pack("!I", len(raw)) + raw
        offset = 0
        while offset < len(frame):
            self.wait(descriptor, write=True, deadline=deadline)
            try:
                count = os.write(descriptor, frame[offset:offset + 8192])
            except BlockingIOError:
                continue
            if count <= 0:
                raise GuestProtocolError("guest channel write failed")
            offset += count

    def run(self) -> int:
        # No recursive mkdir or removal of preexisting paths. The controller
        # provisions this guest directory; the bridge owns only its new socket.
        if not self.command or not self.path.is_absolute() or str(self.path) != os.path.abspath(self.path) or len(os.fsencode(self.path)) >= 100:
            raise GuestProtocolError("invalid guest bridge configuration")
        parent = self.path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise GuestProtocolError("guest socket directory must be private")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        process = None
        owned_socket = None
        changed: dict[int, bool] = {}
        try:
            server.bind(str(self.path))
            os.chmod(self.path, 0o600)
            info = self.path.lstat()
            owned_socket = (info.st_dev, info.st_ino)
            server.listen(1)
            server.setblocking(False)
            if self.agent_uid is not None:
                if type(self.agent_uid) is not int or not 1 <= self.agent_uid <= 65535 or os.geteuid() not in {0, self.agent_uid}:
                    raise GuestProtocolError("invalid unprivileged guest identity")
                if os.geteuid() == 0:
                    os.chown(self.path, self.agent_uid, self.agent_uid)
                    os.chown(self.path.parent, self.agent_uid, self.agent_uid)
            for descriptor in (0, 1, 2):
                changed[descriptor] = os.get_blocking(descriptor)
                os.set_blocking(descriptor, False)
            environment = dict(os.environ)  # Already guest-only; no host credential import.
            environment["STARTUP_FACTORY_GUEST_SOCKET"] = str(self.path)
            if self.agent_uid is not None:
                environment["HOME"] = "/home/sf-agent"
                environment["USER"] = environment["LOGNAME"] = "sf-agent"
                environment["SHELL"] = "/bin/sh"
                environment["PATH"] = "/opt/startup-factory/bin:" + environment.get("PATH", "/usr/bin:/bin")
                environment["STARTUP_FACTORY_PROMPT"] = "/opt/startup-factory/prompt.md"
            def drop_identity():
                if self.agent_uid is not None:
                    # Linux guest only: an agent/test must not regain root via
                    # setuid or file capabilities and alter its trusted monitor.
                    libc = ctypes.CDLL(None, use_errno=True)
                    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
                        os._exit(126)
                    if os.geteuid() == 0:
                        os.setgroups([])
                        os.setgid(self.agent_uid)
                        os.setuid(self.agent_uid)
            process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=environment, close_fds=True, start_new_session=True,
                                       preexec_fn=drop_identity if self.agent_uid is not None else None)
            assert process.stdout is not None and process.stderr is not None
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                self.logs.add(stream.fileno())
            requests = 0
            total_input = 0
            while True:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise GuestProtocolError("guest bridge deadline exceeded")
                readable, _, _ = select.select([server.fileno(), *self.logs], [], [], min(0.1, remaining))
                for descriptor in self.logs.intersection(readable):
                    self.drain(descriptor)
                if server.fileno() in readable:
                    connection, _ = server.accept()
                    with connection:
                        connection.setblocking(False)
                        deadline = min(self.deadline, time.monotonic() + FRAME_SECONDS)
                        raw = self.frame(connection.fileno(), MAX_REQUEST, deadline)
                        request = decode(raw)
                        requests += 1
                        total_input += len(raw)
                        if requests > MAX_REQUESTS or total_input > 4 * 1024 * 1024 or request.get("operation") not in {"artifact.submit", "context.read", "progress.report"} or type(request.get("id")) is not str:
                            raise GuestProtocolError("guest request budget or operation rejected")
                        self.write(1, raw, deadline)
                        response_raw = self.frame(0, MAX_RESPONSE, deadline)
                        response = decode(response_raw)
                        if response.get("id") != request["id"] or response.get("operation") != request["operation"]:
                            raise GuestProtocolError("host response binding mismatch")
                        self.write(connection.fileno(), response_raw, deadline)
                if not self.logs:
                    try:
                        return process.wait(timeout=0)
                    except subprocess.TimeoutExpired:
                        pass
        finally:
            server.close()
            if process is not None:
                # Do not poll/reap before signaling: retain the leader's PID
                # reservation until this bridge has retired its owned group.
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=2)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            for descriptor, blocking in changed.items():
                os.set_blocking(descriptor, blocking)
            if owned_socket is not None:
                try:
                    current = self.path.lstat()
                except FileNotFoundError:
                    current = None
                if current is not None and stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == owned_socket:
                    self.path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest-only", action="store_true", required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--wall-seconds", type=int, default=1800)
    parser.add_argument("--agent-uid", type=int, default=None)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    def interrupted(_number, _frame):
        raise GuestProtocolError("guest bridge interrupted")
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        if not 1 <= args.wall_seconds <= 86400:
            raise GuestProtocolError("invalid guest wall limit")
        result = Bridge(command, args.socket, args.wall_seconds, args.agent_uid).run()
        return result if 0 <= result <= 125 else 1
    except (OSError, ValueError, subprocess.SubprocessError):
        try:
            blocking = os.get_blocking(2)
            try:
                os.set_blocking(2, False)
                os.write(2, b"guest bridge closed\n")
            finally:
                os.set_blocking(2, blocking)
        except OSError:
            pass
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
