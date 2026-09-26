#!/usr/bin/env python3
"""Detached, bounded runner for one idempotent release reconciliation."""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


EXPECTED_IDENTITY_FIELDS = {
    "jobId",
    "repository",
    "runId",
    "team",
    "featureId",
    "attempt",
    "commandDigest",
}
LIFECYCLE_HELPER = Path(__file__).resolve().with_name("process-lifecycle.py")
TEAM_FENCE_HELPER = Path(__file__).resolve().with_name("launch-lane-lock.py")
LIFECYCLE_ENV = {
    "PATH": "/usr/bin:/bin",
    "PYTHONNOUSERSITE": "1",
    "PYTHONSAFEPATH": "1",
}
LIFECYCLE_RECORD_FIELDS = {
    "schemaVersion",
    "repositoryId",
    "team",
    "category",
    "instance",
    "kind",
    "pid",
    "processIdentity",
    "launchToken",
    "createdAt",
    "tmuxSession",
    "tmuxWindow",
    "tmuxPane",
    "processGroupId",
    "sessionId",
    "tmuxPanePid",
    "auth",
}
GUARDIAN_STATUS_FIELDS = {"schemaVersion", "commandPid", "returnCode"}
GUARDIAN_STATUS_LIMIT = 512
RELEASE_RESULT_LOCK_TIMEOUT_SECONDS = 2.0
RELEASE_RESULT_LOCK_POLL_SECONDS = 0.02
RELEASE_RESULT_FIELDS = {
    "schemaVersion",
    "identity",
    "state",
    "createdAt",
    "workerPid",
    "startedAt",
    "heartbeatAt",
    "releasePid",
    "releaseMayHaveStartedAt",
    "authorityRevokedAt",
    "exitCode",
    "completedAt",
    "cancelledAt",
    "timedOut",
    "workerError",
}
GUARDIAN_SOURCE = r"""
import json
import os
import select
import signal
import sys


def read_decision(descriptor):
    decision = b""
    while len(decision) <= 16 and b"\n" not in decision:
        try:
            part = os.read(descriptor, 17 - len(decision))
        except InterruptedError:
            continue
        if not part:
            break
        decision += part
    return decision


def write_all(descriptor, payload):
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise RuntimeError("release guardian pipe write made no progress")
        offset += written


def kill_own_group(command_pid=None):
    if command_pid is not None:
        # The containment process is the unreaped direct parent, so this PID
        # cannot have been reused.  Kill it explicitly as well as the group in
        # case the command changed its own process-group membership.
        try:
            os.kill(command_pid, signal.SIGKILL)
        except OSError:
            # Group containment is still authoritative and must be attempted
            # even if an unusual exec-time credential change blocks PID signal.
            pass
    try:
        os.killpg(os.getpgrp(), signal.SIGKILL)
    except ProcessLookupError:
        pass
    os._exit(125)


def await_guardian_loss(descriptor):
    while True:
        try:
            readable, _, _ = select.select([descriptor], [], [])
        except InterruptedError:
            continue
        if readable:
            try:
                os.read(descriptor, 1)
            except InterruptedError:
                continue
            # The guardian sends exactly one launch decision before this loop.
            # EOF proves that the only writer (the registered guardian) died;
            # any later byte is a protocol violation.  The containment process
            # is itself a member of this group, so the PGID cannot be reused
            # before this exact group is killed.
            kill_own_group()


control_fd = int(sys.argv[1])
status_fd = int(sys.argv[2])
command = sys.argv[3:]
signal.signal(signal.SIGTERM, signal.SIG_IGN)

# The guardian is the authenticated session/group leader, but it never forks
# the release command directly.  Its containment child owns only the read end
# of this private pipe and launches the command, so neither the command nor any
# descendant can inherit the guardian's sole write end.  Guardian death is
# therefore an unforgeable EOF that remains portable across macOS and Linux.
containment_read, containment_write = os.pipe()
try:
    containment_pid = os.fork()
except BaseException as exc:
    print("release guardian could not fork containment: %s" % type(exc).__name__, file=sys.stderr, flush=True)
    os.close(containment_read)
    os.close(containment_write)
    os.close(status_fd)
    # Before registration, the worker's control writer is the only liveness
    # tether available.  EOF must retire this otherwise-unrecoverable guardian.
    # A valid decision can only follow successful lifecycle registration; stay
    # alive in that case so the worker (or later recovery) can terminate the
    # exact authenticated generation after observing status EOF.
    decision = read_decision(control_fd)
    os.close(control_fd)
    if decision in {b"go\n", b"cancel\n"}:
        while True:
            signal.pause()
    kill_own_group()

if containment_pid == 0:
    os.close(control_fd)
    os.close(containment_write)
    for signal_name in ("SIGTERM", "SIGINT", "SIGHUP"):
        signal.signal(getattr(signal, signal_name), signal.SIG_IGN)
    decision = read_decision(containment_read)
    if decision == b"go\n":
        try:
            command_pid = os.fork()
        except BaseException as exc:
            print("release containment could not fork command: %s" % type(exc).__name__, file=sys.stderr, flush=True)
            os.close(status_fd)
            await_guardian_loss(containment_read)
        if command_pid == 0:
            try:
                os.close(containment_read)
                os.close(status_fd)
                for signal_name in ("SIGTERM", "SIGINT", "SIGHUP"):
                    signal.signal(getattr(signal, signal_name), signal.SIG_DFL)
                os.closerange(3, 1048576)
                os.execvp(command[0], command)
            except BaseException as exc:
                print("release command could not exec: %s" % type(exc).__name__, file=sys.stderr, flush=True)
                os._exit(127)

        wait_status = None
        while wait_status is None:
            try:
                readable, _, _ = select.select([containment_read], [], [], 0.05)
            except InterruptedError:
                continue
            if readable:
                try:
                    os.read(containment_read, 1)
                except InterruptedError:
                    continue
                kill_own_group(command_pid)
            try:
                waited_pid, candidate = os.waitpid(command_pid, os.WNOHANG)
            except InterruptedError:
                continue
            if waited_pid == command_pid:
                wait_status = candidate
            elif waited_pid != 0:
                os.close(status_fd)
                kill_own_group()

        payload = json.dumps(
            {
                "schemaVersion": 1,
                "commandPid": command_pid,
                "returnCode": os.waitstatus_to_exitcode(wait_status),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        try:
            write_all(status_fd, payload)
        except BrokenPipeError:
            pass
        os.close(status_fd)
        await_guardian_loss(containment_read)
    elif decision == b"cancel\n":
        os.close(status_fd)
        await_guardian_loss(containment_read)
    else:
        os.close(status_fd)
        kill_own_group()

os.close(containment_read)
os.close(status_fd)
decision = read_decision(control_fd)
os.close(control_fd)
if decision not in {b"go\n", b"cancel\n"}:
    os.close(containment_write)
    kill_own_group()
try:
    write_all(containment_write, decision)
except BrokenPipeError:
    kill_own_group()

# Retain the only liveness writer for the lifetime of the authenticated leader.
# Conversely, if containment disappears first, this still-authenticated group
# leader can safely kill its own exact group rather than leave an unsupervised
# release command behind.
while True:
    try:
        waited_pid, _ = os.waitpid(containment_pid, 0)
        break
    except InterruptedError:
        continue
if waited_pid != containment_pid:
    kill_own_group()
kill_own_group()
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key: %s" % key)
        value[key] = item
    return value


def digest_command(command: list[str]) -> str:
    raw = json.dumps(
        command, sort_keys=False, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_identity(identity: object, command: list[str]) -> dict:
    if (
        not isinstance(identity, dict)
        or set(identity) != EXPECTED_IDENTITY_FIELDS
        or any(
            not isinstance(identity.get(field), str) or not identity[field]
            for field in EXPECTED_IDENTITY_FIELDS - {"attempt"}
        )
        or type(identity.get("attempt")) is not int
        or not 1 <= identity["attempt"] <= 1_000_000
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity["commandDigest"])
        or identity["commandDigest"] != digest_command(command)
    ):
        raise SystemExit("release-worker: identity has an unsupported schema or command")
    material = {
        field: identity[field] for field in EXPECTED_IDENTITY_FIELDS - {"jobId"}
    }
    expected = "release-" + hashlib.sha256(
        json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()[:32]
    if identity["jobId"] != expected:
        raise SystemExit("release-worker: identity digest mismatch")
    return identity


class TerminalResultAlreadyPublished(RuntimeError):
    """A concurrent supervisor has made this release result immutable."""

    def __init__(self, result: dict):
        super().__init__("a validated terminal release result is already published")
        self.result = result


def validate_release_result(value: object, identity: dict) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) - RELEASE_RESULT_FIELDS
        or value.get("schemaVersion") != 1
        or value.get("identity") != identity
        or value.get("state")
        not in {"launching", "running", "completed", "cancelled"}
    ):
        raise RuntimeError("release job result has an unsupported schema")
    for field in ("workerPid", "releasePid"):
        if field in value and (type(value[field]) is not int or value[field] <= 1):
            raise RuntimeError("release job result has an unsafe %s" % field)
    for field in (
        "createdAt",
        "startedAt",
        "heartbeatAt",
        "releaseMayHaveStartedAt",
        "authorityRevokedAt",
        "completedAt",
        "cancelledAt",
    ):
        if field in value and (
            not isinstance(value[field], str) or not value[field]
        ):
            raise RuntimeError("release job result has an invalid %s" % field)
    if value["state"] in {"completed", "cancelled"}:
        if (
            type(value.get("exitCode")) is not int
            or not isinstance(value.get("completedAt"), str)
            or not value["completedAt"]
        ):
            raise RuntimeError("terminal release job result is incomplete")
    elif "exitCode" in value or "completedAt" in value:
        raise RuntimeError("non-terminal release job result contains terminal fields")
    if "timedOut" in value and value["timedOut"] is not True:
        raise RuntimeError("release job timedOut must be true when present")
    if "workerError" in value and not isinstance(value["workerError"], str):
        raise RuntimeError("release job workerError must be a string")
    if "authorityRevokedAt" in value and value["state"] != "completed":
        raise RuntimeError(
            "only a completed release job may carry revoked-authority evidence"
        )
    return value


def locked_release_result(path: Path, identity: dict) -> dict:
    regular_private_file(path, "current job result")
    try:
        current = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("current release job result is invalid") from exc
    return validate_release_result(current, identity)


def acquire_release_result_lock(directory: int) -> None:
    """Bound writer serialization so a stopped peer cannot wedge this worker."""
    deadline = time.monotonic() + RELEASE_RESULT_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except (BlockingIOError, InterruptedError) as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    "timed out acquiring the release result writer fence"
                ) from exc
            time.sleep(min(RELEASE_RESULT_LOCK_POLL_SECONDS, remaining))


def atomic_json(path: Path, value: dict) -> None:
    is_release_result = (
        path.name == "result.json"
        and re.fullmatch(r"release-[0-9a-f]{32}", path.parent.name) is not None
    )
    identity: dict | None = None
    if is_release_result:
        candidate_identity = value.get("identity") if isinstance(value, dict) else None
        if not isinstance(candidate_identity, dict):
            raise RuntimeError("release job result has no protected identity")
        identity = candidate_identity
        validate_release_result(value, identity)

    directory = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary = path.with_name(".%s.tmp.%s" % (path.name, os.getpid()))
    descriptor = -1
    try:
        if is_release_result:
            info = os.fstat(directory)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise RuntimeError("release job directory is not private")
            # result.json is replaced on every publication; lock the stable,
            # private job-directory inode shared with the PM writer instead.
            acquire_release_result_lock(directory)
            assert identity is not None
            current = locked_release_result(path, identity)
            if current["state"] in {"completed", "cancelled"}:
                # Never even rewrite identical bytes here.  Seeing a terminal
                # result means another recovery path won publication and this
                # stale worker must stop before it can launch or mutate again.
                raise TerminalResultAlreadyPublished(current)

        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        os.close(directory)


def regular_private_file(path: Path, label: str, *, missing: bool = False) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing:
            return False
        raise SystemExit("release-worker: %s is missing" % label)
    except OSError as exc:
        raise SystemExit("release-worker: cannot inspect %s: %s" % (label, exc)) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise SystemExit("release-worker: %s must be an owner-only regular file" % label)
    return True


def cancellation_requested(path: Path, identity: dict) -> bool:
    if not regular_private_file(path, "cancellation request", missing=True):
        return False
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("invalid cancellation request") from exc
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != 1
        or value.get("identity") != identity
        or not isinstance(value.get("requestedAt"), str)
        or value.get("reason") not in {"tracker-authority-changed", "run-paused"}
    ):
        raise RuntimeError("cancellation request identity/schema mismatch")
    return True


def acquire_team_admission(
    lifecycle_root: Path, repository: Path, team: str
) -> tuple[subprocess.Popen[bytes], Path]:
    """Share the launcher's protected team fence through release admission."""
    barrier = Path(
        tempfile.mkdtemp(prefix=".release-team-fence.", dir=lifecycle_root)
    )
    barrier.chmod(0o700)
    holder: subprocess.Popen[bytes] | None = None
    try:
        holder = subprocess.Popen(
            [
                str(Path(sys.executable).resolve()), "-I", "-B",
                str(TEAM_FENCE_HELPER),
                "--root", str(lifecycle_root), "--repo", str(repository),
                "--team", team, "--category", "team", "--instance", "all",
                "--mode", "shared", "--barrier", str(barrier),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=LIFECYCLE_ENV,
            close_fds=True,
        )
        ready = barrier / "ready"
        while not ready.exists():
            if holder.poll() is not None:
                raise RuntimeError("protected release team fence failed before acquisition")
            time.sleep(0.02)
        info = ready.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size != len(str(holder.pid)) + 1
        ):
            raise RuntimeError("protected release team fence acknowledgement is unsafe")
        descriptor = os.open(
            ready, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            content = os.read(descriptor, info.st_size + 1)
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            or content != (str(holder.pid) + "\n").encode("ascii")
            or holder.poll() is not None
        ):
            raise RuntimeError("protected release team fence acknowledgement changed")
        return holder, barrier
    except BaseException:
        if holder is not None and holder.poll() is None:
            holder.terminate()
            holder.wait(timeout=5)
        if holder is not None and holder.stderr is not None:
            holder.stderr.close()
        (barrier / "ready").unlink(missing_ok=True)
        barrier.rmdir()
        raise


def release_team_admission(
    fence: tuple[subprocess.Popen[bytes], Path]
) -> None:
    holder, barrier = fence
    (barrier / "release").mkdir(mode=0o700)
    try:
        if holder.wait(timeout=5) != 0:
            raise RuntimeError("protected release team fence holder failed")
    finally:
        if holder.stderr is not None:
            holder.stderr.close()
        (barrier / "ready").unlink(missing_ok=True)
        (barrier / "release").rmdir()
        barrier.rmdir()


def lifecycle_command(
    action: str,
    *,
    lifecycle_root: Path,
    repository: Path,
    identity: dict,
    pid: int | None = None,
    generation: dict | None = None,
    signal_name: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    if action not in {"register", "signal", "terminate", "verify", "forget"}:
        raise RuntimeError("unsupported protected release lifecycle action")
    argv = [
        str(Path(sys.executable).resolve()),
        "-I", "-S", "-E", "-s",
        str(LIFECYCLE_HELPER),
        action,
        "--root", str(lifecycle_root),
        "--repo", str(repository),
    ]
    if action == "register":
        assert pid is not None
        argv += [
            "--team", identity["team"],
            "--category", "release",
            "--instance", identity["jobId"],
            "--kind", "background",
            "--pid", str(pid),
        ]
    else:
        argv += [
            "--team", identity["team"],
            "--category", "release",
            "--instance", identity["jobId"],
        ]
        if action == "signal":
            assert signal_name is not None
            argv += ["--signal", signal_name]
        elif signal_name is not None:
            raise RuntimeError("release lifecycle signal supplied for a non-signal action")
        if generation is None:
            raise RuntimeError("release lifecycle mutation requires an exact generation")
        created_at = generation.get("createdAt")
        launch_token = generation.get("launchToken")
        if (
            not isinstance(created_at, str)
            or not created_at.endswith("Z")
            or not isinstance(launch_token, str)
            or re.fullmatch(r"[0-9a-f]{64}", launch_token) is None
        ):
            raise RuntimeError("invalid exact release lifecycle generation")
        argv += [
            "--expected-created-at", created_at,
            "--expect-token-stdin",
        ]
    input_text = None if generation is None else generation["launchToken"] + "\n"
    options = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "env": LIFECYCLE_ENV,
        "timeout": 10,
        "check": False,
    }
    if input_text is None:
        options["stdin"] = subprocess.DEVNULL
    else:
        options["input"] = input_text
    result = subprocess.run(argv, **options)
    if check and result.returncode:
        raise RuntimeError(
            "protected release lifecycle %s failed with exit %s"
            % (action, result.returncode)
        )
    return result


def parse_lifecycle_generation(
    result: subprocess.CompletedProcess, identity: dict, guardian_pid: int
) -> dict:
    if result.returncode:
        raise RuntimeError(
            "protected release lifecycle register failed with exit %s"
            % result.returncode
        )
    if len(result.stdout.encode("utf-8")) > 4096:
        raise RuntimeError("protected release lifecycle record is too large")
    try:
        record = json.loads(result.stdout, object_pairs_hook=strict_object)
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError("protected release lifecycle record is malformed") from exc
    if (
        not isinstance(record, dict)
        or set(record) != LIFECYCLE_RECORD_FIELDS
        or record.get("schemaVersion") != 3
        or record.get("team") != identity["team"]
        or record.get("category") != "release"
        or record.get("instance") != identity["jobId"]
        or record.get("kind") != "background"
        or type(record.get("pid")) is not int
        or record["pid"] != guardian_pid
        or record.get("processGroupId") != guardian_pid
        or record.get("sessionId") != guardian_pid
        or not isinstance(record.get("processIdentity"), str)
        or not record["processIdentity"]
        or not isinstance(record.get("repositoryId"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["repositoryId"]) is None
        or not isinstance(record.get("launchToken"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["launchToken"]) is None
        or not isinstance(record.get("createdAt"), str)
        or not record["createdAt"].endswith("Z")
        or not isinstance(record.get("auth"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["auth"]) is None
        or any(
            record.get(field) is not None
            for field in ("tmuxSession", "tmuxWindow", "tmuxPane", "tmuxPanePid")
        )
    ):
        raise RuntimeError(
            "protected release lifecycle record does not match its guardian"
        )
    return {
        "pid": guardian_pid,
        "createdAt": record["createdAt"],
        "launchToken": record["launchToken"],
    }


def enable_child_subreaper() -> None:
    """Keep release descendants reapable after their direct parent exits on Linux."""
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise RuntimeError("cannot enable release child subreaper: errno %s" % error)
    enabled = ctypes.c_int()
    if prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0 or enabled.value != 1:
        error = ctypes.get_errno()
        raise RuntimeError("cannot verify release child subreaper: errno %s" % error)


def spawn_guardian(
    command: list[str], log: object
) -> tuple[subprocess.Popen, int, int]:
    control_read = control_write = status_read = status_write = -1
    try:
        control_read, control_write = os.pipe()
        status_read, status_write = os.pipe()
        os.set_blocking(status_read, False)
        guardian = subprocess.Popen(
            [
                str(Path(sys.executable).resolve()),
                "-I", "-S", "-E", "-s", "-c", GUARDIAN_SOURCE,
                str(control_read), str(status_write), *command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            pass_fds=(control_read, status_write),
        )
        os.close(control_read)
        control_read = -1
        os.close(status_write)
        status_write = -1
        return guardian, control_write, status_read
    except BaseException:
        for descriptor in (control_read, control_write, status_read, status_write):
            if descriptor >= 0:
                os.close(descriptor)
        raise


def parse_guardian_status(raw: bytes) -> dict:
    if not raw or len(raw) > GUARDIAN_STATUS_LIMIT:
        raise RuntimeError("release guardian status is empty or too large")
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise RuntimeError("release guardian status is not one complete record")
    try:
        status = json.loads(raw.decode("ascii"), object_pairs_hook=strict_object)
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError("release guardian status is malformed") from exc
    if (
        not isinstance(status, dict)
        or set(status) != GUARDIAN_STATUS_FIELDS
        or status.get("schemaVersion") != 1
        or type(status.get("commandPid")) is not int
        or status["commandPid"] <= 1
        or type(status.get("returnCode")) is not int
        or not -255 <= status["returnCode"] <= 255
    ):
        raise RuntimeError("release guardian status has an unsupported schema")
    return status


def read_guardian_status(descriptor: int, buffered: bytes) -> tuple[dict | None, bytes]:
    while True:
        try:
            chunk = os.read(descriptor, GUARDIAN_STATUS_LIMIT + 1)
        except BlockingIOError:
            return None, buffered
        except InterruptedError:
            continue
        if not chunk:
            return parse_guardian_status(buffered), buffered
        buffered += chunk
        if len(buffered) > GUARDIAN_STATUS_LIMIT:
            raise RuntimeError("release guardian status is too large")


def terminate_unregistered_guardian(process: subprocess.Popen) -> None:
    """Kill only a still-blocked, never-registered guardian owned by this worker."""
    if process.poll() is not None:
        return
    try:
        if os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
            raise RuntimeError("unregistered release guardian lacks a dedicated session")
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("unregistered release guardian survived SIGKILL") from exc


def drain_adopted_children(timeout: float = 5.0) -> None:
    if not sys.platform.startswith("linux"):
        return
    deadline = time.monotonic() + timeout
    while True:
        try:
            child_pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except InterruptedError:
            continue
        if child_pid > 0:
            continue
        if time.monotonic() >= deadline:
            raise RuntimeError("release descendants could not be reaped after termination")
        time.sleep(0.02)


def terminate_release_generation(
    process: subprocess.Popen,
    *,
    lifecycle_root: Path,
    repository: Path,
    identity: dict,
    generation: dict,
    graceful: bool,
    grace_seconds: float = 10.0,
) -> None:
    """Terminate and reap one exact generation, retaining its safe tombstone."""
    if process.pid != generation.get("pid"):
        raise RuntimeError("release guardian does not match lifecycle generation")
    if graceful:
        term = lifecycle_command(
            "signal",
            lifecycle_root=lifecycle_root,
            repository=repository,
            identity=identity,
            generation=generation,
            signal_name="TERM",
            check=False,
        )
        if term.returncode != 0:
            raise RuntimeError(
                "exact release lifecycle TERM failed with exit %s" % term.returncode
            )
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    terminated = lifecycle_command(
        "terminate",
        lifecycle_root=lifecycle_root,
        repository=repository,
        identity=identity,
        generation=generation,
        check=False,
    )
    if terminated.returncode != 0:
        raise RuntimeError(
            "exact release lifecycle termination failed with exit %s"
            % terminated.returncode
        )
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("release guardian survived exact SIGKILL") from exc
    drain_adopted_children()


def forget_release_generation(
    *,
    lifecycle_root: Path,
    repository: Path,
    identity: dict,
    generation: dict,
) -> None:
    """Forget an exact completed tombstone only after durable terminal state."""
    forgotten = lifecycle_command(
        "forget",
        lifecycle_root=lifecycle_root,
        repository=repository,
        identity=identity,
        generation=generation,
        check=False,
    )
    if forgotten.returncode != 0:
        raise RuntimeError(
            "exact release lifecycle forget failed with exit %s"
            % forgotten.returncode
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--identity-json", required=True)
    parser.add_argument("--lifecycle-root", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.timeout < 60 or args.timeout > 86400:
        raise SystemExit("release-worker: invalid command or timeout")
    try:
        identity = json.loads(args.identity_json, object_pairs_hook=strict_object)
    except ValueError as exc:
        raise SystemExit("release-worker: invalid identity JSON") from exc
    identity = validate_identity(identity, command)
    parent = args.result.parent.resolve(strict=True)
    if args.log.parent.resolve(strict=True) != parent:
        raise SystemExit("release-worker: result and log must share one protected directory")
    if args.result.name != "result.json" or args.log.name != "release.log":
        raise SystemExit("release-worker: result/log names are fixed by the supervisor")
    if parent.name != identity["jobId"]:
        raise SystemExit("release-worker: job directory does not match job identity")
    info = parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SystemExit("release-worker: job directory must be private mode 0700")
    lifecycle_root = args.lifecycle_root.resolve(strict=True)
    repository = args.repository.resolve(strict=True)
    if str(repository) != identity["repository"]:
        raise SystemExit("release-worker: repository does not match job identity")
    regular_private_file(args.result, "initial job result")
    try:
        initial = json.loads(
            args.result.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit("release-worker: initial job result is invalid") from exc
    if (
        not isinstance(initial, dict)
        or set(initial) != {"schemaVersion", "identity", "state", "createdAt"}
        or initial.get("schemaVersion") != 1
        or initial.get("identity") != identity
        or initial.get("state") != "launching"
        or not isinstance(initial.get("createdAt"), str)
    ):
        raise SystemExit("release-worker: initial job result does not authorize this launch")
    cancel = parent / "cancel.json"

    state = {
        "schemaVersion": 1,
        "identity": identity,
        "state": "running",
        "workerPid": os.getpid(),
        "startedAt": now(),
        "heartbeatAt": now(),
    }
    try:
        atomic_json(args.result, state)
    except TerminalResultAlreadyPublished:
        return 125
    if cancellation_requested(cancel, identity):
        completed_at = now()
        state.update(
            {
                "state": "cancelled",
                "exitCode": 130,
                "completedAt": completed_at,
                "cancelledAt": completed_at,
            }
        )
        try:
            atomic_json(args.result, state)
        except TerminalResultAlreadyPublished:
            return 125
        return 0
    log_fd = os.open(
        args.log,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    exit_code = 125
    timed_out = False
    cancelled = False
    authority_revoked_at: str | None = None
    process: subprocess.Popen | None = None
    generation: dict | None = None
    registration_succeeded = False
    tombstone_pending = False
    team_fence: tuple[subprocess.Popen[bytes], Path] | None = None
    control_write = -1
    status_read = -1
    status_buffer = b""
    try:
        with os.fdopen(log_fd, "a", encoding="utf-8") as log:
            log_fd = -1
            # Generic team stop cannot snapshot between release admission and
            # the durable guardian registration/go decision.  The guardian
            # still waits behind its private pipe while the fence is acquired.
            team_fence = acquire_team_admission(
                lifecycle_root, repository, identity["team"]
            )
            enable_child_subreaper()
            process, control_write, status_read = spawn_guardian(command, log)
            state["releasePid"] = process.pid
            # Make the guardian PID durable before its authenticated lifecycle
            # record can become durable.  The guardian is still blocked behind
            # the control pipe, so a crash before registration closes the pipe
            # without ever launching the release command.  A crash after
            # registration leaves both anchors available to exact recovery.
            atomic_json(args.result, state)
            registered = lifecycle_command(
                "register",
                lifecycle_root=lifecycle_root,
                repository=repository,
                identity=identity,
                pid=process.pid,
                check=False,
            )
            registration_succeeded = registered.returncode == 0
            generation = parse_lifecycle_generation(registered, identity, process.pid)
            if cancellation_requested(cancel, identity):
                cancelled = True
                try:
                    if os.write(control_write, b"cancel\n") != len(b"cancel\n"):
                        raise RuntimeError("release cancellation barrier write was incomplete")
                except BrokenPipeError:
                    pass
                os.close(control_write)
                control_write = -1
                terminate_release_generation(
                    process,
                    lifecycle_root=lifecycle_root,
                    repository=repository,
                    identity=identity,
                    generation=generation,
                    graceful=False,
                )
                registration_succeeded = False
                tombstone_pending = True
                exit_code = 130
            else:
                # Persist uncertainty before opening the barrier. A crash after
                # this write can never be misclassified as a safe pre-launch
                # cancellation, even if it occurs immediately around os.write.
                state["releaseMayHaveStartedAt"] = now()
                atomic_json(args.result, state)
                try:
                    if os.write(control_write, b"go\n") != len(b"go\n"):
                        raise RuntimeError("release launch barrier write was incomplete")
                except BrokenPipeError as exc:
                    raise RuntimeError("release launch barrier exited before authorization") from exc
                os.close(control_write)
                control_write = -1
                release_team_admission(team_fence)
                team_fence = None
            deadline = time.monotonic() + args.timeout
            next_heartbeat = time.monotonic() + 1
            while not cancelled:
                if cancellation_requested(cancel, identity):
                    authority_revoked_at = now()
                    terminate_release_generation(
                        process,
                        lifecycle_root=lifecycle_root,
                        repository=repository,
                        identity=identity,
                        generation=generation,
                        graceful=True,
                    )
                    registration_succeeded = False
                    tombstone_pending = True
                    exit_code = 130
                    state["workerError"] = (
                        "release authority changed after launch; deployment outcome requires reconciliation"
                    )
                    break
                status, status_buffer = read_guardian_status(
                    status_read, status_buffer
                )
                if status is not None:
                    exit_code = status["returnCode"]
                    terminate_release_generation(
                        process,
                        lifecycle_root=lifecycle_root,
                        repository=repository,
                        identity=identity,
                        generation=generation,
                        graceful=False,
                    )
                    registration_succeeded = False
                    tombstone_pending = True
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    terminate_release_generation(
                        process,
                        lifecycle_root=lifecycle_root,
                        repository=repository,
                        identity=identity,
                        generation=generation,
                        graceful=True,
                    )
                    registration_succeeded = False
                    tombstone_pending = True
                    exit_code = 124
                    break
                if time.monotonic() >= next_heartbeat:
                    state["heartbeatAt"] = now()
                    atomic_json(args.result, state)
                    next_heartbeat = time.monotonic() + 1
                time.sleep(0.2)
    except BaseException as exc:
        terminal_result_won = isinstance(exc, TerminalResultAlreadyPublished)
        cleanup_error: BaseException | None = None
        if process is not None and registration_succeeded and generation is not None:
            try:
                terminate_release_generation(
                    process,
                    lifecycle_root=lifecycle_root,
                    repository=repository,
                    identity=identity,
                    generation=generation,
                    graceful=False,
                )
                registration_succeeded = False
                tombstone_pending = True
            except BaseException as cleanup_exc:
                cleanup_error = cleanup_exc
        elif process is not None and not registration_succeeded:
            try:
                terminate_unregistered_guardian(process)
            except BaseException as cleanup_exc:
                cleanup_error = cleanup_exc
        elif process is not None:
            cleanup_error = RuntimeError(
                "registered release guardian has no exact lifecycle generation"
            )
        if terminal_result_won:
            if cleanup_error is None and tombstone_pending:
                try:
                    assert generation is not None
                    forget_release_generation(
                        lifecycle_root=lifecycle_root,
                        repository=repository,
                        identity=identity,
                        generation=generation,
                    )
                except BaseException:
                    pass
            # The winning terminal record is already durable.  Whether exact
            # cleanup just succeeded or recovery already retired the record,
            # this stale worker must never publish from its obsolete snapshot.
            return 125
        if cleanup_error is not None:
            state["state"] = "running"
            state["heartbeatAt"] = now()
            state["workerError"] = "%s: %s; cleanup: %s: %s" % (
                type(exc).__name__, str(exc)[:260],
                type(cleanup_error).__name__, str(cleanup_error)[:180],
            )
            for field in (
                "exitCode", "completedAt", "cancelledAt", "timedOut",
                "authorityRevokedAt",
            ):
                state.pop(field, None)
            try:
                atomic_json(args.result, state)
            except TerminalResultAlreadyPublished:
                return 125
            return 125
        state["workerError"] = "%s: %s" % (type(exc).__name__, str(exc)[:500])
        exit_code = 125
    finally:
        if team_fence is not None:
            release_team_admission(team_fence)
        if control_write >= 0:
            os.close(control_write)
        if status_read >= 0:
            os.close(status_read)
        if log_fd >= 0:
            os.close(log_fd)
    final_state = "cancelled" if cancelled else "completed"
    state.update({"state": final_state, "exitCode": exit_code, "completedAt": now()})
    if cancelled:
        state["cancelledAt"] = state["completedAt"]
    if authority_revoked_at is not None:
        state["authorityRevokedAt"] = authority_revoked_at
    if timed_out:
        state["timedOut"] = True
    try:
        atomic_json(args.result, state)
    except TerminalResultAlreadyPublished:
        return 125
    if tombstone_pending:
        try:
            assert generation is not None
            forget_release_generation(
                lifecycle_root=lifecycle_root,
                repository=repository,
                identity=identity,
                generation=generation,
            )
        except BaseException:
            # Terminal state is already durable and must not be rewritten as
            # nonterminal.  The safe completed tombstone remains available to
            # the supervisor's authenticated release inspection and cleanup.
            return 125
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
