"""Operator-only exec-channel experiment for the observed sbx v0.54.0 interface.

This is not an execution backend or qualification authority. Name-based commands
are not atomically bound to inspect results, even when every inspection agrees.
The operator must own the disposable sandbox and arrange its eventual cleanup.
The only guest program copied or executed is the fixed qualification fixture;
that repository program is never imported or executed on the host.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import math
import os
import pwd
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


APP_NAME = "sf-qualification"
SUPPORTED_VERSION = "v0.54.0"
GUEST_FIXTURE = "/tmp/sf_qualification_fixture.py"
SOURCE_FIXTURE = Path(__file__).resolve().parents[2] / "bin/sandbox_qualification_fixture.py"
STDERR_MARKER = b"SF_QUALIFICATION_STDERR\n"
BINARY_PAYLOAD = bytes(range(256)) * 64
MAX_RUNTIME_BYTES = 256 * 1024 * 1024
MAX_FIXTURE_BYTES = 64 * 1024
MAX_INSPECT_BYTES = 64 * 1024
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
MAX_EXEC_OUTPUT_BYTES = 128 * 1024
MAX_FRAME_BYTES = 64 * 1024
FILE_READ_BYTES = 64 * 1024
TOTAL_TIMEOUT_SECONDS = 40.0
INSPECT_TIMEOUT_SECONDS = 5.0
COPY_TIMEOUT_SECONDS = 10.0
EXEC_TIMEOUT_SECONDS = 15.0
INSPECT_FIELDS = frozenset(
    {
        "agent", "cpus", "created_at", "created_version", "daemon_uptime",
        "daemon_version", "effective_working_dir", "host_mounts", "id", "image",
        "image_digest", "kits", "mcp_gateway", "mcp_mode", "mcp_servers", "memory",
        "name", "network", "network_policy", "proxy", "runtime_mounts", "sessions",
        "state", "uptime", "working_dir",
    }
)
REQUIRED_INSPECT_FIELDS = frozenset(
    {
        "id", "name", "created_at", "created_version", "daemon_version",
        "host_mounts", "runtime_mounts", "mcp_mode", "mcp_servers", "state",
    }
)
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CREATED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
LIMITATIONS = (
    "Operator-only experiment; not a production execution backend or authority receipt.",
    "Inspect checks and name-based commands are not atomically bound; matching "
    "metadata does not certify stable sandbox identity.",
    "Only exec framing, binary echo, stderr separation, and an exit status are observed; "
    "containment, policy, credentials, resource limits, and cleanup remain unqualified.",
    "Copy/exec may start a stopped sandbox. This probe does not create, stop, or "
    "remove sandboxes; the operator owns cleanup.",
)


class ExecProbeError(ValueError):
    """An operator probe failed closed without establishing qualification."""


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


CommandRunner = Callable[..., CommandResult]


@dataclasses.dataclass(frozen=True)
class ExecProbeReport:
    sandbox: str
    expected_id: str
    expected_created_at: str
    runtime_sha256: str
    fixture_sha256: str
    observed_states: tuple[str, ...]
    extra_diagnostic_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "action": "sandbox.exec-probe",
            "ok": True,
            "passed": True,
            "scope": "exec-channel-only",
            "operatorOnly": True,
            "qualified": False,
            "autonomousReady": False,
            "productionBackendAllowed": False,
            "identityAtomic": False,
            "containmentVerified": False,
            "cleanupPerformed": False,
            "appName": APP_NAME,
            "sandbox": self.sandbox,
            "expectedId": self.expected_id,
            "expectedCreatedAt": self.expected_created_at,
            "runtimeVersion": SUPPORTED_VERSION,
            "runtimeSha256": self.runtime_sha256,
            "fixtureSha256": self.fixture_sha256,
            "observedStates": list(self.observed_states),
            "observations": {
                "exactResponseFrames": 4,
                "binaryEchoBytes": len(BINARY_PAYLOAD),
                "stderrMarkerMatched": True,
                "extraDiagnosticBytes": self.extra_diagnostic_bytes,
                "exitStatus": 7,
                "metadataInspections": 3,
            },
            "limitations": list(LIMITATIONS),
        }


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink,
    )


def _read_file(
    path: Path, *, maximum: int, executable: bool, collect: bool
) -> tuple[bytes | None, str, tuple[int, ...]]:
    if not path.is_absolute() or ".." in path.parts:
        raise ExecProbeError("probe input must use an absolute normalized path")
    if not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_NONBLOCK", 0):
        raise ExecProbeError("probe requires no-follow, nonblocking regular-file reads")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ExecProbeError("probe input must be a bounded, nonempty regular file")
        if executable and (not before.st_mode & 0o111 or not os.access(path, os.X_OK)):
            raise ExecProbeError("explicit sbx path is not executable")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(FILE_READ_BYTES, maximum + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            if collect:
                chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if total > maximum or _identity(before) != _identity(after) or _identity(after) != _identity(named):
            raise ExecProbeError("probe input changed or exceeded its bound while being read")
        return b"".join(chunks) if collect else None, digest.hexdigest(), _identity(after)
    except OSError as exc:
        raise ExecProbeError("cannot securely read a required probe input") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_regular(path: Path, *, maximum: int, executable: bool) -> tuple[bytes, tuple[int, ...]]:
    content, _digest, identity = _read_file(path, maximum=maximum, executable=executable, collect=True)
    assert content is not None
    return content, identity


def _runtime_fingerprint(path: Path) -> tuple[str, tuple[int, ...]]:
    # sbx is a large native binary. Hash it incrementally without retaining its
    # contents, including during every pre-command pin recheck.
    _content, digest, identity = _read_file(
        path, maximum=MAX_RUNTIME_BYTES, executable=True, collect=False
    )
    return digest, identity


def _host_environment() -> dict[str, str]:
    # HOME comes from the account database, never an inherited override. sbx
    # needs its dedicated application state; no ambient API keys or endpoints
    # are copied. This does not certify the contents of that application's state.
    account = pwd.getpwuid(os.geteuid())
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
    }


def _require_child_ownership() -> None:
    # This operator tool owns its Popen children until it explicitly waits.
    # SIG_IGN/custom SIGCHLD handlers and foreign child-reaper threads break
    # that reservation. Native waitpid reapers/SA_NOCLDWAIT are unsupported;
    # this helper must not be embedded in a process using either mechanism.
    if (
        threading.current_thread() is not threading.main_thread()
        or threading.active_count() != 1
        or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
    ):
        raise ExecProbeError("native probe commands require single-threaded ownership and default SIGCHLD handling")


def _run_bounded(
    argv: Sequence[str],
    *,
    input_data: bytes,
    env: Mapping[str, str],
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> CommandResult:
    """Bound operator I/O; callers must not externally reap its owned children."""
    _require_child_ownership()
    deadline = time.monotonic() + timeout_seconds
    process = subprocess.Popen(
        list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd="/", env=dict(env), shell=False, close_fds=True, start_new_session=True,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max_stdout_bytes, "stderr": max_stderr_bytes}
    offset = 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if input_data:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ExecProbeError("sbx command exceeded its wall-clock deadline")
                for key, _mask in selector.select(remaining):
                    stream = key.fileobj
                    label = key.data
                    try:
                        if label == "stdin":
                            try:
                                offset += os.write(stream.fileno(), input_data[offset:offset + 8192])
                            except BrokenPipeError:
                                offset = len(input_data)
                            if offset == len(input_data):
                                selector.unregister(stream)
                                stream.close()
                        else:
                            chunk = os.read(stream.fileno(), 8192)
                            if not chunk:
                                selector.unregister(stream)
                                stream.close()
                            else:
                                if len(output[label]) + len(chunk) > limits[label]:
                                    raise ExecProbeError("sbx command exceeded its output byte limit")
                                output[label].extend(chunk)
                    except (BlockingIOError, InterruptedError):
                        continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ExecProbeError("sbx command exceeded its wall-clock deadline")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise ExecProbeError("sbx command exceeded its wall-clock deadline") from exc
        return CommandResult(returncode, bytes(output["stdout"]), bytes(output["stderr"]))
    finally:
        try:
            if process.returncode is None:
                _require_child_ownership()
                # Never poll/wait before this signal on failure. An exited but
                # unreaped leader still reserves its PID, so its dedicated
                # PGID cannot be reused while descendants retain our pipes.
                # The supported single-owner/default-SIGCHLD model above is
                # essential to that guarantee; the property lookup does not
                # reap the leader as Popen.poll() would.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


def _json_object(raw: bytes) -> dict[str, Any]:
    # Bound nesting before decoding, including JSON inside informational fields.
    depth = 0
    quoted = False
    escaped = False
    for value in raw:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            if depth > 16:
                raise ExecProbeError("probe JSON exceeds its nesting limit")
        elif value in (93, 125):
            depth -= 1
            if depth < 0:
                raise ExecProbeError("probe JSON has invalid nesting")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in items:
            if name in result:
                raise ExecProbeError("duplicate JSON key in probe output")
            result[name] = value
        return result

    def constant(_value: str) -> Any:
        raise ExecProbeError("non-finite JSON number in probe output")

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ExecProbeError("probe output is not strict UTF-8 JSON") from exc
    if not isinstance(result, dict):
        raise ExecProbeError("probe output must be one JSON object")
    pending: list[Any] = [result]
    count = 0
    while pending:
        value = pending.pop()
        count += 1
        if count > 4096:
            raise ExecProbeError("probe JSON exceeds its item limit")
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ExecProbeError("non-finite JSON number in probe output")
        elif isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ExecProbeError("invalid Unicode surrogate in probe output")
    return result


def _inspect(raw: bytes, *, sandbox: str, expected_id: str, expected_created_at: str) -> str:
    value = _json_object(raw)
    if not REQUIRED_INSPECT_FIELDS <= value.keys() or value.keys() - INSPECT_FIELDS:
        raise ExecProbeError("unknown or incomplete sbx inspect schema")
    if (value["id"], value["name"], value["created_at"]) != (expected_id, sandbox, expected_created_at):
        raise ExecProbeError("sandbox identity or creation metadata does not match")
    if value["created_version"] != SUPPORTED_VERSION or value["daemon_version"] != SUPPORTED_VERSION:
        raise ExecProbeError("probe supports only observed sbx v0.54.0 metadata")
    for name in ("host_mounts", "runtime_mounts", "mcp_servers"):
        if type(value[name]) is not list or value[name]:
            raise ExecProbeError("probe requires empty mount lists and no MCP servers")
    if value["mcp_mode"] != "static":
        raise ExecProbeError("probe requires static MCP mode without servers")
    state = value["state"]
    if not isinstance(state, str) or state not in {"running", "stopped"}:
        raise ExecProbeError("unknown sandbox state in inspect output")
    return state


def _frame(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 0 < len(raw) <= MAX_FRAME_BYTES:
        raise ExecProbeError("probe frame exceeds its byte limit")
    return struct.pack("!I", len(raw)) + raw


def _requests() -> tuple[dict[str, Any], ...]:
    return tuple(
        {"schemaVersion": 1, "id": identifier, "operation": operation, "payloadHex": payload.hex()}
        for identifier, operation, payload in (
            ("ping", "ping", b""), ("binary", "echo", BINARY_PAYLOAD),
            ("stderr", "stderr", b""), ("exit", "exit", b"\x07"),
        )
    )


def _validate_response(result: CommandResult, requests: tuple[dict[str, Any], ...]) -> int:
    # sbx may emit bounded startup diagnostics on stderr. They remain opaque
    # data, never control frames or rendered report text. The fixture marker
    # must occur exactly once on that separate channel.
    if result.returncode != 7 or result.stderr.count(STDERR_MARKER) != 1:
        raise ExecProbeError("fixture exit status or separate stderr marker did not match")
    offset = 0
    for request in requests:
        if len(result.stdout) - offset < 4:
            raise ExecProbeError("fixture response has a missing or truncated frame")
        size = struct.unpack("!I", result.stdout[offset:offset + 4])[0]
        offset += 4
        if not 0 < size <= MAX_FRAME_BYTES or len(result.stdout) - offset < size:
            raise ExecProbeError("fixture response has an invalid or truncated frame size")
        raw = result.stdout[offset:offset + size]
        offset += size
        decoded = _json_object(raw)
        expected = {**request, "fixtureVersion": 1}
        if decoded != expected or _frame(expected)[4:] != raw:
            raise ExecProbeError("fixture response does not exactly match the requested frame")
    if offset != len(result.stdout):
        raise ExecProbeError("fixture response contains trailing or extra frames")
    return len(result.stderr) - len(STDERR_MARKER)


def run_probe(
    *,
    sbx_path: Path,
    expected_sha256: str,
    sandbox: str,
    expected_id: str,
    expected_created_at: str,
    runner: CommandRunner | None = None,
) -> ExecProbeReport:
    """Run a fixed operator experiment; this never grants production authority."""
    if not _SHA256.fullmatch(expected_sha256):
        raise ExecProbeError("expected sbx SHA-256 must be 64 lowercase hexadecimal characters")
    if not _NAME.fullmatch(sandbox):
        raise ExecProbeError("sandbox must be one bounded lowercase name")
    try:
        if str(uuid.UUID(expected_id)) != expected_id:
            raise ValueError
        if not _CREATED_AT.fullmatch(expected_created_at):
            raise ValueError
        datetime.datetime.fromisoformat(expected_created_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ExecProbeError("expected ID must be a canonical UUID and creation must be RFC3339") from exc
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    runtime_digest, runtime_identity = _runtime_fingerprint(sbx_path)
    if runtime_digest != expected_sha256:
        raise ExecProbeError("explicit sbx executable does not match its expected SHA-256")
    fixture, fixture_identity = _read_regular(SOURCE_FIXTURE, maximum=MAX_FIXTURE_BYTES, executable=False)
    execute = runner if runner is not None else _run_bounded
    environment = _host_environment()
    prefix = [os.fspath(sbx_path), "--app-name", APP_NAME, "--no-input"]

    def call(arguments: list[str], *, timeout: float, maximum: int, payload: bytes = b"") -> CommandResult:
        current_digest, identity = _runtime_fingerprint(sbx_path)
        if identity != runtime_identity or current_digest != expected_sha256:
            raise ExecProbeError("pinned sbx executable changed during the probe")
        started = time.monotonic()
        remaining = min(timeout, deadline - started)
        if remaining <= 0:
            raise ExecProbeError("probe exceeded its total wall-clock deadline")
        command_deadline = started + remaining
        try:
            result = execute(
                [*prefix, *arguments], input_data=payload, env=environment,
                timeout_seconds=remaining, max_stdout_bytes=maximum,
                max_stderr_bytes=MAX_COMMAND_OUTPUT_BYTES,
            )
        except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            raise ExecProbeError("sbx command failed or exceeded its deadline") from exc
        if time.monotonic() >= command_deadline:
            raise ExecProbeError("sbx command exceeded its wall-clock deadline")
        if (
            not isinstance(result, CommandResult) or type(result.returncode) is not int
            or not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes)
            or len(result.stdout) > maximum or len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES
        ):
            raise ExecProbeError("sbx command returned invalid or oversized output")
        return result

    def inspect() -> str:
        result = call(
            ["inspect", sandbox, "--format", "json"],
            timeout=INSPECT_TIMEOUT_SECONDS, maximum=MAX_INSPECT_BYTES,
        )
        if result.returncode != 0 or result.stderr:
            raise ExecProbeError("sbx inspect did not return clean successful JSON")
        return _inspect(
            result.stdout, sandbox=sandbox, expected_id=expected_id,
            expected_created_at=expected_created_at,
        )

    states = [inspect()]
    copied = call(
        ["cp", os.fspath(SOURCE_FIXTURE), f"{sandbox}:{GUEST_FIXTURE}"],
        timeout=COPY_TIMEOUT_SECONDS, maximum=MAX_COMMAND_OUTPUT_BYTES,
    )
    if copied.returncode != 0:
        raise ExecProbeError("fixed qualification fixture copy failed")
    after_copy, after_copy_identity = _read_regular(SOURCE_FIXTURE, maximum=MAX_FIXTURE_BYTES, executable=False)
    if after_copy_identity != fixture_identity or after_copy != fixture:
        raise ExecProbeError("qualification fixture changed while being copied")
    states.append(inspect())
    requests = _requests()
    result = call(
        ["exec", "-i", "--user", "root", sandbox, "/usr/bin/python3", "-I", "-B",
         GUEST_FIXTURE, "--frame-timeout", "3"],
        timeout=EXEC_TIMEOUT_SECONDS, maximum=MAX_EXEC_OUTPUT_BYTES,
        payload=b"".join(_frame(request) for request in requests),
    )
    extra_diagnostic_bytes = _validate_response(result, requests)
    states.append(inspect())
    return ExecProbeReport(
        sandbox, expected_id, expected_created_at, expected_sha256,
        hashlib.sha256(fixture).hexdigest(), tuple(states), extra_diagnostic_bytes,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbx", required=True, type=Path, help="explicit absolute sbx executable")
    parser.add_argument("--sbx-sha256", required=True, help="expected SHA-256 of that executable")
    parser.add_argument("--app-name", required=True, choices=(APP_NAME,))
    parser.add_argument("--sandbox", required=True, help="existing disposable sandbox name")
    parser.add_argument("--expected-id", required=True, help="expected canonical UUID")
    parser.add_argument("--expected-created-at", required=True, help="exact expected RFC3339 creation timestamp")
    parser.add_argument("--json", action="store_true", help="emit the diagnostic report as JSON")
    args = parser.parse_args(argv)
    try:
        report = run_probe(
            sbx_path=args.sbx, expected_sha256=args.sbx_sha256, sandbox=args.sandbox,
            expected_id=args.expected_id, expected_created_at=args.expected_created_at,
        ).as_dict()
        status = 0
    except (ExecProbeError, KeyError) as exc:
        report = {
            "schemaVersion": 1, "action": "sandbox.exec-probe", "ok": False,
            "passed": False, "scope": "exec-channel-only", "operatorOnly": True,
            "qualified": False, "autonomousReady": False, "productionBackendAllowed": False,
            "identityAtomic": False, "containmentVerified": False, "cleanupPerformed": False,
            "error": str(exc), "limitations": list(LIMITATIONS),
        }
        status = 1
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    else:
        print("Operator exec-channel probe: " + ("passed" if report["passed"] else "failed"))
        if "error" in report:
            print(report["error"])
        for limitation in LIMITATIONS:
            print("  " + limitation)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
