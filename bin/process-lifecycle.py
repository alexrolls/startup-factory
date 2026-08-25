#!/usr/bin/env python3
"""Authenticated process-lifecycle records for the deterministic team broker.

The agent workspace is deliberately not an authority source.  This helper keeps
the PID, process start identity, and tmux target in a protected external root and
authenticates every record with a root-local HMAC key before it is trusted.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


NOT_LIVE = 3
IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
RECORD_KEYS_V1 = {
    "schemaVersion",
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
    "auth",
}
RECORD_KEYS_V2 = RECORD_KEYS_V1 | {
    "processGroupId",
    "sessionId",
    "tmuxPanePid",
}


class LifecycleError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise LifecycleError(message)


def canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def validate_identifier(label: str, value: str) -> None:
    if not IDENTIFIER.fullmatch(value):
        fail(f"unsafe {label} identifier {value!r}")


def validate_directory_component(path: Path, *, leaf: bool) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot stat lifecycle path component {path}: {exc}")
    if stat.S_ISLNK(metadata.st_mode):
        fail(f"lifecycle path component must not be a symlink: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"lifecycle path component is not a directory: {path}")
    if metadata.st_uid not in {0, os.geteuid()}:
        fail(f"lifecycle path component has an untrusted owner: {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o022:
        fail(f"lifecycle path component is group/world-writable: {path}")
    if leaf and mode != 0o700:
        fail(f"lifecycle state root must be private (mode 0700): {path}")
    return metadata


def validate_root(raw: str, repository_raw: str) -> Path:
    root = Path(raw)
    if not root.is_absolute():
        fail("lifecycle state root must be absolute")
    normalized = Path(os.path.normpath(str(root)))
    if normalized != root:
        fail("lifecycle state root must be normalized and contain no '..'")

    current = Path(root.anchor)
    validate_directory_component(current, leaf=current == root)
    for part in root.parts[1:]:
        current /= part
        validate_directory_component(current, leaf=current == root)

    resolved = root.resolve(strict=True)
    repository = Path(repository_raw).resolve(strict=True)
    skill_root = Path(__file__).resolve(strict=True).parent.parent
    for boundary, label in ((repository, "agent repository"), (skill_root, "skill installation")):
        try:
            common = Path(os.path.commonpath((str(resolved), str(boundary))))
        except ValueError:
            continue
        if common in {resolved, boundary}:
            fail(f"lifecycle state root and {label} must be disjoint")
    if not os.access(resolved, os.R_OK | os.W_OK | os.X_OK):
        fail("lifecycle state root is not accessible to the broker executor")
    return resolved


def secure_open(path: Path, *, expected_mode: int) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot securely open {path}: {exc}")
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        if not stat.S_ISREG(opened.st_mode):
            fail(f"protected lifecycle file is not regular: {path}")
        if stat.S_ISLNK(named.st_mode):
            fail(f"protected lifecycle file must not be a symlink: {path}")
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            fail(f"protected lifecycle file changed while opening: {path}")
        if opened.st_uid not in {0, os.geteuid()}:
            fail(f"protected lifecycle file has an untrusted owner: {path}")
        if stat.S_IMODE(opened.st_mode) != expected_mode:
            fail(f"protected lifecycle file must have mode {expected_mode:04o}: {path}")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def read_secure(path: Path, *, expected_mode: int, maximum: int) -> bytes:
    descriptor, metadata = secure_open(path, expected_mode=expected_mode)
    try:
        if metadata.st_size > maximum:
            fail(f"protected lifecycle file is too large: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            fail(f"protected lifecycle file is too large: {path}")
        after = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            fail(f"protected lifecycle file changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def initialize(raw_root: str, repository: str) -> tuple[Path, Path, bytes]:
    root = validate_root(raw_root, repository)
    records = root / "records"
    if not records.exists():
        try:
            records.mkdir(mode=0o700)
        except OSError as exc:
            fail(f"cannot create protected lifecycle records directory: {exc}")
    validate_directory_component(records, leaf=True)

    key_path = root / "record-auth.key"
    if not key_path.exists():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(key_path, flags, 0o600)
        except FileExistsError:
            pass
        except OSError as exc:
            fail(f"cannot create lifecycle authentication key: {exc}")
        else:
            try:
                key = secrets.token_bytes(32)
                os.write(descriptor, key)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    key = read_secure(key_path, expected_mode=0o600, maximum=32)
    if len(key) != 32:
        fail("lifecycle authentication key must contain exactly 32 bytes")
    return root, records, key


def record_path(records: Path, team: str, category: str, instance: str) -> Path:
    digest = hashlib.sha256(
        team.encode("utf-8")
        + b"\0"
        + category.encode("ascii")
        + b"\0"
        + instance.encode("utf-8")
    ).hexdigest()
    return records / f"{digest}.json"


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key in lifecycle record: {key}")
        result[key] = value
    return result


def authenticate(record: dict[str, Any], key: bytes, path: Path) -> None:
    expected_keys = {
        1: RECORD_KEYS_V1,
        2: RECORD_KEYS_V2,
    }.get(record.get("schemaVersion"))
    if expected_keys is None or set(record) != expected_keys:
        fail(f"lifecycle record has an unexpected schema: {path}")
    supplied = record.get("auth")
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{64}", supplied):
        fail(f"lifecycle record has an invalid authenticator: {path}")
    payload = dict(record)
    del payload["auth"]
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        fail(f"lifecycle record authentication failed: {path}")


def validate_record(record: dict[str, Any], path: Path, records: Path) -> None:
    if record["schemaVersion"] not in {1, 2}:
        fail(f"unsupported lifecycle record version: {path}")
    for label in ("team", "instance"):
        value = record[label]
        if not isinstance(value, str):
            fail(f"lifecycle record {label} must be a string: {path}")
        validate_identifier(label, value)
    if record["category"] not in {"gate", "task", "release"}:
        fail(f"lifecycle record has an invalid category: {path}")
    if record["kind"] not in {"background", "tmux"}:
        fail(f"lifecycle record has an invalid process kind: {path}")
    if not isinstance(record["pid"], int) or isinstance(record["pid"], bool) or record["pid"] <= 1:
        fail(f"lifecycle record has an unsafe PID: {path}")
    if not isinstance(record["processIdentity"], str) or not record["processIdentity"]:
        fail(f"lifecycle record has no process identity: {path}")
    if not isinstance(record["launchToken"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", record["launchToken"]
    ):
        fail(f"lifecycle record has an invalid launch token: {path}")
    if not isinstance(record["createdAt"], str) or not record["createdAt"].endswith("Z"):
        fail(f"lifecycle record has an invalid creation time: {path}")
    tmux_values = (record["tmuxSession"], record["tmuxWindow"], record["tmuxPane"])
    if record["kind"] == "tmux":
        if not all(isinstance(value, str) and value for value in tmux_values):
            fail(f"tmux lifecycle record is missing its protected target: {path}")
    elif any(value is not None for value in tmux_values):
        fail(f"background lifecycle record contains a tmux target: {path}")
    if record["schemaVersion"] == 2:
        group_values = (record["processGroupId"], record["sessionId"])
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 1
            for value in group_values
        ):
            fail(f"lifecycle record has an unsafe process group: {path}")
        if group_values != (record["pid"], record["pid"]):
            fail(f"lifecycle process group is not a dedicated session: {path}")
        pane_pid = record["tmuxPanePid"]
        if record["kind"] == "tmux":
            if not isinstance(pane_pid, int) or isinstance(pane_pid, bool) or pane_pid <= 1:
                fail(f"tmux lifecycle record has an unsafe pane PID: {path}")
        elif pane_pid is not None:
            fail(f"background lifecycle record must not claim a tmux pane PID: {path}")
    expected = record_path(records, record["team"], record["category"], record["instance"])
    if expected.name != path.name:
        fail(f"lifecycle record filename does not match its identity: {path}")


def load_record(path: Path, records: Path, key: bytes) -> dict[str, Any]:
    raw = read_secure(path, expected_mode=0o600, maximum=16384)
    try:
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"invalid lifecycle record JSON at {path}: {exc}")
    if not isinstance(record, dict):
        fail(f"lifecycle record must be a JSON object: {path}")
    authenticate(record, key, path)
    validate_record(record, path, records)
    return record


def process_identity(pid: int) -> str | None:
    if pid <= 1:
        return None
    proc_stat = Path(f"/proc/{pid}/stat")
    if proc_stat.exists():
        try:
            raw = proc_stat.read_text(encoding="ascii")
            closing = raw.rfind(")")
            fields = raw[closing + 2 :].split()
            start_ticks = fields[19]
            try:
                boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                    encoding="ascii"
                ).strip()
            except OSError:
                boot_id = "unknown-boot"
            return f"linux:{boot_id}:{start_ticks}"
        except (OSError, IndexError, ValueError):
            return None

    if sys.platform == "darwin":
        # Darwin's ps(1) start time is only second precision.  proc_pidinfo
        # exposes the kernel's microsecond start timestamp, which makes the
        # identity robust against rapid PID reuse.
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

        try:
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            proc_pidinfo = libproc.proc_pidinfo
            proc_pidinfo.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            proc_pidinfo.restype = ctypes.c_int
            info = ProcBsdInfo()
            returned = proc_pidinfo(
                pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)
            )
            if returned == ctypes.sizeof(info) and info.pbi_pid == pid:
                return (
                    f"darwin:{info.pbi_start_tvsec}:"
                    f"{info.pbi_start_tvusec}"
                )
        except (AttributeError, OSError):
            return None
        return None

    ps = "/bin/ps" if Path("/bin/ps").is_file() else "/usr/bin/ps"
    try:
        result = subprocess.run(
            [ps, "-o", "lstart=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
            env={"PATH": "/usr/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    line = " ".join(result.stdout.split())
    if result.returncode != 0 or not line:
        return None
    return f"ps:{line}"


def group_exists(process_group_id: int) -> bool:
    if not hasattr(os, "killpg"):
        fail("process-group supervision is unavailable on this platform")
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Existence is established, but an actual signal will still fail
        # closed rather than being redirected to leader-only authority.
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        fail(f"cannot verify protected process group {process_group_id}: {exc}")


def leader_matches_group(record: dict[str, Any], identity: str | None) -> bool:
    if identity is None:
        return True
    if not hmac.compare_digest(identity, record["processIdentity"]):
        return False
    try:
        return (
            os.getpgid(record["pid"]) == record["processGroupId"]
            and os.getsid(record["pid"]) == record["sessionId"]
        )
    except ProcessLookupError:
        # The leader exited between its start-identity and group checks.  The
        # dedicated group remains authoritative while any child still exists.
        return True
    except OSError as exc:
        fail(f"cannot verify protected process-group leader: {exc}")


def record_state(record: dict[str, Any]) -> str:
    current = process_identity(record["pid"])
    if record["schemaVersion"] == 2:
        if not leader_matches_group(record, current):
            return "identity-mismatch"
        return "live" if group_exists(record["processGroupId"]) else "dead"
    if current is None:
        return "dead"
    if not hmac.compare_digest(current, record["processIdentity"]):
        return "identity-mismatch"
    return "live"


def signed(payload: dict[str, Any], key: bytes) -> dict[str, Any]:
    record = dict(payload)
    record["auth"] = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    return record


def atomic_write(path: Path, record: dict[str, Any]) -> None:
    data = canonical(record) + b"\n"
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".record-", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def find_record(
    records: Path, key: bytes, team: str, category: str, instance: str
) -> tuple[Path, dict[str, Any]] | None:
    path = record_path(records, team, category, instance)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return path, load_record(path, records, key)


def all_records(records: Path, key: bytes) -> list[tuple[Path, dict[str, Any]]]:
    result: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(records.glob("*.json")):
        result.append((path, load_record(path, records, key)))
    return result


def safe_signal(record: dict[str, Any], signal_number: int) -> None:
    pid = record["pid"]
    pidfd: int | None = None
    if hasattr(os, "pidfd_open"):
        try:
            pidfd = os.pidfd_open(pid, 0)
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                raise SystemExit(NOT_LIVE)
            fail(f"cannot open a stable handle for lifecycle PID {pid}: {exc}")
    try:
        current = process_identity(pid)
        if current is None:
            raise SystemExit(NOT_LIVE)
        if not hmac.compare_digest(current, record["processIdentity"]):
            fail(
                f"refusing to signal PID {pid}: protected process identity no longer matches"
            )
        if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
            signal.pidfd_send_signal(pidfd, signal_number)
        else:
            # Recheck immediately before the non-pidfd fallback.  Darwin has no
            # pidfd, so the stored start time is the binding available there.
            second = process_identity(pid)
            if second is None or not hmac.compare_digest(second, record["processIdentity"]):
                fail(f"refusing to signal PID {pid}: process identity changed")
            os.kill(pid, signal_number)
    finally:
        if pidfd is not None:
            os.close(pidfd)


def safe_signal_group(record: dict[str, Any], signal_number: int) -> None:
    if record["schemaVersion"] != 2:
        fail("legacy lifecycle record has no authenticated process-group authority")
    if record["kind"] not in {"background", "tmux"}:
        fail("unsupported process kind for process-group authority")
    process_group_id = record["processGroupId"]
    session_id = record["sessionId"]
    if process_group_id != record["pid"] or session_id != record["pid"]:
        fail("refusing non-dedicated process-group authority")

    # A process group belongs to exactly one session for its entire lifetime.
    # Binding a newly created group and session to the authenticated leader PID
    # therefore continues to identify descendants after the leader exits.
    current = process_identity(record["pid"])
    if not leader_matches_group(record, current):
        fail("refusing to signal process group: protected leader identity changed")
    if not group_exists(process_group_id):
        raise SystemExit(NOT_LIVE)

    # Recheck immediately before killpg.  This is the cross-platform POSIX
    # equivalent of the leader pidfd guard: no workspace PID/PGID participates,
    # and a live dedicated group cannot be reused by another session.
    second = process_identity(record["pid"])
    if not leader_matches_group(record, second):
        fail("refusing to signal process group after leader identity changed")
    if not group_exists(process_group_id):
        raise SystemExit(NOT_LIVE)
    try:
        os.killpg(process_group_id, signal_number)
    except ProcessLookupError:
        raise SystemExit(NOT_LIVE)
    except OSError as exc:
        fail(f"cannot signal protected process group {process_group_id}: {exc}")


def base_context(args: argparse.Namespace) -> tuple[Path, Path, bytes]:
    return initialize(args.root, args.repo)


def enforce_expected_generation(record: dict[str, Any], args: argparse.Namespace) -> None:
    expected_created = getattr(args, "expected_created_at", None)
    if expected_created is not None and record.get("createdAt") != expected_created:
        fail("protected lifecycle generation changed before the requested action")
    if not getattr(args, "expect_token_stdin", False):
        return
    expected_token = sys.stdin.readline().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_token):
        fail("expected lifecycle token on stdin is malformed")
    if not hmac.compare_digest(str(record.get("launchToken") or ""), expected_token):
        fail("protected lifecycle generation changed before the requested action")


def cmd_init(args: argparse.Namespace) -> int:
    root, _, _ = base_context(args)
    print(root)
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    _, records, key = base_context(args)
    validate_identifier("team", args.team)
    validate_identifier("instance", args.instance)
    identity = process_identity(args.pid)
    if identity is None:
        fail(f"cannot register PID {args.pid}: process is not live")
    path = record_path(records, args.team, args.category, args.instance)
    if path.exists():
        existing = load_record(path, records, key)
        if record_state(existing) == "live":
            fail(
                f"refusing to replace a live lifecycle record for {args.team}/{args.instance}"
            )
    if args.kind == "tmux":
        if not (
            args.tmux_session
            and args.tmux_window
            and args.tmux_pane
            and isinstance(args.tmux_pane_pid, int)
            and not isinstance(args.tmux_pane_pid, bool)
            and args.tmux_pane_pid > 1
        ):
            fail("tmux registration requires session, window, pane, and pane PID identities")
    elif args.tmux_session or args.tmux_window or args.tmux_pane or args.tmux_pane_pid:
        fail("background registration must not contain tmux identities")
    process_group_id: int | None = None
    session_id: int | None = None
    if args.kind in {"background", "tmux"}:
        # The launcher calls setsid before waiting on its launch barrier.  Give
        # that trusted wrapper a short scheduling window, while refusing any
        # ordinary/shared process group rather than widening signal authority.
        for _ in range(100):
            current = process_identity(args.pid)
            if current is None:
                fail(f"cannot bind process group: PID {args.pid} exited")
            if not hmac.compare_digest(current, identity):
                fail(f"cannot bind process group: PID {args.pid} identity changed")
            try:
                process_group_id = os.getpgid(args.pid)
                session_id = os.getsid(args.pid)
            except ProcessLookupError:
                fail(f"cannot bind process group: PID {args.pid} exited")
            if process_group_id == args.pid and session_id == args.pid:
                break
            time.sleep(0.01)
        else:
            fail("lifecycle process must lead a dedicated process group and session")
    payload: dict[str, Any] = {
        "schemaVersion": 2,
        "team": args.team,
        "category": args.category,
        "instance": args.instance,
        "kind": args.kind,
        "pid": args.pid,
        "processIdentity": identity,
        "launchToken": secrets.token_hex(32),
        "createdAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tmuxSession": args.tmux_session,
        "tmuxWindow": args.tmux_window,
        "tmuxPane": args.tmux_pane,
        "processGroupId": process_group_id,
        "sessionId": session_id,
        "tmuxPanePid": args.tmux_pane_pid,
    }
    record = signed(payload, key)
    atomic_write(path, record)
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    _, records, key = base_context(args)
    found = find_record(records, key, args.team, args.category, args.instance)
    if found is None:
        return NOT_LIVE
    _, record = found
    enforce_expected_generation(record, args)
    if record_state(record) != "live":
        return NOT_LIVE
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    _, records, key = base_context(args)
    for _, record in all_records(records, key):
        if record["team"] != args.team:
            continue
        view = dict(record)
        view["state"] = record_state(record)
        del view["auth"]
        del view["launchToken"]
        print(json.dumps(view, sort_keys=True, separators=(",", ":")))
    return 0


def cmd_any_live(args: argparse.Namespace) -> int:
    _, records, key = base_context(args)
    needle = f"--{args.task_key}--a" if args.task_key else None
    for _, record in all_records(records, key):
        if record["team"] != args.team or record["category"] != args.category:
            continue
        if needle is not None and needle not in record["instance"]:
            continue
        if record_state(record) == "live":
            return 0
    return NOT_LIVE


def cmd_verify(args: argparse.Namespace) -> int:
    _, records, key = base_context(args)
    found = find_record(records, key, args.team, args.category, args.instance)
    if found is None:
        return NOT_LIVE
    _, record = found
    enforce_expected_generation(record, args)
    state = record_state(record)
    if state == "dead":
        return NOT_LIVE
    if state == "identity-mismatch":
        fail(
            f"refusing lifecycle authority for {args.team}/{args.instance}: process identity mismatch"
        )
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


def cmd_signal(args: argparse.Namespace) -> int:
    _, records, key = base_context(args)
    found = find_record(records, key, args.team, args.category, args.instance)
    if found is None:
        return NOT_LIVE
    _, record = found
    enforce_expected_generation(record, args)
    signal_number = {
        "TERM": signal.SIGTERM,
        "KILL": signal.SIGKILL,
    }.get(args.signal_name)
    if signal_number is None:
        fail("unsupported lifecycle signal")
    safe_signal_group(record, signal_number)
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    _, records, key = base_context(args)
    found = find_record(records, key, args.team, args.category, args.instance)
    if found is None:
        return 0
    path, record = found
    enforce_expected_generation(record, args)
    state = record_state(record)
    if state == "live":
        fail(f"refusing to forget a live lifecycle record for {args.team}/{args.instance}")
    if state == "identity-mismatch" and not args.allow_identity_mismatch:
        fail(
            f"refusing to forget {args.team}/{args.instance}: process identity mismatch"
        )
    path.unlink()
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subcommands = result.add_subparsers(dest="command", required=True)

    def common(command: str) -> argparse.ArgumentParser:
        child = subcommands.add_parser(command)
        child.add_argument("--root", required=True)
        child.add_argument("--repo", required=True)
        return child

    common("init").set_defaults(handler=cmd_init)

    register = common("register")
    register.add_argument("--team", required=True)
    register.add_argument("--category", required=True, choices=("gate", "task", "release"))
    register.add_argument("--instance", required=True)
    register.add_argument("--kind", required=True, choices=("background", "tmux"))
    register.add_argument("--pid", required=True, type=int)
    register.add_argument("--tmux-session")
    register.add_argument("--tmux-window")
    register.add_argument("--tmux-pane")
    register.add_argument("--tmux-pane-pid", type=int)
    register.set_defaults(handler=cmd_register)

    for name, handler in (("probe", cmd_probe), ("verify", cmd_verify)):
        child = common(name)
        child.add_argument("--team", required=True)
        child.add_argument("--category", required=True, choices=("gate", "task", "release"))
        child.add_argument("--instance", required=True)
        child.add_argument("--expect-token-stdin", action="store_true")
        child.set_defaults(handler=handler)

    listing = common("list")
    listing.add_argument("--team", required=True)
    listing.set_defaults(handler=cmd_list)

    any_live = common("any-live")
    any_live.add_argument("--team", required=True)
    any_live.add_argument("--category", required=True, choices=("gate", "task", "release"))
    any_live.add_argument("--task-key")
    any_live.set_defaults(handler=cmd_any_live)

    signalling = common("signal")
    signalling.add_argument("--team", required=True)
    signalling.add_argument("--category", required=True, choices=("gate", "task", "release"))
    signalling.add_argument("--instance", required=True)
    signalling.add_argument("--expect-token-stdin", action="store_true")
    signalling.add_argument(
        "--signal", dest="signal_name", choices=("TERM", "KILL"), default="TERM"
    )
    signalling.set_defaults(handler=cmd_signal)

    forget = common("forget")
    forget.add_argument("--team", required=True)
    forget.add_argument("--category", required=True, choices=("gate", "task", "release"))
    forget.add_argument("--instance", required=True)
    forget.add_argument("--expect-token-stdin", action="store_true")
    forget.add_argument("--expected-created-at")
    forget.add_argument("--allow-identity-mismatch", action="store_true")
    forget.set_defaults(handler=cmd_forget)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.handler(args))
    except LifecycleError as exc:
        print(f"process-lifecycle: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
