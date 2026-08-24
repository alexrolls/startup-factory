#!/usr/bin/env python3
"""Opt-in genuine Linux proof for the protected Beads V27 native boundary.

The offline suite runs this file only to observe its explicit SKIP. Operators
run it on the exact disposable systemd-254/SELinux host after installing the
root-owned controller, V27 manifest, native supervisor, Podman and conmon.
Passing is external evidence; it never promotes Startup Factory readiness.
"""

from __future__ import annotations

import fcntl
import json
import os
import pwd
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path


if os.environ.get("STARTUP_FACTORY_REAL_BEADS_NATIVE_V27_PROBE") != "1":
    print(
        "SKIP: external V27 gate remains non-green; set "
        "STARTUP_FACTORY_REAL_BEADS_NATIVE_V27_PROBE=1 only on the "
        "operator-provisioned disposable Linux fixture"
    )
    raise SystemExit(0)

if not sys.platform.startswith("linux") or os.geteuid() != 0:
    raise SystemExit("V27 proof requires an operator-provisioned Linux root harness")

from startup_factory_cli import beads_boundary_controller as controller  # noqa: E402
from startup_factory_cli import beads_native_boundary_v27 as boundary  # noqa: E402


def strict_json(raw: bytes, label: str) -> dict:
    if not raw or len(raw) > boundary.MAX_CANONICAL_BYTES:
        raise SystemExit(f"{label} returned empty or oversized JSON")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"{label} returned malformed/duplicate JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} did not return one JSON object")
    return value


def fixed_run(argv: list[str], *, as_uid: int | None = None) -> bytes:
    if not argv or any(type(item) is not str or not item or "\0" in item for item in argv):
        raise SystemExit("probe constructed invalid argv")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    before = None
    if as_uid is not None:
        account = pwd.getpwuid(as_uid)
        environment["HOME"] = account.pw_dir
        environment["USER"] = account.pw_name
        environment["LOGNAME"] = account.pw_name
        environment["XDG_RUNTIME_DIR"] = f"/run/user/{as_uid}"

        def before() -> None:
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

    completed = subprocess.run(
        argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=30,
        check=False,
        preexec_fn=before,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"fixed probe argv {argv!r} failed rc={completed.returncode}: "
            f"{completed.stderr[:512]!r}"
        )
    return completed.stdout


config = controller.load_controller_config()
if not config.beads_enabled:
    raise SystemExit("beadsEnabled is false; the operator has not enabled this gate")
controller._verify_installed_artifacts(config)
manifest_raw = controller._read_root_owned(
    config.native_boundary_manifest_path, "installed V27 manifest"
)
manifest = boundary.parse_native_boundary_manifest_v27(json.loads(manifest_raw))

systemd = fixed_run(["/usr/bin/systemd", "--version"]).splitlines()[0]
if systemd != b"systemd 254 (254)" and not systemd.startswith(b"systemd 254 "):
    raise SystemExit(f"systemd version differs from exact 254 fixture: {systemd!r}")
podman_version = fixed_run([str(manifest.podman_path), "--version"]).strip()
if podman_version != b"podman version 5.4.1":
    raise SystemExit(f"Podman version differs from exact 5.4.1 fixture: {podman_version!r}")
conmon_version = fixed_run([str(manifest.conmon_path), "--version"]).splitlines()[0]
if b"2.1.12" not in conmon_version:
    raise SystemExit(f"conmon version differs from exact 2.1.12 fixture: {conmon_version!r}")
if fixed_run(["/usr/sbin/getenforce"]).strip() != b"Enforcing":
    raise SystemExit("SELinux is not enforcing")

for path, expected, label in (
    (manifest.supervisor_path, manifest.supervisor_sha256, "native supervisor"),
    (manifest.podman_path, manifest.podman_sha256, "Podman"),
    (manifest.conmon_path, manifest.conmon_sha256, "conmon"),
):
    if controller._sha(controller._read_root_owned(path, label, executable=True)) != expected:
        raise SystemExit(f"{label} digest differs from the V27 manifest")
policy_path = Path("/sys/fs/selinux/policy")
if controller._sha(controller._read_root_owned(policy_path, "SELinux policy")) != manifest.selinux_policy_sha256:
    raise SystemExit("loaded SELinux policy digest differs from the V27 manifest")

podman_info = strict_json(
    fixed_run([str(manifest.podman_path), "info", "--format", "json"], as_uid=config.worker_uid),
    "rootless Podman info",
)
try:
    if podman_info["host"]["security"]["rootless"] is not True:
        raise KeyError("rootless")
except (KeyError, TypeError) as exc:
    raise SystemExit("Podman info does not prove exact rootless execution") from exc

supervisor_observation = strict_json(
    fixed_run([str(manifest.supervisor_path), "--startup-factory-probe-v27"]),
    "native supervisor",
)
boundary.validate_platform_observation_v27(supervisor_observation, manifest)

left, right = socket.socketpair(
    socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC, 0
)
try:
    left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    right.send(b"x" * 128)
    data, ancillary, flags, _ = left.recvmsg(128, socket.CMSG_SPACE(12))
    credentials = sum(
        level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
        for level, kind, _payload in ancillary
    )
    boundary.validate_seqpacket_observation_v27(
        {
            "packetLength": len(data),
            "msgTrunc": bool(flags & socket.MSG_TRUNC),
            "msgCtrunc": bool(flags & socket.MSG_CTRUNC),
            "zeroLengthRecord": len(data) == 0,
            "credentialsCount": credentials,
            "rightsCount": sum(kind == socket.SCM_RIGHTS for _level, kind, _ in ancillary),
            "extraQueuedRecord": False,
            "peerEof": False,
        },
        expected_length=128,
    )
finally:
    left.close()
    right.close()

memfd = os.memfd_create("startup-factory-v27-key", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
try:
    key = os.urandom(32)
    os.write(memfd, key)
    fcntl.fcntl(
        memfd,
        fcntl.F_ADD_SEALS,
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL,
    )
    os.lseek(memfd, 0, os.SEEK_SET)
    boundary.verify_live_sealed_key_material_v27(
        memfd, expected_sha256=boundary.sha256(key)
    )
finally:
    os.close(memfd)

with tempfile.NamedTemporaryFile() as operation_lock:
    result, captured_errno = boundary.try_operation_lock_v27(operation_lock.fileno())
    if (result, captured_errno) != ("acquired", 0):
        raise SystemExit("the genuine OFD operation-lock fixture did not acquire exactly once")

print(
    "external protected Beads V27 Linux fixture: PASS "
    "(evidence only; readiness is not promoted and release remains operator-gated)"
)
