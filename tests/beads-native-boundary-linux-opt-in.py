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


def strict_json(raw: bytes, label: str) -> object:
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
    if not isinstance(value, (dict, list)):
        raise SystemExit(f"{label} did not return one JSON object or array")
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
operator_key = controller._read_operator_key()
controller.verify_operator_lifecycle_v1(config, operator_key, require_active=True)
controller._verify_installed_artifacts(config)
manifest_raw = controller._read_root_owned(
    config.native_boundary_manifest_path, "installed V27 manifest"
)
manifest = boundary.parse_native_boundary_manifest_v27(json.loads(manifest_raw))

for path, expected, label in (
    (manifest.supervisor_path, manifest.supervisor_sha256, "native supervisor"),
    (manifest.podman_path, manifest.podman_sha256, "Podman"),
    (manifest.conmon_path, manifest.conmon_sha256, "conmon"),
):
    if controller._sha(controller._read_root_owned(path, label, executable=True)) != expected:
        raise SystemExit(f"{label} digest differs from the V27 manifest")
policy_path = Path("/sys/fs/selinux/policy")
if controller._sha(
    controller._read_root_owned(
        policy_path, "SELinux policy", max_bytes=64 * 1024 * 1024
    )
) != manifest.selinux_policy_sha256:
    raise SystemExit("loaded SELinux policy digest differs from the V27 manifest")

# A non-broker/non-controller/non-worker account must not even connect to the
# protected endpoint or read any protected authority/key root.
agent = pwd.getpwnam("nobody")
if agent.pw_uid in {0, config.controller_uid, config.broker_uid, config.worker_uid}:
    raise SystemExit("nobody is not a distinct agent denial identity")
agent_pid = os.fork()
if agent_pid == 0:
    try:
        os.setgroups([])
        os.setgid(agent.pw_gid)
        os.setuid(agent.pw_uid)
        for forbidden in (
            config.protected_root,
            config.record_hmac_key_path,
            controller.CONTROLLER_KEY_PATH,
            controller.OPERATOR_KEY_PATH,
        ):
            try:
                descriptor = os.open(forbidden, os.O_RDONLY | os.O_NOFOLLOW)
            except PermissionError:
                continue
            else:
                os.close(descriptor)
                os._exit(91)
        denied = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            denied.connect(str(controller.ENDPOINT_PATH))
        except PermissionError:
            os._exit(0)
        os._exit(92)
    except BaseException:
        os._exit(93)
_, agent_status = os.waitpid(agent_pid, 0)
if not os.WIFEXITED(agent_status) or os.WEXITSTATUS(agent_status) != 0:
    raise SystemExit("unprivileged agent denial fixture failed")

fixture_root = Path(tempfile.mkdtemp(prefix="startup-factory-beads-v27-"))
workspace = fixture_root / "workspace"
state_root = fixture_root / "state"
workspace.mkdir(mode=0o700)
state_root.mkdir(mode=0o700)
account = pwd.getpwuid(config.worker_uid)
for path in (fixture_root, workspace, state_root):
    os.chown(path, account.pw_uid, account.pw_gid)
    os.chmod(path, 0o700)

# Permanently enter the production worker identity. All probes and every real
# Podman/bd lifecycle below run after this point and cannot regain root.
os.environ.clear()
os.environ.update(
    {
        "HOME": account.pw_dir,
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin",
        "USER": account.pw_name,
        "XDG_RUNTIME_DIR": f"/run/user/{config.worker_uid}",
    }
)
os.setgroups([])
os.setgid(account.pw_gid)
os.setuid(account.pw_uid)
controller._assert_worker_dac_isolation_v27(config)

supervisor_observation = boundary.verify_local_platform_gate_v27(
    manifest, expected_worker_uid=config.worker_uid
)
boundary.validate_native_supervisor_probe_v27(supervisor_observation, manifest)

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

# Run four genuine bd invocations. Each one traverses sealed-plan FD3 and the
# exact Podman create -> init -> start/attach -> terminal -> cleanup -> rm path.
commands = (
    ["/usr/local/bin/bd", "version", "--json"],
    [
        "/usr/local/bin/bd",
        "--db",
        "/workspace/db",
        "--json",
        "--sandbox",
        "init",
    ],
    [
        "/usr/local/bin/bd",
        "--db",
        "/workspace/db",
        "--json",
        "--sandbox",
        "config",
        "set",
        "status.custom",
        "open,closed",
    ],
    [
        "/usr/local/bin/bd",
        "--db",
        "/workspace/db",
        "--json",
        "--sandbox",
        "config",
        "list",
    ],
)
fixture_key = os.urandom(32)
for ordinal, argv in enumerate(commands, 1):
    operation_id = f"{ordinal:064x}"
    plan = boundary.reference_supervised_effect_plan_v27(
        manifest,
        operation_id=operation_id,
        operation_class="create-preparation",
        argv=argv,
        repository_path=str(workspace),
    )
    captured = []

    def genuine_runner(observed_manifest, observed_plan):
        raw = boundary.run_native_supervisor_v27(observed_manifest, observed_plan)
        captured.append(raw)
        return raw

    result = boundary.execute_supervised_effect_v27(
        state_root, fixture_key, manifest, plan, runner=genuine_runner
    )
    if result["exitCode"] != 0 or len(captured) != 1:
        raise SystemExit(f"genuine bd lifecycle {ordinal} did not complete exactly once")
    strict_json(captured[0]["stdout"], f"genuine bd lifecycle {ordinal}")

# A real child death after the authenticated result object is fsynced must
# recover only the durable suffix and must never relaunch Podman.
crash_plan = boundary.reference_supervised_effect_plan_v27(
    manifest,
    operation_id="f" * 64,
    operation_class="ordinary",
    argv=["/usr/local/bin/bd", "version", "--json"],
    repository_path=str(workspace),
)
crash_pid = os.fork()
if crash_pid == 0:
    try:
        with boundary.inject_native_effect_fault_v27("result-object-written"):
            boundary.execute_supervised_effect_v27(
                state_root, fixture_key, manifest, crash_plan
            )
    except SystemExit:
        os._exit(91)
    except BaseException:
        os._exit(93)
    os._exit(92)
_, crash_status = os.waitpid(crash_pid, 0)
if not os.WIFEXITED(crash_status) or os.WEXITSTATUS(crash_status) != 91:
    raise SystemExit("real V27 process-death fixture did not stop at the bound phase")

def forbidden_replay(_manifest, _plan):
    raise SystemExit("stored-result recovery attempted to replay Podman")

recovered = boundary.execute_supervised_effect_v27(
    state_root, fixture_key, manifest, crash_plan, runner=forbidden_replay
)
if recovered["exitCode"] != 0:
    raise SystemExit("stored-result suffix recovery did not preserve the terminal result")

print(
    "external protected Beads V27 Linux full lifecycle: PASS "
    "(worker UID, agent denial, four real bd/Podman lifecycles, process death and "
    "no-replay recovery; evidence only, readiness is not promoted)"
)
