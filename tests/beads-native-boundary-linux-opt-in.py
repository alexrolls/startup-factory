#!/usr/bin/env python3
"""External installed-service proof for the protected Beads V27 boundary.

This is intentionally skipped by the offline suite.  It runs only on the
operator-provisioned disposable systemd-254/SELinux/Podman-5.4.1 fixture.  The
fixture manifest names already-authorized public API requests; it contains no
credentials and grants no authority.  Passing remains evidence, not readiness.
"""

from __future__ import annotations

import json
import os
import pwd
import socket
import stat
import subprocess
import sys
import time
import hashlib
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

import startup_factory_cli.beads_boundary_controller as controller  # noqa: E402
import startup_factory_cli.beads_protected_runtime as runtime  # noqa: E402


UNIT = "startup-factory-beads-controller.service"
MANIFEST_ENV = "STARTUP_FACTORY_REAL_BEADS_PUBLIC_FIXTURE"


def fixed_run(argv: list[str], *, timeout: int = 30) -> bytes:
    completed = subprocess.run(
        argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"fixed fixture argv failed rc={completed.returncode}: {completed.stderr[:512]!r}"
        )
    return completed.stdout


def policy_search(*arguments: str) -> bytes:
    return fixed_run(["/usr/bin/sesearch", *arguments])


def require_policy_rule(label: str, *arguments: str) -> None:
    observed = policy_search(*arguments)
    if not observed.strip():
        raise SystemExit(f"loaded SELinux policy lacks {label}")


def require_policy_absence(label: str, *arguments: str) -> None:
    observed = policy_search(*arguments)
    if observed.strip():
        raise SystemExit(f"loaded SELinux policy unexpectedly grants {label}")


def verify_loaded_selinux_policy(manifest) -> None:
    if fixed_run(["/usr/sbin/getenforce"]) != b"Enforcing\n":
        raise SystemExit("external V27 policy probe requires enforcing SELinux")
    capability = Path(
        "/sys/fs/selinux/policy_capabilities/nnp_nosuid_transition"
    ).read_bytes()
    if capability not in {b"1", b"1\n"}:
        raise SystemExit("loaded policy lacks nnp_nosuid_transition policycap")
    loaded = controller.native_boundary_v27._selinux_policy_bytes()
    if "sha256:" + hashlib.sha256(loaded).hexdigest() != manifest.selinux_policy_sha256:
        raise SystemExit("loaded SELinux binary differs from the pinned manifest")
    modules = fixed_run(["/usr/sbin/semodule", "-lfull"]).decode("utf-8").splitlines()
    matching = [
        line for line in modules
        if "startup_factory_beads_v27" in line.split()
    ]
    if len(matching) != 1:
        raise SystemExit("installed V27 SELinux module identity is absent or duplicated")

    result_root = Path("/run/user/993/startup-factory-beads-results")
    result_metadata = os.lstat(result_root)
    if (
        stat.S_ISLNK(result_metadata.st_mode)
        or not stat.S_ISDIR(result_metadata.st_mode)
        or result_metadata.st_uid != 993
        or stat.S_IMODE(result_metadata.st_mode) != 0o700
    ):
        raise SystemExit("UID 993 result root type/owner/mode is not exact")
    expected_result_context = b"system_u:object_r:beads_runtime_result_t:s0"
    if fixed_run(["/usr/bin/matchpathcon", "-n", str(result_root)]).strip() != expected_result_context:
        raise SystemExit("installed file-context policy does not map the UID 993 result root")
    if fixed_run(["/usr/bin/stat", "-c", "%C", str(result_root)]).strip() != expected_result_context:
        raise SystemExit("UID 993 result root was not actually restored to the pinned label")

    for controller_type in (
        "beads_controller_t",
        "startup_factory_beads_controller_t",
    ):
        for permission in (
            "add_name", "create", "getattr", "open", "read", "remove_name",
            "rmdir", "search", "write",
        ):
            require_policy_rule(
                f"{controller_type} delegated cgroup directory {permission}",
                "--allow", "-s", controller_type, "-t", "cgroup_t",
                "-c", "dir", "-p", permission,
            )
        for permission in ("getattr", "open", "read", "write"):
            require_policy_rule(
                f"{controller_type} delegated cgroup control file {permission}",
                "--allow", "-s", controller_type, "-t", "cgroup_t",
                "-c", "file", "-p", permission,
            )
        for permission in ("mount", "remount", "unmount"):
            require_policy_absence(
                f"{controller_type} cgroup filesystem {permission}",
                "--allow", "-s", controller_type, "-t", "cgroup_t",
                "-c", "filesystem", "-p", permission,
            )
        for object_class in ("dir", "file"):
            for permission in ("relabelfrom", "relabelto"):
                require_policy_absence(
                    f"{controller_type} cgroup {object_class} {permission}",
                    "--allow", "-s", controller_type, "-t", "cgroup_t",
                    "-c", object_class, "-p", permission,
                )

    automatic_edges = (
        (
            "startup_factory_beads_controller_t",
            "startup_factory_beads_conmon_exec_t",
            "startup_factory_beads_conmon_t",
        ),
        (
            "startup_factory_beads_controller_t",
            "startup_factory_beads_runtime_exec_t",
            "startup_factory_beads_runtime_t",
        ),
        (
            "startup_factory_beads_conmon_t",
            "startup_factory_beads_runtime_exec_t",
            "startup_factory_beads_runtime_t",
        ),
    )
    for source, executable, target in automatic_edges:
        for permission in ("getattr", "read", "open", "map", "execute"):
            require_policy_rule(
                f"{source} executable {permission}",
                "--allow", "-s", source, "-t", executable,
                "-c", "file", "-p", permission,
            )
        require_policy_rule(
            f"{target} executable entrypoint",
            "--allow", "-s", target, "-t", executable,
            "-c", "file", "-p", "entrypoint",
        )
        require_policy_rule(
            f"{source}->{target} process transition",
            "--allow", "-s", source, "-t", target,
            "-c", "process", "-p", "transition",
        )
        require_policy_rule(
            f"{source}->{target} NNP transition",
            "--allow", "-s", source, "-t", target,
            "-c", "process2", "-p", "nnp_transition",
        )
        require_policy_rule(
            f"{source}->{target} automatic type transition",
            "--type_trans", "-s", source, "-t", executable,
            "-c", "process",
        )

    runtime_type = "startup_factory_beads_runtime_t"
    payload_type = "startup_factory_beads_payload_t"
    payload_exec = "startup_factory_beads_payload_exec_t"
    for permission in ("getattr", "read", "open", "map", "execute"):
        require_policy_rule(
            f"runtime payload executable {permission}",
            "--allow", "-s", runtime_type, "-t", payload_exec,
            "-c", "file", "-p", permission,
        )
    require_policy_rule(
        "payload executable entrypoint",
        "--allow", "-s", payload_type, "-t", payload_exec,
        "-c", "file", "-p", "entrypoint",
    )
    require_policy_rule(
        "runtime payload process transition",
        "--allow", "-s", runtime_type, "-t", payload_type,
        "-c", "process", "-p", "transition",
    )
    for permission in ("nnp_transition", "nosuid_transition"):
        require_policy_rule(
            f"runtime payload {permission}",
            "--allow", "-s", runtime_type, "-t", payload_type,
            "-c", "process2", "-p", permission,
        )
    require_policy_rule(
        "runtime self setexec",
        "--allow", "-s", runtime_type, "-t", runtime_type,
        "-c", "process", "-p", "setexec",
    )
    require_policy_absence(
        "runtime payload automatic transition",
        "--type_trans", "-s", runtime_type, "-t", payload_exec,
        "-c", "process",
    )

    conmon_type = "startup_factory_beads_conmon_t"
    podman_exec = "startup_factory_beads_podman_exec_t"
    for permission in ("execute", "execute_no_trans"):
        require_policy_absence(
            f"conmon Podman {permission}",
            "--allow", "-s", conmon_type, "-t", podman_exec,
            "-c", "file", "-p", permission,
        )
    require_policy_absence(
        "conmon Podman automatic transition",
        "--type_trans", "-s", conmon_type, "-t", podman_exec,
        "-c", "process",
    )
    require_policy_absence(
        "conmon self setexec",
        "--allow", "-s", conmon_type, "-t", conmon_type,
        "-c", "process", "-p", "setexec",
    )


def strict_manifest(path: Path) -> dict:
    raw = path.read_bytes()
    duplicate = False

    def pairs(items):
        nonlocal duplicate
        value = {}
        for key, item in items:
            if key in value:
                duplicate = True
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=pairs)
    if duplicate or not isinstance(value, dict) or runtime.canonical_bytes(value) + b"\n" != raw:
        raise SystemExit("external V27 public fixture manifest is not canonical closed JSON")
    if set(value) != {"prepare", "advance", "receipt", "expected"}:
        raise SystemExit("external V27 public fixture manifest shape changed")
    return value


def public_cycle_as_broker(config, fixture: dict) -> dict:
    """Use only installed public APIs after entering the configured broker UID."""

    account = pwd.getpwuid(config.broker_uid)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            os.environ.clear()
            os.environ.update(
                {
                    "HOME": account.pw_dir,
                    "LANG": "C",
                    "LC_ALL": "C",
                    "LOGNAME": account.pw_name,
                    "PATH": "/usr/bin:/bin",
                    "USER": account.pw_name,
                }
            )
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            prepared = runtime.prepare_atomic_claim_v1(
                runtime.PrepareAtomicClaimRequestV1(**fixture["prepare"])
            )
            advanced_request = dict(fixture["advance"])
            advanced_request["leaseRecordSha256"] = prepared.record_sha256
            # Hostile caller observations are deliberately bogus. Production
            # derives success/revision/status from four native read containers.
            advanced_request.update(
                {"claimSucceeded": False, "observedRevision": None, "observedStatus": None}
            )
            claimed = runtime.advance_atomic_claim_v1(
                runtime.AdvanceAtomicClaimRequestV1(**advanced_request)
            )
            receipt_request = dict(fixture["receipt"])
            receipt_request["leaseRecordSha256"] = claimed.record_sha256
            receipt_request.update(
                {
                    "readBackRevision": "caller-forgery",
                    "readBackStatus": "caller-forgery",
                    "claimIdentitySha256": "sha256:" + "0" * 64,
                }
            )
            receipt = runtime.record_atomic_claim_receipt_v1(
                runtime.RecordAtomicClaimReceiptRequestV1(**receipt_request)
            )
            result = {
                "claimState": claimed.payload["claimState"],
                "revision": receipt.payload["revision"],
                "status": receipt.payload["status"],
                "taskId": receipt.payload["taskId"],
            }
            os.write(write_fd, runtime.canonical_bytes(result))
            os._exit(0)
        except BaseException as exc:
            os.write(write_fd, str(exc).encode("utf-8")[:4096])
            os._exit(91)
    os.close(write_fd)
    raw = os.read(read_fd, runtime.MAX_CANONICAL_BYTES + 1)
    os.close(read_fd)
    _pid, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise SystemExit(f"installed public V27 cycle failed: {raw!r}")
    return json.loads(raw)


fixture_path = os.environ.get(MANIFEST_ENV)
if not fixture_path:
    raise SystemExit(f"set {MANIFEST_ENV} to the root-owned canonical fixture manifest")
fixture = strict_manifest(Path(fixture_path))
config = controller.load_controller_config()
if not config.beads_enabled:
    raise SystemExit("beadsEnabled is false; external gate remains non-green")
controller.verify_operator_lifecycle_v1(
    config, controller._read_operator_key(), require_active=True
)
installed_manifest = controller._verify_installed_artifacts(config)
verify_loaded_selinux_policy(installed_manifest)

# Start the packaged unit and prove the installed controller domain, rather
# than calling a Python/native helper directly.
fixed_run(["/usr/bin/systemctl", "start", UNIT])
fixed_run(["/usr/bin/systemctl", "is-active", "--quiet", UNIT])
properties = fixed_run(
    ["/usr/bin/systemctl", "show", UNIT, "--property=Delegate", "--property=DelegateSubgroup"]
)
if properties != b"Delegate=yes\nDelegateSubgroup=controller\n":
    raise SystemExit("packaged unit delegation differs from the closed topology")

# Independent agent denial: no protected roots, endpoint, lifecycle or worker
# handoff may become readable merely because the service is active.
agent = pwd.getpwnam("nobody")
agent_pid = os.fork()
if agent_pid == 0:
    os.setgroups([])
    os.setgid(agent.pw_gid)
    os.setuid(agent.pw_uid)
    for forbidden in (
        config.protected_root,
        config.record_hmac_key_path,
        controller.CONTROLLER_KEY_PATH,
        controller.OPERATOR_KEY_PATH,
        Path("/var/lib/startup-factory/beads-worker"),
        Path("/var/lib/startup-factory/beads-handoff"),
    ):
        try:
            descriptor = os.open(forbidden, os.O_RDONLY | os.O_NOFOLLOW)
        except PermissionError:
            continue
        else:
            os.close(descriptor)
            os._exit(92)
    denied = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        denied.connect(str(controller.ENDPOINT_PATH))
    except PermissionError:
        os._exit(0)
    os._exit(93)
_, denial_status = os.waitpid(agent_pid, 0)
if not os.WIFEXITED(denial_status) or os.WEXITSTATUS(denial_status) != 0:
    raise SystemExit("external agent-denial proof failed")

observed = public_cycle_as_broker(config, fixture)
if observed != fixture["expected"]:
    raise SystemExit(
        "installed public V27 cycle did not derive exact task/labels/comment/dependency projection"
    )

# Controller death must drain the complete delegated subtree. A disposable
# fixture may kill the packaged unit only after one successful public cycle.
fixed_run(["/usr/bin/systemctl", "kill", "--kill-whom=all", "--signal=KILL", UNIT])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    if fixed_run(["/usr/bin/systemctl", "show", UNIT, "--property=ActiveState"]).strip() != b"ActiveState=active":
        break
    time.sleep(0.05)
fixed_run(["/usr/bin/systemctl", "start", UNIT])
fixed_run(["/usr/bin/systemctl", "is-active", "--quiet", UNIT])

print(
    "external protected Beads V27 Linux installed lifecycle: PASS "
    "(packaged systemd controller domain, public API, derived authority, "
    "create/init/start-attach/terminal/cleanup/rm, four reads, agent denial, "
    "controller death/restart; evidence only, readiness is not promoted)"
)
