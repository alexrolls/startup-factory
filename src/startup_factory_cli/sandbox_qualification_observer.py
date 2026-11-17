"""Fixed, bounded administrator observations of an already prepared deployment.

Only read-only settings/policy metadata commands run. This does not validate
network enforcement, credentials, storage pressure or crash recovery. It must
not be called from a guest RPC or replace the production native-client journal.
"""
from __future__ import annotations

import os
from pathlib import Path
import plistlib
import pwd
import selectors
import signal
import subprocess
import time

from .execution_backend import DockerProfile
from .sandbox_deployment import Deployment, DeploymentError, decode_object, private_directory, read_root_protected


REQUIRED_DISABLED_SETTINGS = frozenset({"ssh.agentForwardingEnabled", "browser.enabled", "clipboard.imagePaste",
    "sandbox.fuse", "model.server.enabled"})
MAX_NATIVE_BYTES = 256 * 1024


def parse_settings(raw: bytes) -> dict[str, bool]:
    value = decode_object(b'{"settings":' + raw + b'}', maximum=MAX_NATIVE_BYTES + 32)
    records = value["settings"]
    if type(records) is not list or not 1 <= len(records) <= 512:
        raise DeploymentError("unsupported native settings response")
    selected = {}; seen = set()
    for record in records:
        if type(record) is not dict or type(record.get("key")) is not str or record["key"] in seen:
            raise DeploymentError("native settings are missing a key or repeat it")
        seen.add(record["key"])
        if record["key"] in REQUIRED_DISABLED_SETTINGS:
            if record.get("type") != "bool" or record.get("value") is not False:
                raise DeploymentError("required host integration or model service is enabled")
            selected[record["key"]] = False
    if set(selected) != REQUIRED_DISABLED_SETTINGS:
        raise DeploymentError("native effective settings omit required host integrations")
    return selected


def parse_policy(raw: bytes, descriptor) -> dict:
    """The raw descriptor pin and observed native rule schema are distinct."""
    from .sandbox_network_policy import verify_effective_policy, NetworkPolicyError
    try:
        return verify_effective_policy(descriptor, raw, stage="global")
    except NetworkPolicyError as exc:
        raise DeploymentError("actual dedicated namespace is not the exact deny-default baseline") from exc


def _native(deployment: Deployment, profile: DockerProfile, arguments: tuple[str, ...]) -> bytes:
    if arguments not in {("settings", "list", "--json"), ("policy", "ls", "--json")}:
        raise DeploymentError("qualification observer only permits fixed read-only metadata queries")
    if os.geteuid() not in {0, deployment.controller_uid} or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise DeploymentError("observer requires root/controller identity and exclusive native-child custody")
    private_directory(Path(deployment.account_home) / "tmp", deployment.controller_uid)
    _raw, digest = read_root_protected(Path(profile.sbx_path), maximum=256 * 1024 * 1024, capture=False, executable=True)
    if digest != profile.sbx_sha256:
        raise DeploymentError("observer runtime differs from its protected pin")
    environment = {"PATH": "/usr/bin:/bin", "HOME": deployment.account_home, "USER": deployment.account_name,
        "LOGNAME": deployment.account_name, "TMPDIR": deployment.account_home + "/tmp", "LANG": "C", "LC_ALL": "C", "SBX_NO_TELEMETRY": "1"}
    privilege = {"user": deployment.controller_uid, "group": deployment.controller_gid, "extra_groups": []} if os.geteuid() == 0 else {}
    return _bounded([profile.sbx_path, "--app-name", deployment.namespace, "--no-input", *arguments], environment, privilege)


def _bounded(argv: list[str], environment: dict[str, str], privilege: dict) -> bytes:
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise DeploymentError("observer requires exclusive native-child custody")
    child = subprocess.Popen(argv,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", env=environment,
        close_fds=True, start_new_session=True, shell=False, umask=0o077, **privilege)
    assert child.stdout is not None and child.stderr is not None
    deadline = time.monotonic() + 10
    output = bytearray(); errors = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            for stream, name in ((child.stdout, "stdout"), (child.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DeploymentError("native observation deadline exceeded")
                for key, _mask in selector.select(remaining):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except (InterruptedError, BlockingIOError):
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj); key.fileobj.close(); continue
                    selected = output if key.data == "stdout" else errors
                    if len(selected) + len(chunk) > (MAX_NATIVE_BYTES if key.data == "stdout" else 16384):
                        raise DeploymentError("native observation exceeded its byte limit")
                    selected.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or child.wait(timeout=max(remaining, 0.001)) != 0 or errors:
            raise DeploymentError("native observation did not complete cleanly")
        return bytes(output)
    finally:
        if child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=1)
        child.stdout.close(); child.stderr.close()


def current_settings_policy(deployment: Deployment, profile: DockerProfile) -> dict:
    """Actual dedicated-account metadata, not a qualification pass result."""
    settings_raw = _native(deployment, profile, ("settings", "list", "--json"))
    policy_raw = _native(deployment, profile, ("policy", "ls", "--json"))
    from .sandbox_network_policy import load_network_policy
    descriptor = load_network_policy(Path(deployment.network_policy_path), profile)
    return {"settings": parse_settings(settings_raw), "policy": parse_policy(policy_raw, descriptor)}


def parse_storage(info_raw: bytes, volumes_raw: bytes, deployment: Deployment) -> dict:
    """Accept only an explicit mounted APFS volume with the exact finite quota."""
    try:
        if len(info_raw) > MAX_NATIVE_BYTES or len(volumes_raw) > MAX_NATIVE_BYTES:
            raise DeploymentError("native storage metadata is oversized")
        info = plistlib.loads(info_raw); volumes = plistlib.loads(volumes_raw)
        selected = deployment.storage
        identifier = info.get("VolumeUUID", info.get("APFSVolumeUUID"))
        if (info.get("FilesystemType") != "apfs" or info.get("MountPoint") != selected["mountPoint"]
            or type(identifier) is not str or identifier.lower() != selected["volumeUuid"].lower()):
            raise DeploymentError("dedicated APFS mount/volume identity differs")
        matches = []
        for container in volumes["Containers"]:
            for volume in container["Volumes"]:
                candidate = volume.get("APFSVolumeUUID", volume.get("VolumeUUID"))
                if type(candidate) is str and candidate.lower() == identifier.lower():
                    matches.append(volume)
        if len(matches) != 1 or type(matches[0].get("CapacityQuota")) is not int or matches[0]["CapacityQuota"] != selected["quotaBytes"]:
            raise DeploymentError("APFS aggregate quota is absent, changed or ambiguous")
        return {"mountPoint": selected["mountPoint"], "volumeUuid": identifier, "quotaBytes": matches[0]["CapacityQuota"]}
    except (KeyError, TypeError, AttributeError, ValueError, plistlib.InvalidFileException) as exc:
        raise DeploymentError("native APFS metadata is unsupported or incomplete") from exc


def current_storage(deployment: Deployment) -> dict:
    """Read-only system metadata; no volume creation, resizing, formatting or fill."""
    program = Path("/usr/sbin/diskutil")
    read_root_protected(program, maximum=32 * 1024 * 1024, executable=True, capture=False)
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin", "HOME": deployment.account_home, "LANG": "C", "LC_ALL": "C"}
    info = _bounded([str(program), "info", "-plist", deployment.storage["mountPoint"]], environment, {})
    volumes = _bounded([str(program), "apfs", "list", "-plist"], environment, {})
    result = parse_storage(info, volumes, deployment)
    device = os.stat(deployment.storage["mountPoint"], follow_symlinks=False).st_dev
    if os.stat(deployment.account_home, follow_symlinks=False).st_dev != device:
        raise DeploymentError("dedicated HOME escapes the quota volume")
    from .sandbox_deployment import verify_storage_paths
    verify_storage_paths(deployment)
    return result


def current_account_status(deployment: Deployment) -> None:
    """Read only the disabled marker; never password/hash/keychain attributes."""
    program = Path("/usr/bin/dscl")
    read_root_protected(program, maximum=32 * 1024 * 1024, executable=True, capture=False)
    raw = _bounded([str(program), ".", "-read", "/Users/" + deployment.account_name, "AuthenticationAuthority"],
        {"PATH": "/usr/bin:/bin", "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C"}, {})
    parts = raw.decode("utf-8", errors="strict").strip().split(":", 1)
    if len(parts) != 2 or parts[0].strip() != "AuthenticationAuthority" or parts[1].strip() != ";DisabledUser;":
        raise DeploymentError("dedicated account disabled marker is absent or has additional authentication providers")


def current_host_resources() -> dict:
    program = Path("/usr/sbin/sysctl")
    read_root_protected(program, maximum=32 * 1024 * 1024, executable=True, capture=False)
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C"}
    selected = []
    for key in ("hw.memsize", "hw.logicalcpu"):
        raw = _bounded([str(program), "-n", key], environment, {}).strip()
        if not raw.isdigit() or len(raw) > 20 or int(raw) <= 0:
            raise DeploymentError("current host resource inventory is invalid")
        selected.append(int(raw))
    return {"physicalMemoryMiB": selected[0] // (1024 * 1024), "logicalCpus": selected[1]}


def current_interpreter(deployment: Deployment) -> str:
    pin = deployment.programs["python"]
    _raw, digest = read_root_protected(Path(pin["path"]), maximum=256 * 1024 * 1024, executable=True, capture=False)
    if digest != pin["sha256"]:
        raise DeploymentError("protected Python changed")
    raw = _bounded([pin["path"], "-I", "-B", "-c", "import sys;sys.stdout.write('.'.join(map(str,sys.version_info[:3])))"],
        {"PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C"},
        {"user": deployment.controller_uid, "group": deployment.controller_gid, "extra_groups": []})
    value = raw.decode("ascii", errors="strict")
    import re
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is None or tuple(map(int, value.split("."))) < (3, 10, 0):
        raise DeploymentError("Python 3.10 or later is required")
    return value


_ENDPOINT_PROBE = """import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(1)
try:
 s.connect(sys.argv[1]);code=0
except OSError as exc:
 code=exc.errno if exc.errno is not None else -1
s.close();sys.stdout.write(str(code))
"""

_PROTECTED_PROBE = """import json,os,pathlib,sys
paths=json.loads(sys.argv[1]);root=paths.pop();count=0
def fail(_error):raise SystemExit(3)
for directory,folders,files in os.walk(root,followlinks=False,onerror=fail):
 count+=len(folders)+len(files)
 if count>20000:raise SystemExit(2)
 paths.extend(str(pathlib.Path(directory)/name) for name in folders+files)
paths.append(root)
if any(p!=sys.argv[2] and not os.access(p,os.R_OK,effective_ids=True) for p in paths):raise SystemExit(4)
selected=set()
for raw in paths:
 p=pathlib.Path(raw);selected.add(str(p));selected.update(str(parent) for parent in p.parents)
sys.stdout.write('unsafe' if any(os.access(p,os.W_OK,effective_ids=True) for p in selected) else 'protected')
"""


def current_protected_denials(deployment: Deployment, profile: DockerProfile) -> None:
    """Actual controller effective-access checks include ACL grants to root paths."""
    if os.geteuid() != 0:
        raise DeploymentError("controller access observations require the root issuer")
    program = deployment.programs["python"]
    _raw, digest = read_root_protected(Path(program["path"]), maximum=256 * 1024 * 1024, capture=False, executable=True)
    if digest != program["sha256"]:
        raise DeploymentError("controller observer Python differs from its protected pin")
    paths = [str(deployment.source_path), deployment.profile_path, deployment.receipt_path,
        deployment.evidence_root, profile.sbx_path, *[pin["path"] for pin in deployment.programs.values()], deployment.bundle_root]
    import json
    response = _bounded([program["path"], "-I", "-B", "-c", _PROTECTED_PROBE, json.dumps(paths), deployment.receipt_path],
        {"PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C"},
        {"user": deployment.controller_uid, "group": deployment.controller_gid, "extra_groups": []})
    if response != b"protected":
        raise DeploymentError("controller can write protected authority/runtime, including through an ACL")


def current_endpoint_denials(deployment: Deployment, endpoints: list[dict]) -> None:
    """Actual no-message connect probes as ordinary OS accounts, including ACLs.

    Each fixed child uses that account's actual primary and supplementary
    groups, so an ACL grant to (for example) admin/staff is not missed. A
    successful connection fails enrollment; absence/timeout is not accepted as
    proof of access denial. Nothing is sent to the daemon after connecting.
    """
    if os.geteuid() != 0:
        raise DeploymentError("cross-account endpoint observations require the root issuer")
    accounts = {entry.pw_uid: entry for entry in pwd.getpwall() if 500 <= entry.pw_uid <= 2**31 - 1 and entry.pw_uid != deployment.controller_uid}
    if not accounts or len(accounts) * len(endpoints) > 64:
        raise DeploymentError("ordinary-account endpoint probe coverage is empty or exceeds its bound")
    program = deployment.programs["python"]
    _raw, digest = read_root_protected(Path(program["path"]), maximum=256 * 1024 * 1024, capture=False, executable=True)
    if digest != program["sha256"]:
        raise DeploymentError("endpoint observer Python differs from its protected pin")
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C"}
    import errno
    for uid, account in sorted(accounts.items()):
        groups = os.getgrouplist(account.pw_name, account.pw_gid)
        if len(groups) > 128 or any(type(group) is not int or not 0 <= group <= 2**31 - 1 for group in groups):
            raise DeploymentError("ordinary account group inventory is unsupported or oversized")
        for endpoint in endpoints:
            response = _bounded([program["path"], "-I", "-B", "-c", _ENDPOINT_PROBE, endpoint["path"]], environment,
                {"user": uid, "group": account.pw_gid, "extra_groups": groups})
            if response not in {str(errno.EACCES).encode(), str(errno.EPERM).encode()}:
                raise DeploymentError("ordinary account can reach an endpoint or denial was not established")
