"""Run validation of an exact raw Git tree in a fresh enrolled sandbox.

Only native Git object plumbing and the protected controller client run on the
host. Setup hooks, scripts and configured shell commands run in the guest as
the unprivileged agent identity. No publication or model capability is issued.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "bin")]
from startup_factory_cli.execution_backend import GuestCommand, LaunchScope, load_profile
from startup_factory_cli.sandbox_deployment import load_deployment, verify_deployment
from execution_descriptor import validate_sandbox_binding
from host_git import HostGit, oid
from sandbox_acceptance import project_id
from sandbox_client import prepare_request, run_client

MAX_PLAN_BYTES = 64 * 1024
MAX_CHANGED_BYTES = 8 * 1024 * 1024
VALIDATION_KEYS = ("VALIDATE_BUILD", "VALIDATE_TEST", "VALIDATE_LINT", "VALIDATE_FORMAT")

# Fixed installed code, executed only in the guest. The variable command text
# arrives as data in the already-bound prompt file, not as native host argv.
GUEST_VALIDATION_CODE = r'''import json,os,pathlib,subprocess,sys
p=json.loads(pathlib.Path('/opt/startup-factory/prompt.md').read_bytes())
if set(p)!={'schemaVersion','tree','workdir','setup','checks'} or type(p['schemaVersion'])is not int or p['schemaVersion']!=1:raise ValueError('plan')
root=pathlib.Path('/workspace/project')
def cwd():
 d=(root/p['workdir']).resolve(strict=True)
 d.relative_to(root.resolve(strict=True))
 if not d.is_dir():raise ValueError('workdir')
 return d
env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','TMPDIR','LANG','LC_ALL','TERM','NO_COLOR'}}
env.update(AWS_EC2_METADATA_DISABLED='true',PYTHONDONTWRITEBYTECODE='1')
def run(argv,directory):
 r=subprocess.run(argv,cwd=directory,env=env,stdin=subprocess.DEVNULL)
 if r.returncode:sys.exit(min(255,128-r.returncode) if r.returncode<0 else min(255,r.returncode))
if p['setup']:run(['/bin/sh','-c',p['setup']],root)
for c in p['checks']:
 if set(c)!={'label','argv'} or type(c['argv'])is not list or not c['argv']:raise ValueError('check')
 print('sandbox-validation: running '+c['label'],file=sys.stderr,flush=True)
 run(c['argv'],cwd())
'''
# GuestCommand forbids control characters in individual arguments. Compressing
# the fixed installed program preserves that contract without a shell wrapper.
import base64
import zlib
GUEST_COMMAND = GuestCommand(("/usr/bin/python3", "-I", "-B", "-c",
    "import base64,zlib;exec(zlib.decompress(base64.b64decode(" + repr(base64.b64encode(zlib.compress(GUEST_VALIDATION_CODE.encode())).decode()) + ")))"))


class SandboxValidationError(RuntimeError):
    pass


def relative_path(value: str, *, directory: bool = False) -> str:
    if type(value) is not str or not value or len(value.encode()) > 4096 or "\x00" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise SandboxValidationError("validation path is invalid")
    if directory and value == ".":
        return value
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")) or str(path) != value:
        raise SandboxValidationError("validation paths must be normalized repository-relative paths")
    return value


def parse_changed(raw: bytes) -> list[str]:
    if type(raw) is not bytes or len(raw) > MAX_CHANGED_BYTES or raw and not raw.endswith(b"\0"):
        raise SandboxValidationError("changed files require bounded NUL-delimited paths")
    result = []
    for record in raw.split(b"\0")[:-1] if raw else []:
        try:
            path = record.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise SandboxValidationError("changed paths require UTF-8") from exc
        # Newline is a valid Git pathname, preserved as one literal argv value.
        if not path or len(record) > 16 * 1024 or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")):
            raise SandboxValidationError("changed file path is unsafe")
        result.append(path)
        if len(result) > 100_000:
            raise SandboxValidationError("changed path count exceeds its bound")
    if len(result) != len(set(result)):
        raise SandboxValidationError("changed paths contain duplicates")
    return result


def plan(config: dict, changed: list[str], *, tree: str, workdir: str = ".", command: str | None = None, script: str | None = None) -> bytes:
    tree, workdir = oid(tree), relative_path(workdir, directory=True)
    if command is not None and script is not None:
        raise SandboxValidationError("choose one validation command or script")
    checks = []
    if command is not None:
        checks.append({"label": "command", "argv": ["/bin/sh", "-c", command]})
    elif script is not None:
        checks.append({"label": "VALIDATE_SCRIPT", "argv": ["./" + relative_path(script), *changed]})
    else:
        configured_script = config.get("VALIDATE_SCRIPT")
        if configured_script:
            checks.append({"label": "VALIDATE_SCRIPT", "argv": ["./" + relative_path(configured_script), *changed]})
        else:
            checks.extend({"label": key, "argv": ["/bin/sh", "-c", config[key]]} for key in VALIDATION_KEYS if config.get(key))
    setup = config.get("WORKTREE_SETUP") or None
    if (setup is not None and (type(setup) is not str or "\x00" in setup)) or any(type(value) is not str or "\x00" in value for check in checks for value in check["argv"]):
        raise SandboxValidationError("validation commands must be bounded strings")
    raw = json.dumps({"schemaVersion": 1, "tree": tree, "workdir": workdir, "setup": setup,
        "checks": checks}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if not 0 < len(raw) <= MAX_PLAN_BYTES:
        raise SandboxValidationError("validation plan exceeds the guest input bound")
    return raw


def validation_commit(git: HostGit, tree: str) -> str:
    """Name the exact staged tree without commit hooks, parent traversal or refs."""
    tree = oid(tree)
    git.read_object("tree", tree)
    raw = ("tree " + tree + "\nauthor Startup Factory Validation <validation@invalid> 0 +0000\n"
        "committer Startup Factory Validation <validation@invalid> 0 +0000\n\n"
        "Exact staged tree for isolated validation.\n").encode("ascii")
    commit = git.write_object("commit", raw)
    if git.commit_tree(commit) != tree:
        raise SandboxValidationError("validation commit does not name its exact tree")
    return commit


def run_validation(*, repository: Path, workspace: Path, team: str, feature: str,
                   role: str, tree: str, config: dict, changed: list[str],
                   workdir: str = ".", command: str | None = None, script: str | None = None,
                   diagnostic: Callable[[bytes], None] | None = None) -> int:
    if config.get("AGENT_EXECUTION_BACKEND") != "docker-sandboxes" or config.get("AGENT_SANDBOX_ENFORCED") != "true":
        raise SandboxValidationError("isolated validation requires the enforced Docker backend")
    path = config.get("AGENT_SANDBOX_DEPLOYMENT")
    if type(path) is not str or not Path(path).is_absolute():
        raise SandboxValidationError("Docker validation requires its protected deployment")
    repository, workspace = Path(repository), Path(workspace)
    if repository.resolve(strict=True) != repository or workspace.resolve(strict=True) != workspace:
        raise SandboxValidationError("validation paths require canonical project bindings")
    deployment = load_deployment(Path(path))
    profile = load_profile(Path(deployment.profile_path))
    verify_deployment(deployment, profile)
    if os.geteuid() != deployment.controller_uid or os.getegid() != deployment.controller_gid:
        raise SandboxValidationError("validation requires the dedicated controller account")
    scope = LaunchScope(project_id(repository), team, feature, role, "-", 0)
    projects = [entry for entry in deployment.projects
        if entry["projectId"] == scope.project_id and entry["repository"] == str(repository)]
    if len(projects) != 1 or Path(projects[0]["workspaceRoot"]) / team != workspace:
        raise SandboxValidationError("validation project/workspace is outside the deployment")
    # Parse/policy-check the entire plan before the only local object write.
    prompt = plan(config, changed, tree=tree, workdir=workdir, command=command, script=script)
    git = HostGit(repository)
    git.assert_no_checkout_programs()
    base = validation_commit(git, tree)
    request = prepare_request(deployment, repository=repository, workspace=workspace,
        scope=scope, kind="validation", base_commit=base,
        target_ref="refs/heads/sandbox-validation/" + tree,
        guest_command=GUEST_COMMAND, prompt=prompt, capability_id=None, transport=None)
    result = run_client(deployment, request, diagnostic=diagnostic)
    binding = validate_sandbox_binding(result["binding"])
    if binding["baseCommit"] != base or any(binding[key] != getattr(profile, attribute) for key, attribute in (("namespace", "namespace"), ("profileDigest", "digest"), ("policyDigest", "policy_digest"), ("image", "image"))) or any(binding[key] is not None for key in ("acceptedCommit", "acceptedTree", "acceptedExportDigest")) or result.get("promotionReceipt") is not None or git.commit_tree(base) != tree:
        raise SandboxValidationError("validation result differs from its exact candidate")
    code = result.get("exitCode")
    if type(code) is not int or not 0 <= code <= 255:
        raise SandboxValidationError("validation result has no bounded exit status")
    return code
