"""Provision reviewed, private machine state without executing configuration."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import pwd
import re
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import project_config
from .config_values import ConfigValueError, parse_config_bytes, value_for
from .installer import InstallerError


class MachineSetupError(RuntimeError):
    """Machine provisioning could not be completed safely."""


_SUPPORTED_CLIS = {"claude", "codex", "gemini", "aider", "deepseek-harness", "dsh"}
_BARE_CLI = re.compile(r"^(claude|codex|gemini|aider|deepseek-harness|dsh)(?=[ \t]|$)")


def _absolute(value: str, label: str) -> Path:
    candidate = Path(value)
    if (
        not candidate.is_absolute()
        or value != os.path.normpath(value)
        or str(candidate) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise MachineSetupError(f"{label} must be an absolute normalized path")
    return candidate


def _disjoint(path: Path, boundary: Path, label: str) -> None:
    if Path(os.path.commonpath((path, boundary))) in {path, boundary}:
        raise MachineSetupError(f"{label} must be disjoint from {boundary}")


def _not_shared(path: Path, label: str) -> None:
    for shared in (Path("/tmp"), Path("/private/tmp"), Path("/var/tmp"), Path("/private/var/tmp")):
        if path == shared or shared in path.parents:
            raise MachineSetupError(f"{label} must not live below a shared temporary directory")


def _check_directory(info: os.stat_result, path: Path, label: str) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise MachineSetupError(f"{label} requires non-symlink directory components: {path}")
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o022:
        raise MachineSetupError(f"{label} components must be executor/root-owned and not group/world-writable: {path}")


def _directory(path: Path, label: str, *, create: bool = False, private: bool = False) -> None:
    """Inspect, or create and open, every directory through no-follow dirfds."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    return
                os.mkdir(part, 0o700, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise MachineSetupError(f"cannot securely open {label} component {current}: {exc}") from exc
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            _check_directory(info, current, label)
            if current == path and private and stat.S_IMODE(info.st_mode) != 0o700:
                raise MachineSetupError(f"{label} must have mode 0700: {path}")
    finally:
        os.close(descriptor)


def _cli_chain(path: Path, label: str, *, depth: int = 0, boundaries: tuple[Path, ...] = ()) -> None:
    if depth > 32:
        raise MachineSetupError(f"{label} has a cyclic or excessively deep symlink chain")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if any(current == boundary or boundary in current.parents for boundary in boundaries):
            raise MachineSetupError(f"{label} must be disjoint from repository and installed skill: {current}")
        try:
            info = current.lstat()
        except OSError as exc:
            raise MachineSetupError(f"cannot inspect {label} {current}: {exc}") from exc
        if info.st_uid not in {0, os.geteuid()}:
            raise MachineSetupError(f"{label} must be executor/root-owned: {current}")
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            target = Path(os.readlink(current))
            if not target.is_absolute():
                target = current.parent / target
            target = Path(os.path.normpath(target))
            _not_shared(target, label)
            _cli_chain(target, label, depth=depth + 1, boundaries=boundaries)
        # Symlink permission bits have no access-control meaning. Both its
        # lexical parents and canonical target chain are inspected separately.
        if not stat.S_ISLNK(info.st_mode) and mode & 0o022:
            homebrew_group = (
                (current == Path("/opt/homebrew") or Path("/opt/homebrew") in current.parents)
                and info.st_uid == os.geteuid()
                and stat.S_ISDIR(info.st_mode)
                and not mode & 0o002
            )
            if not homebrew_group:
                raise MachineSetupError(f"{label} must not be group/world-writable: {current}")
        if current != path and not current.is_dir():
            raise MachineSetupError(f"{label} ancestor must be a directory: {current}")


def validate_cli_executable(value: str, *, label: str = "CLI executable", boundaries: tuple[Path, ...] = ()) -> Path:
    """Return a canonical executable after checking both lexical/target chains."""
    candidate = _absolute(value, label)
    _not_shared(candidate, label)
    _cli_chain(candidate, label, boundaries=boundaries)
    try:
        canonical = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise MachineSetupError(f"cannot resolve {label}: {exc}") from exc
    _not_shared(canonical, label)
    _cli_chain(canonical, label, boundaries=boundaries)
    info = canonical.lstat()
    if not stat.S_ISREG(info.st_mode) or not os.access(canonical, os.X_OK):
        raise MachineSetupError(f"{label} must resolve to a regular executable file: {candidate}")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise MachineSetupError(f"{label} executable must not be group/world-writable: {canonical}")
    return canonical


def _find_cli(name: str, caller_path: str, boundaries: tuple[Path, ...]) -> Path:
    rejected: list[str] = []
    for entry in caller_path.split(":"):
        if not entry or not Path(entry).is_absolute():
            continue
        candidate = Path(entry) / name
        if not candidate.exists() and not candidate.is_symlink():
            continue
        try:
            canonical = validate_cli_executable(str(candidate), label=name, boundaries=boundaries)
            for boundary in boundaries:
                _disjoint(candidate, boundary, name)
                _disjoint(canonical, boundary, name)
            return candidate
        except MachineSetupError as exc:
            rejected.append(str(exc))
    detail = f" ({rejected[0]})" if rejected else ""
    raise MachineSetupError(f"configured CLI {name!r} is unavailable in a safe absolute caller PATH directory; install it, then rerun setup{detail}")



def _first_token(command: str) -> tuple[str, int] | None:
    """Locate only a simple leading shell word; never interpret its contents."""
    quote: str | None = None
    escaped = False
    end = len(command)
    for index, character in enumerate(command):
        if escaped:
            escaped = False
        elif character == "\\" and quote != "'":
            escaped = True
        elif quote is not None:
            if character == quote:
                quote = None
        elif character in "\"'":
            quote = character
        elif character in " \t":
            end = index
            break
    try:
        return shlex.split(command[:end])[0], end
    except (ValueError, IndexError):
        return None


def _node_interpreter(executable: Path, caller_path: str, boundaries: tuple[Path, ...], *, configured: str | None = None) -> Path | None:
    canonical = validate_cli_executable(str(executable))
    descriptor = os.open(canonical, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first_line = os.read(descriptor, 512).split(b"\n", 1)[0].rstrip(b"\r")
    finally:
        os.close(descriptor)
    if re.fullmatch(rb"#![ \t]*/usr/bin/env[ \t]+node[ \t]*", first_line):
        if configured is not None:
            validate_cli_executable(configured, label="configured CLI interpreter")
            return Path(configured)
        try:
            return _find_cli("node", caller_path, boundaries)
        except MachineSetupError as exc:
            raise MachineSetupError(f"{executable} requires Node via /usr/bin/env; install Node in a safe absolute caller PATH directory, then rerun setup: {exc}") from exc
    return None



def _validate_lifecycle_socket(lifecycle: Path) -> None:
    # Match publication_supervisor.transport_locator's cross-platform bound.
    length = len(os.fsencode(lifecycle / "p" / ("0" * 32)))
    if length >= 100:
        raise MachineSetupError(
            f"BROKER_LIFECYCLE_ROOT is too long for publication sockets ({length} bytes; must be below 100). "
            "Choose a shorter --state-root before configuring lifecycle state; "
            "an existing explicit BROKER_LIFECYCLE_ROOT must be shortened in config/team.config.md."
        )


def _load_authority(skill: Path):
    spec = importlib.util.spec_from_file_location("_startup_factory_setup_authority", skill / "bin/authority_config.py")
    if spec is None or spec.loader is None:
        raise MachineSetupError("installed authority configuration helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> project_config.ProjectConfig:
    _directory(path.parent, "configuration directory")
    raw, info, parent_identity, absolute = project_config._read_regular_file(path)
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o022:
        raise MachineSetupError(f"configuration must be executor/root-owned and not group/world-writable: {path}")
    parse_config_bytes(raw, str(path))
    return project_config.ProjectConfig(
        absolute, raw, raw.decode("utf-8"), stat.S_IMODE(info.st_mode),
        project_config._identity(info), parent_identity, {},
    )


def _encode(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _render(snapshot: project_config.ProjectConfig, updates: dict[str, str]) -> bytes:
    values = parse_config_bytes(snapshot.raw, str(snapshot.path))
    lines = snapshot.text.splitlines(keepends=True)
    additions: list[str] = []
    for key, value in updates.items():
        previous = values.get(key)
        if previous is not None and previous.state == "value" and previous.value == value:
            continue
        if previous is None:
            additions.append(f"{key}={_encode(value)}\n")
            continue
        line = lines[previous.line - 1]
        ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        lines[previous.line - 1] = f"{key}={_encode(value)}{ending}"
    rendered = "".join(lines)
    if additions:
        rendered += ("" if rendered.endswith("\n") else "\n") + "\n# Machine provisioning: explicit CLI executables for dedicated-home login.\n" + "".join(additions)
    raw = rendered.encode("utf-8")
    parsed = parse_config_bytes(raw, "provisioned team configuration")
    if any(value_for(parsed, key) != value for key, value in updates.items()):
        raise MachineSetupError("provisioned configuration did not round-trip through the inert parser")
    return raw


def _write(snapshot: project_config.ProjectConfig, replacement: bytes) -> None:
    if replacement == snapshot.raw:
        return
    # Reuse the installer's no-follow, dirfd-based atomic exchange, including
    # concurrent-writer detection and preservation of any displaced snapshot.
    descriptor, absolute, metadata = project_config._open_parent_directory(snapshot.path)
    try:
        project_config._apply_changes_in_directory(snapshot, replacement, descriptor, absolute.name, absolute, metadata)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class SetupResult:
    project: Path
    agent_home: Path
    lifecycle_root: Path
    markdown_root: Path | None
    runtime_path: str
    rewritten_commands: int
    config_changed: bool


def provision(*, skill: Path, project: Path, operator_home: str, caller_path: str, state_root: str | None = None) -> SetupResult:
    """Validate a complete plan before provisioning folders or updating config."""
    skill = skill.resolve(strict=True)
    project = project.resolve(strict=True)
    team = _read(skill / "config/team.config.md")
    pm = _read(skill / "config/project-management.config.md")
    values = parse_config_bytes(team.raw, "team configuration")
    pm_values = parse_config_bytes(pm.raw, "project-management configuration")
    authority = _load_authority(skill)
    try:
        runtime_path = authority.validated_runtime_path(caller_path, project, skill)
    except authority.AuthorityConfigError as exc:
        raise MachineSetupError(str(exc)) from exc

    if state_root is None:
        home = _absolute(operator_home, "operator HOME")
        digest = hashlib.sha256(os.fsencode(project)).hexdigest()[:12]
        # Unix-domain publication sockets have a tight platform path limit.
        base = home / ".local/share/sf" / digest
    else:
        base = _absolute(state_root, "state root")
    _not_shared(base, "state root")
    for boundary in (project, skill):
        _disjoint(base, boundary, "state root")
    _directory(base, "state root")

    agent_home = _absolute(value_for(values, "AGENT_SANDBOX_HOME") or str(base / "h"), "AGENT_SANDBOX_HOME")
    lifecycle = _absolute(value_for(values, "BROKER_LIFECYCLE_ROOT") or str(base / "l"), "BROKER_LIFECYCLE_ROOT")
    for path, label in ((agent_home, "AGENT_SANDBOX_HOME"), (lifecycle, "BROKER_LIFECYCLE_ROOT")):
        _not_shared(path, label)
        for boundary in (project, skill):
            _disjoint(path, boundary, label)
        _directory(path, label, private=True)
    _disjoint(agent_home, lifecycle, "AGENT_SANDBOX_HOME")
    _validate_lifecycle_socket(lifecycle)

    markdown: Path | None = None
    if value_for(pm_values, "PRODUCT_MANAGEMENT_TOOL") == "Markdown":
        configured = value_for(pm_values, "MARKDOWN_ROOT") or ".workspace/task-manager"
        raw_markdown = Path(configured)
        if ".." in raw_markdown.parts:
            raise MachineSetupError("MARKDOWN_ROOT must not contain '..'")
        markdown = _absolute(str(raw_markdown if raw_markdown.is_absolute() else project / raw_markdown), "MARKDOWN_ROOT")
        if markdown == project:
            raise MachineSetupError("MARKDOWN_ROOT must name a dedicated directory")
        for private in (agent_home, lifecycle):
            _disjoint(markdown, private, "MARKDOWN_ROOT")
        _directory(markdown, "MARKDOWN_ROOT")

    updates: dict[str, str] = {}
    for key, path in (("AGENT_SANDBOX_HOME", agent_home), ("BROKER_LIFECYCLE_ROOT", lifecycle)):
        if value_for(values, key) is None:
            updates[key] = str(path)
    discovered: dict[str, Path] = {}
    interpreters: dict[str, Path] = {}
    rewritten = 0
    for key, parsed in values.items():
        if not key.endswith("_CMD") or parsed.state != "value":
            continue
        command = parsed.value
        match = _BARE_CLI.match(command)
        if match:
            name = match.group(1)
            executable = discovered.get(name) or _find_cli(name, caller_path, (project, skill))
            word_end = match.end()
        else:
            leading = _first_token(command)
            if leading is None:
                continue
            first, word_end = leading
            if not Path(first).is_absolute() or Path(first).name not in _SUPPORTED_CLIS:
                continue
            name = Path(first).name
            validate_cli_executable(first, label=key)
            executable = Path(first)
        discovered.setdefault(name, executable)
        interpreter = _node_interpreter(executable, caller_path, (project, skill), configured=value_for(values, name.upper() + "_CLI_INTERPRETER_PATH"))
        if interpreter is not None:
            interpreters.setdefault(name, interpreter)
        if match or interpreter is not None:
            prefix = (shlex.quote(str(interpreter)) + " ") if interpreter is not None else ""
            if name == "claude" and interpreter is not None:
                prefix = "STARTUP_FACTORY_LLM_RUNTIME=claude " + prefix
            updated = prefix + shlex.quote(str(executable)) + command[word_end:]
            if updated != command:
                updates[key] = updated
                rewritten += 1
    for name in ("claude", "codex"):
        key = name.upper() + "_CLI_PATH"
        explicit = value_for(values, key)
        executable = Path(explicit) if explicit is not None else discovered.get(name)
        if executable is not None:
            validate_cli_executable(str(executable), label=key)
            interpreter = _node_interpreter(executable, caller_path, (project, skill), configured=value_for(values, name.upper() + "_CLI_INTERPRETER_PATH"))
            if interpreter is not None:
                interpreters[name] = interpreter
            if explicit is None:
                updates[key] = str(executable)
        interpreter_key = name.upper() + "_CLI_INTERPRETER_PATH"
        explicit_interpreter = value_for(values, interpreter_key)
        if explicit_interpreter is not None:
            validate_cli_executable(explicit_interpreter, label=interpreter_key)
        elif name in interpreters:
            updates[interpreter_key] = str(interpreters[name])
    replacement = _render(team, updates)

    # Everything above is read-only. Recheck complete directory chains during
    # creation, then validate with the launcher's existing lifecycle authority.
    _directory(agent_home, "AGENT_SANDBOX_HOME", create=True, private=True)
    _directory(lifecycle, "BROKER_LIFECYCLE_ROOT", create=True, private=True)
    try:
        authority.resolve_lifecycle_root(str(lifecycle), project, skill, required=True)
    except authority.AuthorityConfigError as exc:
        raise MachineSetupError(str(exc)) from exc
    if markdown is not None:
        _directory(markdown, "MARKDOWN_ROOT", create=True)
    _write(team, replacement)
    return SetupResult(project, agent_home, lifecycle, markdown, runtime_path, rewritten, replacement != team.raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="setup-machine.sh", description="Provision private Startup Factory state and pin configured CLI executables for this machine.")
    parser.add_argument("--state-root", help="absolute external parent for new private CLI home and lifecycle directories")
    parser.add_argument("--skip-doctor", action="store_true", help="provision only; CLI login and readiness remain pending")
    parser.add_argument("--skill-dir", required=True, type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--project", required=True, type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--operator-home", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--caller-path", required=True, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        result = provision(skill=args.skill_dir, project=args.project, operator_home=args.operator_home, caller_path=args.caller_path, state_root=args.state_root)
        print(f"Machine setup provisioned for {result.project}")
        print(f"  Agent CLI home: {result.agent_home}")
        print(f"  Broker lifecycle: {result.lifecycle_root}")
        if result.markdown_root is not None:
            print(f"  Markdown tracker: {result.markdown_root}")
        print(f"  CLI role commands pinned: {result.rewritten_commands}")
        print("  Installed team configuration: " + ("updated" if result.config_changed else "already configured"))
        if args.skip_doctor:
            launcher = shlex.quote(str(args.skill_dir / "bin/launch-team.sh"))
            print(f"Readiness pending: sign in with {launcher} login, then run {launcher} doctor.")
            return 0
        print("Running team doctor…", flush=True)
        user = pwd.getpwuid(os.geteuid()).pw_name
        environment = {"PATH": result.runtime_path, "HOME": args.operator_home, "USER": user, "LOGNAME": user, "LANG": "C", "LC_ALL": "C"}
        return subprocess.run([str(args.skill_dir / "bin/launch-team.sh"), "doctor"], cwd=result.project, env=environment, check=False).returncode
    except (MachineSetupError, ConfigValueError, InstallerError, OSError) as exc:
        print(f"setup-machine: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
