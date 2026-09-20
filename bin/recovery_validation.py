#!/usr/bin/env python3
"""Run late-invalidation validation without inheriting broker credentials.

The integration finalizer starts this helper through an absolute system Python
under an isolated, fixed environment.  This module then creates the still
narrower environment used by repository-controlled validation commands.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, NoReturn, Optional, Union

sys.dont_write_bytecode = True
SKILL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "src"))

from startup_factory_cli.config_values import (  # noqa: E402
    ConfigValueError,
    parse_config_bytes,
    value_for,
)


MAX_CONFIG_BYTES = 1024 * 1024
MAX_CHANGED_FILES_BYTES = 8 * 1024 * 1024
MAX_CHANGED_FILES = 100_000
MAX_CHANGED_PATH_BYTES = 16 * 1024
MAX_VALIDATION_OUTPUT_BYTES = 8 * 1024 * 1024
VALIDATION_TIMEOUT_SECONDS = 15 * 60
TERMINATION_GRACE_SECONDS = 2.0
VALIDATION_KEYS = (
    "VALIDATE_BUILD",
    "VALIDATE_TEST",
    "VALIDATE_LINT",
    "VALIDATE_FORMAT",
)
RELEVANT_KEYS = {
    "AGENT_ENV_ALLOWLIST",
    "AGENT_SANDBOX_ENFORCED",
    "AGENT_SANDBOX_RUNNER",
    "VALIDATE_SCRIPT",
    *VALIDATION_KEYS,
}
# Recovery intentionally uses a positive list.  A deny-list cannot recognize
# every credential spelling (DATABASE_URL, PGPASSWORD, vendor DSNs, and so on).
# These are the complete non-secret names in the shipped AGENT_ENV_ALLOWLIST.
ALLOWED_ENV_NAMES = frozenset(
    {"PATH", "TMPDIR", "LANG", "LC_ALL", "TERM", "NO_COLOR"}
)


class RecoveryValidationError(RuntimeError):
    """Raised when the credential-free validation boundary is unsafe."""


def fail(message: str) -> NoReturn:
    raise RecoveryValidationError(message)


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _repo_path(raw: str, repo: Path, label: str, *, allow_empty: bool) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = repo / candidate
    try:
        before = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        fail(f"{label} is unavailable: {exc}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a non-symlink regular file")
    if not _within(resolved, repo):
        fail(f"{label} must remain inside the repository")
    size = before.st_size
    if size < (0 if allow_empty else 1):
        fail(f"{label} must not be empty")
    return resolved


def _read_bounded(path: Path, label: str, limit: int, *, allow_empty: bool) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a non-symlink regular file")
    if before.st_size > limit or (not allow_empty and before.st_size == 0):
        fail(f"{label} must contain at most {limit} bytes")
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            fail(f"{label} changed while it was opened")
        content = bytearray()
        while len(content) <= limit:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > limit:
            fail(f"{label} exceeds its {limit}-byte limit")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            fail(f"{label} changed while it was read")
        return bytes(content)
    except OSError as exc:
        fail(f"cannot securely read {label}: {exc}")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_config(content: bytes) -> dict[str, Optional[str]]:
    try:
        parsed = parse_config_bytes(content, "team configuration")
    except ConfigValueError as exc:
        fail(str(exc))
    values = {key: value_for(parsed, key) for key in RELEVANT_KEYS if key in parsed}
    for key, value in values.items():
        if value is not None and len(value) > 64 * 1024:
            fail(f"{key} exceeds the 64 KiB value limit")
    for required in ("AGENT_ENV_ALLOWLIST", "AGENT_SANDBOX_ENFORCED"):
        if required not in values or values[required] is None:
            fail(f"configuration must define non-null {required}")
    return values


def _validate_env_name(name: str) -> None:
    if name not in ALLOWED_ENV_NAMES:
        fail(
            "AGENT_ENV_ALLOWLIST may expose only the recovery-safe names "
            + ", ".join(sorted(ALLOWED_ENV_NAMES))
            + f"; refused {name!r}"
        )


def clean_environment(config: dict[str, Optional[str]]) -> list[str]:
    raw = config["AGENT_ENV_ALLOWLIST"] or ""
    names = raw.split()
    if not names:
        fail("AGENT_ENV_ALLOWLIST must contain at least PATH")
    if len(names) != len(set(names)):
        fail("AGENT_ENV_ALLOWLIST contains duplicate names")
    for name in names:
        _validate_env_name(name)
    if "PATH" not in names:
        fail("AGENT_ENV_ALLOWLIST must include PATH")
    assignments: list[str] = []
    for name in names:
        value = os.environ.get(name, "")
        if "\x00" in value or "\r" in value or "\n" in value:
            fail(f"allowlisted environment variable {name!r} contains a control character")
        assignments.append(f"{name}={value}")
    assignments.extend(
        ("AWS_EC2_METADATA_DISABLED=true", "PYTHONDONTWRITEBYTECODE=1")
    )
    return assignments


def _path_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    # Directory content changes legitimately alter size and timestamps; device,
    # inode, type/mode, and ownership are the stable anti-swap identity.
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _validate_protected_metadata(
    path: Path, metadata: os.stat_result, *, directory: bool
) -> None:
    kind = "ancestor" if directory else "file"
    if directory:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail(f"AGENT_SANDBOX_RUNNER {kind} is not a real directory: {path}")
    elif stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("AGENT_SANDBOX_RUNNER must be a non-symlink regular file")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o022:
        fail(f"AGENT_SANDBOX_RUNNER {kind} must not be group- or world-writable: {path}")
    if metadata.st_uid != 0:
        fail(f"AGENT_SANDBOX_RUNNER {kind} must be root-owned: {path}")
    try:
        executor_can_write = os.access(path, os.W_OK, effective_ids=True)
    except (NotImplementedError, TypeError):
        executor_can_write = os.access(path, os.W_OK)
    if executor_can_write:
        fail(f"AGENT_SANDBOX_RUNNER {kind} must not be executor-writable: {path}")
    # The owner may chmod or rewrite its own nominally read-only file.  Requiring
    # root ownership is what makes the runner unavailable to the unprivileged
    # executor whose repository code is about to be sandboxed.


@dataclasses.dataclass(frozen=True)
class RunnerBinding:
    path: Path
    file_identity: tuple[int, int, int, int, int, int, int, int]
    ancestor_identities: tuple[
        tuple[str, tuple[int, int, int, int, int]], ...
    ]

    def revalidate(self, repo: Path) -> None:
        current = _validated_runner_binding(str(self.path), repo)
        if current != self:
            fail("AGENT_SANDBOX_RUNNER identity changed before execution")


def _validated_runner_binding(raw: str, repo: Path) -> RunnerBinding:
    runner = Path(raw)
    if not runner.is_absolute():
        fail("AGENT_SANDBOX_RUNNER must be an absolute path")
    try:
        metadata = runner.lstat()
        resolved = runner.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot inspect AGENT_SANDBOX_RUNNER: {exc}")
    if resolved != runner:
        fail("AGENT_SANDBOX_RUNNER must use its canonical absolute path")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("AGENT_SANDBOX_RUNNER must be a non-symlink regular file")
    if not metadata.st_mode & 0o111 or not os.access(resolved, os.X_OK):
        fail("AGENT_SANDBOX_RUNNER must be executable")
    installed_runtime = Path(__file__).resolve(strict=True).parent.parent
    if _within(resolved, repo):
        fail("AGENT_SANDBOX_RUNNER must be external to the repository")
    if _within(resolved, installed_runtime):
        fail("AGENT_SANDBOX_RUNNER must be external to the installed runtime")
    _validate_protected_metadata(resolved, metadata, directory=False)

    ancestors: list[tuple[str, tuple[int, int, int, int, int]]] = []
    ancestor = resolved.parent
    while True:
        try:
            ancestor_metadata = ancestor.lstat()
        except OSError as exc:
            fail(f"cannot inspect AGENT_SANDBOX_RUNNER ancestor {ancestor}: {exc}")
        _validate_protected_metadata(ancestor, ancestor_metadata, directory=True)
        ancestors.append((str(ancestor), _directory_identity(ancestor_metadata)))
        if ancestor == ancestor.parent:
            break
        ancestor = ancestor.parent
    return RunnerBinding(
        path=resolved,
        file_identity=_path_identity(metadata),
        ancestor_identities=tuple(ancestors),
    )


def validate_runner(raw: Optional[str], repo: Path) -> RunnerBinding:
    if not raw:
        fail("AGENT_SANDBOX_RUNNER is required when AGENT_SANDBOX_ENFORCED=true")
    return _validated_runner_binding(raw, repo)


def _parse_changed_files(content: bytes) -> list[bytes]:
    if content and not content.endswith(b"\0"):
        fail("changed-file list must be NUL-terminated Git path records")
    records = content.split(b"\0")[:-1] if content else []
    result: list[bytes] = []
    seen: set[bytes] = set()
    for index, item in enumerate(records, start=1):
        if not item or len(item) > MAX_CHANGED_PATH_BYTES:
            fail(f"changed-file list contains an empty or oversized path at record {index}")
        parts = item.split(b"/")
        if (
            os.path.isabs(item)
            or any(part in {b"", b".", b".."} for part in parts)
            or os.fsencode(os.fsdecode(item)) != item
        ):
            fail(f"changed-file list contains unsafe path at record {index}")
        if item in seen:
            fail(f"changed-file list contains duplicate path {item!r}")
        seen.add(item)
        result.append(item)
        if len(result) > MAX_CHANGED_FILES:
            fail(f"changed-file list exceeds {MAX_CHANGED_FILES} paths")
    return result


def changed_files(path: Path) -> list[bytes]:
    return _parse_changed_files(
        _read_bounded(
            path,
            "changed-file list",
            MAX_CHANGED_FILES_BYTES,
            allow_empty=True,
        )
    )


def changed_files_from_stdin() -> list[bytes]:
    content = sys.stdin.buffer.read(MAX_CHANGED_FILES_BYTES + 1)
    if len(content) > MAX_CHANGED_FILES_BYTES:
        fail(f"changed-file list exceeds its {MAX_CHANGED_FILES_BYTES}-byte limit")
    return _parse_changed_files(content)


def validation_script(raw: str, repo: Path) -> Path:
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        fail("VALIDATE_SCRIPT must be one repository-relative path")
    script = repo / relative
    try:
        metadata = script.lstat()
        resolved = script.resolve(strict=True)
    except OSError as exc:
        fail(f"VALIDATE_SCRIPT is unavailable: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("VALIDATE_SCRIPT must be a non-symlink regular file")
    if not _within(resolved, repo):
        fail("VALIDATE_SCRIPT must remain inside the repository")
    if not metadata.st_mode & 0o111 or not os.access(resolved, os.X_OK):
        fail("VALIDATE_SCRIPT must be executable")
    return resolved


def _normalized_returncode(returncode: int) -> int:
    if returncode < 0:
        return min(255, 128 + abs(returncode))
    return min(255, returncode)


def _emit_captured(stdout: bytes, stderr: bytes) -> None:
    for stream, content in ((sys.stdout, stdout), (sys.stderr, stderr)):
        if not content:
            continue
        binary = getattr(stream, "buffer", None)
        if binary is not None:
            binary.write(content)
            binary.flush()
        else:  # pragma: no cover - only in embedded text-only callers.
            stream.write(content.decode("utf-8", errors="replace"))
            stream.flush()


def _process_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    except PermissionError as exc:
        fail(f"cannot signal validation process group with SIGTERM: {exc}")
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    # Always target the group after the leader exits: a validation command may
    # have left descendants behind. macOS can return EPERM rather than ESRCH for
    # an already-empty/reaped group under a process sandbox; that case is safe
    # only after the directly owned leader has exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        if process.poll() is not None:
            return
        fail(f"cannot signal validation process group with SIGKILL: {exc}")
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        fail("validation process group did not exit after SIGKILL")


def _run_bounded(
    argv: list[Union[str, bytes]],
    *,
    cwd: Path,
    timeout_seconds: float = VALIDATION_TIMEOUT_SECONDS,
    output_limit: int = MAX_VALIDATION_OUTPUT_BYTES,
    before_launch: Optional[Callable[[], None]] = None,
) -> int:
    if timeout_seconds <= 0 or output_limit <= 0:
        fail("validation deadline and output limit must be positive")
    try:
        if before_launch is not None:
            before_launch()
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        fail(f"cannot start validation command: {exc}")
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    deadline = time.monotonic() + timeout_seconds
    failure: Optional[str] = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"validation exceeded its {timeout_seconds:g}-second deadline"
                break
            events = selector.select(min(remaining, 0.25))
            if not events:
                if process.poll() is not None and _process_group_exists(process.pid):
                    failure = "validation left a background process running"
                    break
                continue
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, min(64 * 1024, output_limit + 1 - total))
                except OSError as exc:
                    failure = f"cannot read validation output: {exc}"
                    break
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                captured[key.data].extend(chunk)
                total += len(chunk)
                if total > output_limit:
                    failure = f"validation output exceeds {output_limit} bytes"
                    break
            if failure is not None:
                break
            if process.poll() is not None and _process_group_exists(process.pid):
                failure = "validation left a background process running"
                break
        if failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"validation exceeded its {timeout_seconds:g}-second deadline"
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    failure = f"validation exceeded its {timeout_seconds:g}-second deadline"
                else:
                    if _process_group_exists(process.pid):
                        failure = "validation left a background process running"
        if failure is not None:
            _terminate_process_group(process)
            _emit_captured(bytes(captured["stdout"]), bytes(captured["stderr"]))
            fail(failure)
        _emit_captured(bytes(captured["stdout"]), bytes(captured["stderr"]))
        assert process.returncode is not None
        return process.returncode
    finally:
        selector.close()
        for pipe in (process.stdout, process.stderr):
            if not pipe.closed:
                pipe.close()
        if process.poll() is None:
            _terminate_process_group(process)


def run_validation(
    repo: Path,
    config: dict[str, Optional[str]],
    changed: list[bytes],
) -> int:
    assignments = clean_environment(config)
    enforced = config["AGENT_SANDBOX_ENFORCED"]
    if enforced not in {"true", "false"}:
        fail("AGENT_SANDBOX_ENFORCED must be exactly true or false")
    runner = validate_runner(config.get("AGENT_SANDBOX_RUNNER"), repo) if enforced == "true" else None
    if runner is None:
        print(
            "recovery-validation: warning: AGENT_SANDBOX_ENFORCED=false; "
            "the environment is scrubbed, but no filesystem or process isolation is provided",
            file=sys.stderr,
        )

    configured_script = config.get("VALIDATE_SCRIPT")
    commands: list[tuple[str, list[Union[str, bytes]]]] = []
    if configured_script:
        script = validation_script(configured_script, repo)
        commands.append(("VALIDATE_SCRIPT", [str(script), *changed]))
    else:
        for key in VALIDATION_KEYS:
            value = config.get(key)
            if value:
                commands.append((key, ["/bin/sh", "-c", value]))

    for label, command in commands:
        clean_command: list[Union[str, bytes]] = [
            "/usr/bin/env",
            "-i",
            *assignments,
            *command,
        ]
        argv = (
            [str(runner.path), "--workdir", str(repo), "--", *clean_command]
            if runner is not None
            else clean_command
        )
        print(f"recovery-validation: running {label}", file=sys.stderr)
        returncode = _run_bounded(
            argv,
            cwd=repo,
            before_launch=(lambda: runner.revalidate(repo))
            if runner is not None
            else None,
        )
        if returncode != 0:
            code = _normalized_returncode(returncode)
            print(f"recovery-validation: {label} failed with status {code}", file=sys.stderr)
            return code
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repo", required=True, help="canonical repository root")
    result.add_argument("--config", required=True, help="repository team config")
    result.add_argument(
        "--changed-files",
        required=True,
        help="NUL-delimited changed paths, or '-' to read them from standard input",
    )
    return result


def main(argv: Optional[list[str]] = None) -> int:
    try:
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            fail(
                "helper must start with a trusted absolute Python using isolated "
                "and no-bytecode modes"
            )
        arguments = parser().parse_args(argv)
        repo = Path(arguments.repo).resolve(strict=True)
        if not repo.is_dir():
            fail("--repo must name an existing directory")
        config_path = _repo_path(
            arguments.config,
            repo,
            "configuration",
            allow_empty=False,
        )
        config = parse_config(
            _read_bounded(
                config_path,
                "configuration",
                MAX_CONFIG_BYTES,
                allow_empty=False,
            )
        )
        if arguments.changed_files == "-":
            changed = changed_files_from_stdin()
        else:
            changed_path = _repo_path(
                arguments.changed_files,
                repo,
                "changed-file list",
                allow_empty=True,
            )
            changed = changed_files(changed_path)
        return run_validation(repo, config, changed)
    except RecoveryValidationError as exc:
        print(f"recovery-validation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
