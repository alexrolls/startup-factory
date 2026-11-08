#!/usr/bin/env python3
"""Resolve a pinned login executable and prepare explicit macOS keychain access."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from startup_factory_cli.machine_setup import (  # noqa: E402
    MachineSetupError,
    validate_cli_executable,
)


def private_directory(path: Path, *, create: bool = False) -> None:
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise MachineSetupError(f"{path} must be a real directory owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise MachineSetupError(f"{path} must have mode 0700")


def keychains_reachable(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            return False
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            return False
        return any(
            candidate.is_file() and candidate.stat().st_uid == os.geteuid()
            for pattern in ("*.keychain", "*.keychain-db")
            for candidate in resolved.glob(pattern)
        )
    except (OSError, RuntimeError):
        return False


def prepare_macos_keychains(home: Path, account_home: Path, share: bool) -> None:
    """Only create the credential-store link after a deliberate opt-in flag."""
    destination = home / "Library" / "Keychains"
    if not share:
        if keychains_reachable(destination):
            return
        raise MachineSetupError(
            "Claude login needs a reachable macOS keychain in AGENT_SANDBOX_HOME="
            f"{home}. To explicitly share your account's credential store, rerun "
            "bin/launch-team.sh login claude --share-macos-keychain. This exposes "
            "your account's Keychains directory to processes using this agent home. "
            "Alternatively provision a separate unlocked keychain in "
            f"{destination}. Never click 'Reset To Defaults' in a Keychain Not Found dialog."
        )
    source = account_home / "Library" / "Keychains"
    if not keychains_reachable(source):
        raise MachineSetupError(f"account keychain is unavailable at {source}; no keychain was changed")
    source = source.resolve(strict=True)
    private_directory(home / "Library", create=True)
    if destination.is_symlink():
        if destination.resolve(strict=True) == source:
            return
        raise MachineSetupError(f"refusing to replace existing keychain link {destination}")
    if destination.exists():
        raise MachineSetupError(f"refusing to replace existing keychain directory {destination}")
    destination.symlink_to(source, target_is_directory=True)
    print(
        f"Explicitly shared account Keychains at {destination}; processes using this agent home "
        "can access that credential store.", file=sys.stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", required=True)
    parser.add_argument("--cli", choices=("claude", "codex"), required=True)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--interpreter")
    parser.add_argument("--share-macos-keychain", action="store_true")
    args = parser.parse_args()
    try:
        home = Path(args.home)
        private_directory(home)
        executable = validate_cli_executable(args.executable, label=f"{args.cli} login executable")
        interpreter = (
            validate_cli_executable(args.interpreter, label=f"{args.cli} login interpreter")
            if args.interpreter else None
        )
        if args.share_macos_keychain and (sys.platform != "darwin" or args.cli != "claude"):
            raise MachineSetupError("--share-macos-keychain applies only to Claude on macOS")
        if sys.platform == "darwin" and args.cli == "claude":
            account = pwd.getpwuid(os.geteuid())
            prepare_macos_keychains(home, Path(account.pw_dir), args.share_macos_keychain)
        print(str(executable) + ("\x1f" + str(interpreter) if interpreter else ""))
    except (OSError, RuntimeError, MachineSetupError) as exc:
        parser.exit(1, f"launch-team: login: {exc}\n")


if __name__ == "__main__":
    main()
