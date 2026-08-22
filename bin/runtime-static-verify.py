#!/usr/bin/env python3
"""Broker-side, non-promoting verification of one installed runtime-kit profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterable


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def pairs(rows: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        if key in result:
            fail("duplicate JSON key")
        result[key] = value
    return result


def strict_json(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content, object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as exc:
        raise VerificationError(f"{label} is malformed") from exc
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    return value


def read_file(
    path: Path,
    label: str,
    *,
    mode: int | None = None,
    executable: bool = False,
    maximum: int = 2 * 1024 * 1024,
) -> bytes:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        fail(f"{label} path is not canonical")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise VerificationError(f"{label} is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            fail(f"{label} path contains a symlink")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        fail("secure no-follow opens are unavailable")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise VerificationError(f"cannot open {label}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            fail(f"{label} is not a bounded single-link file")
        if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o022:
            fail(f"{label} ownership or mode is unsafe")
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            fail(f"{label} mode changed")
        if executable and not info.st_mode & 0o111:
            fail(f"{label} is not executable")
        content = bytearray()
        while len(content) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > maximum:
            fail(f"{label} exceeds its size limit")
        return bytes(content)
    finally:
        os.close(descriptor)


def private_directory(path: Path, label: str) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        fail(f"{label} path is not canonical")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise VerificationError(f"{label} is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            fail(f"{label} contains a symlink")
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_nlink < 1
    ):
        fail(f"{label} is not an exact caller-owned mode-0700 directory")


def path_present_nofollow(path: Path, label: str) -> bool:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        fail(f"{label} path is not canonical")
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:]):
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise VerificationError(f"{label} path is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            fail(f"{label} path contains a symlink: {current}")
        if index < len(path.parts[1:]) - 1 and not stat.S_ISDIR(info.st_mode):
            fail(f"{label} path contains a non-directory ancestor: {current}")
    return True


def assignments(path: Path) -> dict[str, str]:
    content = read_file(path, "team configuration").decode("utf-8")
    keys = {
        "TASK_WORKTREE_MODE", "BROKER_TASK_CLONE_ROOT", "BROKER_AGENT_OUTBOX_ROOT",
        "AGENT_SANDBOX_RUNNER", "AGENT_SANDBOX_ENFORCED", "BROKER_LIFECYCLE_ROOT",
        "AGENT_RUNTIME_MANIFEST",
    }
    result: dict[str, str] = {}
    for line in content.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key not in keys:
            continue
        if key in result:
            fail(f"duplicate runtime configuration key: {key}")
        result[key] = value.split(" #", 1)[0].strip().strip('"')
    if set(result) != keys:
        fail("runtime configuration is incomplete")
    return result


def verify(target: Path) -> dict[str, Any]:
    target = target.resolve(strict=True)
    values = assignments(target / "config/team.config.md")
    if values["TASK_WORKTREE_MODE"] != "standalone-clone" or values["AGENT_SANDBOX_ENFORCED"] != "true":
        fail("runtime-kit authority mode is not selected")
    runner_path = Path(values["AGENT_SANDBOX_RUNNER"])
    manifest_path = Path(values["AGENT_RUNTIME_MANIFEST"])
    clone_root = Path(values["BROKER_TASK_CLONE_ROOT"])
    lifecycle_root = Path(values["BROKER_LIFECYCLE_ROOT"])
    outbox_root = Path(values["BROKER_AGENT_OUTBOX_ROOT"])
    for path, label in (
        (clone_root, "clone root"), (lifecycle_root, "lifecycle root"),
        (outbox_root, "outbox root"),
    ):
        private_directory(path, label)
    runner = read_file(runner_path, "runner", mode=0o700, executable=True)
    manifest_content = read_file(manifest_path, "manifest", mode=0o600)
    runtime_root = manifest_path.parent.parent.parent
    unresolved = [
        path.name
        for path in (runtime_root / ".runtime-kit.lock", runtime_root / ".runtime-kit-journal.json")
        if path_present_nofollow(path, "runtime recovery evidence")
    ]
    if unresolved:
        fail(
            "unresolved runtime-kit transaction evidence (%s); run the exact runtime-kit command "
            "with --recover to preview digest-bound recovery" % ", ".join(unresolved)
        )
    manifest = strict_json(manifest_content, "manifest")
    expected_keys = {
        "schemaVersion", "profile", "sourceAssetsSha256", "engine", "image", "runner",
        "policy", "network", "cloneRoot", "lifecycleRoot", "outboxRoot", "readiness",
        "skillRoot", "capabilities",
    }
    if (
        set(manifest) != expected_keys
        or manifest.get("schemaVersion") != 2
        or manifest.get("profile") != "rootless-podman-5"
        or manifest.get("cloneRoot") != str(clone_root)
        or manifest.get("lifecycleRoot") != str(lifecycle_root)
        or manifest.get("outboxRoot") != str(outbox_root)
        or manifest.get("skillRoot") != str(target)
        or manifest.get("readiness") != "configured_unproved"
        or manifest.get("capabilities") != {"autonomousDelivery": False, "productionDelivery": False}
    ):
        fail("manifest identity changed")
    runner_binding = manifest.get("runner")
    engine = manifest.get("engine")
    image = manifest.get("image")
    policy = manifest.get("policy")
    network = manifest.get("network")
    if runner_binding != {"path": str(runner_path), "sha256": digest(runner)}:
        fail("runner binding changed")
    if not isinstance(engine, dict) or set(engine) != {"path", "sha256", "proofSha256"}:
        fail("engine binding is malformed")
    if (
        not isinstance(image, dict)
        or set(image) != {"reference", "proofSha256", "pull"}
        or image.get("pull") != "never"
        or re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", str(image.get("reference") or "")) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(image.get("proofSha256") or "")) is None
    ):
        fail("image binding is malformed")
    if not isinstance(policy, dict) or set(policy) != {"path", "sha256"}:
        fail("policy binding is malformed")
    if not isinstance(network, dict) or set(network) != {"name", "path", "sha256"} or network.get("name") != "none":
        fail("network binding is malformed")
    engine_content = read_file(Path(engine["path"]), "engine", executable=True, maximum=128 * 1024 * 1024)
    policy_content = read_file(Path(policy["path"]), "policy", mode=0o600)
    network_content = read_file(Path(network["path"]), "network policy", mode=0o600)
    if engine["sha256"] != digest(engine_content) or policy["sha256"] != digest(policy_content) or network["sha256"] != digest(network_content):
        fail("runtime asset digest changed")
    source = b"".join(
        read_file(target / relative, f"source {relative}")
        for relative in (
            "runtime/runner-linux-container.sh", "runtime/container-policy.json",
            "runtime/network-policy-none.json",
        )
    )
    if manifest.get("sourceAssetsSha256") != digest(source):
        fail("source asset binding changed")
    config_content = read_file(target / "config/team.config.md", "team configuration")
    desired = {
        "schemaVersion": 1,
        "profile": "rootless-podman-5",
        "runtimeRoot": str(runtime_root),
        "engineSha256": engine["sha256"],
        "engineProofSha256": engine["proofSha256"],
        "image": image["reference"],
        "imageProofSha256": image["proofSha256"],
        "files": [
            {"path": policy["path"], "mode": 0o600, "sha256": policy["sha256"]},
            {"path": network["path"], "mode": 0o600, "sha256": network["sha256"]},
            {"path": str(runner_path), "mode": 0o700, "sha256": runner_binding["sha256"]},
            {"path": str(manifest_path), "mode": 0o600, "sha256": digest(manifest_content)},
        ],
        "configAfterSha256": digest(config_content),
    }
    installation_digest = digest(canonical(desired))
    marker = runtime_root / (".runtime-kit-committed-" + installation_digest.split(":", 1)[1])
    marker_value = strict_json(read_file(marker, "commit marker", mode=0o600), "commit marker")
    if (
        marker_value.get("schemaVersion") != 1
        or marker_value.get("installationDigest") != installation_digest
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(marker_value.get("appliedPlanDigest") or "")) is None
    ):
        fail("commit marker binding changed")
    return {
        "ok": True,
        "runner": str(runner_path),
        "manifest": str(manifest_path),
        "manifestDigest": digest(manifest_content),
        "cloneRoot": str(clone_root),
        "lifecycleRoot": str(lifecycle_root),
        "outboxRoot": str(outbox_root),
        "profile": manifest["profile"],
        "image": image["reference"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(Path(args.target)), sort_keys=True))
    except (OSError, UnicodeError, VerificationError, ValueError) as exc:
        print(f"runtime-static-verify: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
