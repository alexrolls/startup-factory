"""Inert, fail-closed parser for Startup Factory ``KEY=value`` configuration.

The team configuration is data, never shell input.  This module is the one
lexical authority shared by launch, dispatch, recovery, readiness, and upgrade
paths so an accepted value has exactly the same meaning everywhere.
"""

from __future__ import annotations

import dataclasses
import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import Literal


MAX_CONFIG_BYTES = 1024 * 1024
_ASSIGNMENT = re.compile(r"([A-Z_][A-Z0-9_]*)=(.*)\Z")
_ASSIGNMENT_LIKE = re.compile(r"[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=")
_TRAILING_COMMENT = re.compile(r"[ \t]+#[^\r\n]*")


class ConfigValueError(ValueError):
    """The configuration cannot be interpreted without guessing."""


@dataclasses.dataclass(frozen=True)
class ConfigValue:
    state: Literal["null", "value"]
    value: str
    line: int


def _malformed_value(key: str, line: int, reason: str) -> ConfigValueError:
    return ConfigValueError(
        f"malformed configuration value for {key} on line {line}: {reason}"
    )


def _scan_double_quoted(value: str) -> tuple[str, int]:
    output: list[str] = []
    index = 1
    while index < len(value):
        character = value[index]
        if character == "\\":
            if index + 1 >= len(value):
                raise ConfigValueError("unmatched outer quote or escape")
            following = value[index + 1]
            if following not in ('"', "\\"):
                raise ConfigValueError(
                    f"unsupported escape \\{following} inside an outer double-quoted value"
                )
            output.append(following)
            index += 2
            continue
        if character == '"':
            return "".join(output), index
        output.append(character)
        index += 1
    raise ConfigValueError("unmatched outer quote or escape")


def _scan_single_quoted(value: str) -> tuple[str, int]:
    closing = value.find("'", 1)
    if closing < 0:
        raise ConfigValueError("unmatched outer quote")
    return value[1:closing], closing


def _scan_unquoted(value: str) -> str:
    quote: str | None = None
    escaped = False
    comment: int | None = None
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
        elif character == "#" and index > 0 and value[index - 1] in " \t":
            comment = index
            break
    if escaped or quote is not None:
        raise ConfigValueError("unmatched quote or escape")
    if comment is not None:
        # Re-scan after removing boundary whitespace so trimming cannot expose a
        # trailing escape previously hidden before the comment marker.
        return _scan_unquoted(value[:comment].rstrip(" \t"))
    return value


def _parse_value(raw: str) -> tuple[Literal["null", "value"], str]:
    if any(
        unicodedata.category(character) == "Cc" and character != "\t"
        for character in raw
    ):
        raise ConfigValueError("control character")
    value = raw.strip(" \t")
    if not value:
        raise ConfigValueError("empty value")
    if value[0] in "'\"":
        scanner = _scan_double_quoted if value[0] == '"' else _scan_single_quoted
        text, closing = scanner(value)
        suffix = value[closing + 1 :]
        if suffix and _TRAILING_COMMENT.fullmatch(suffix) is None:
            raise ConfigValueError("trailing bytes after outer quote")
    else:
        text = _scan_unquoted(value)
    if not text:
        raise ConfigValueError("empty value")
    return ("null", "") if text == "null" else ("value", text)


def parse_config_bytes(raw: bytes, label: str = "configuration") -> dict[str, ConfigValue]:
    """Parse and validate every assignment in *raw*.

    Unknown keys are intentionally retained.  A caller requesting one key must
    still reject ambiguity or malformed syntax elsewhere in the authority file.
    """

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigValueError(f"{label} must be UTF-8 text") from exc

    assignments: dict[str, ConfigValue] = {}
    for number, source in enumerate(text.split("\n"), 1):
        line = source[:-1] if source.endswith("\r") else source
        match = _ASSIGNMENT.fullmatch(line)
        if match is None:
            if _ASSIGNMENT_LIKE.match(line):
                raise ConfigValueError(
                    f"malformed configuration assignment on line {number}"
                )
            continue
        key, encoded = match.groups()
        if key in assignments:
            raise ConfigValueError(f"duplicate configuration key {key}")
        try:
            state, value = _parse_value(encoded)
        except ConfigValueError as exc:
            raise _malformed_value(key, number, str(exc)) from exc
        assignments[key] = ConfigValue(state=state, value=value, line=number)
    return assignments


def read_config_file(
    path: Path | str,
    label: str = "configuration",
    *,
    limit: int = MAX_CONFIG_BYTES,
) -> dict[str, ConfigValue]:
    """Securely read a bounded, stable, non-symlink regular config file."""

    config_path = Path(path)
    try:
        before = config_path.lstat()
    except OSError as exc:
        raise ConfigValueError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ConfigValueError(f"{label} must be a non-symlink regular file")
    if before.st_size <= 0 or before.st_size > limit:
        raise ConfigValueError(f"{label} must contain 1..{limit} bytes")

    descriptor: int | None = None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(config_path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise ConfigValueError(f"{label} changed while being opened")
        chunks: list[bytes] = []
        size = 0
        while size <= limit:
            block = os.read(descriptor, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        if size > limit:
            raise ConfigValueError(f"{label} exceeds {limit} bytes")
        after = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ConfigValueError(f"{label} changed while being read")
        try:
            named = config_path.lstat()
        except OSError as exc:
            raise ConfigValueError(f"cannot re-inspect {label}: {exc}") from exc
        if (
            named.st_dev,
            named.st_ino,
            named.st_size,
            named.st_mtime_ns,
            named.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ConfigValueError(f"{label} changed while being read")
        return parse_config_bytes(b"".join(chunks), label)
    except ConfigValueError:
        raise
    except OSError as exc:
        raise ConfigValueError(f"cannot securely read {label}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def value_for(values: dict[str, ConfigValue], key: str) -> str | None:
    parsed = values.get(key)
    if parsed is None or parsed.state == "null":
        return None
    return parsed.value


def state_for(values: dict[str, ConfigValue], key: str) -> Literal["missing", "null", "value"]:
    parsed = values.get(key)
    return "missing" if parsed is None else parsed.state
