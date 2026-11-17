"""Bounded non-authoritative reads shared by sandbox launcher/guard helpers."""
from __future__ import annotations
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from startup_factory_cli.sandbox_deployment import decode_object
from sandbox_acceptance import task_key


def regular_data(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
            raise ValueError("invalid projection")
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        stamp = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if len(raw) != info.st_size or stamp(info) != stamp(os.fstat(fd)):
            raise ValueError("projection changed")
        return bytes(raw)
    finally:
        os.close(fd)


def read_execution(workspace: Path, task: str) -> dict:
    return decode_object(regular_data(workspace / "executions" / (task_key(task) + ".json"), 1024 * 1024), maximum=1024 * 1024)
