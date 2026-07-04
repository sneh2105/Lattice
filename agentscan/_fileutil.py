# -*- coding: utf-8 -*-
"""
Atomic file writes.

AgentScan is invoked as a plain CLI, but nothing prevents two scans from
being pointed at the same --output-file path at once (a CI matrix job,
a wrapper script fanning out several scans, a person re-running a scan
while a previous run is still writing). A plain write_text()/open("wb")
is not atomic: a reader that opens the output file mid-write can see a
truncated or interleaved result, and two concurrent writers can produce
a file that's neither writer's complete output.

_atomic_write_text/_atomic_write_bytes write to a temp file in the same
directory as the target (so the final os.replace is on the same
filesystem and therefore atomic on POSIX and Windows) and then rename
it into place. A reader either sees the old complete file or the new
complete file, never a partial one.
"""
from __future__ import annotations
import os
import tempfile
from pathlib import Path


def atomic_write_text(path: str | Path, content: str, encoding: str = "utf-8") -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix="." + path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
        # tempfile.mkstemp() creates files mode 0600 (owner read/write
        # only), unlike a normal write_text() which gets the standard
        # umask-adjusted mode (typically 0644). These are report files
        # meant to be opened in a browser or handed to someone else, so
        # restore the conventional world-readable mode before the
        # rename -- otherwise every report this writes becomes
        # unreadable by anyone but the user who ran the scan.
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_bytes(path: str | Path, content: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix="." + path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
