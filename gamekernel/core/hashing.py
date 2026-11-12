"""Streaming hashes. Files are read once in chunks; never loaded whole for hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1024 * 1024


def hash_file(path: str | Path, with_md5: bool = True, cancel=None) -> tuple[str, str | None, int]:
    """Return (sha256, md5, bytes_read). ``cancel`` is an optional callable returning True to abort."""
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False) if with_md5 else None
    total = 0
    with open(path, "rb", buffering=0) as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            sha.update(chunk)
            if md5 is not None:
                md5.update(chunk)
            total += len(chunk)
            if cancel is not None and cancel():
                raise InterruptedError("hash cancelado")
    return sha.hexdigest(), (md5.hexdigest() if md5 else None), total


def hash_bytes(data: bytes) -> tuple[str, str]:
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data, usedforsecurity=False).hexdigest()


def sha256_file(path: str | Path) -> str:
    return hash_file(path, with_md5=False)[0]
