from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_size(path: Path) -> int:
    return path.stat().st_size


def checksum_matches(path: Path, expected: str | None) -> bool | None:
    if not expected:
        return None
    normalized = expected.lower().replace("sha256:", "").strip()
    return sha256_file(path) == normalized
